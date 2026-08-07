#include "include/common.h"
#include "io_device.h"
#include "core/registry/virtual_fs.h"
#include "core/process/unicorn_threading.h"
#include "core/io/io_manager.h"

NTSTATUS h_ZwClose(HANDLE Handle);

namespace DeviceTracker {
    std::vector<DeviceInfo> Devices;
    std::mutex DeviceLock;

    uint64_t FindByName(const std::wstring& Name) {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        for (auto& Dev : Devices) {
            if (Dev.DeviceName == Name || Dev.SymLinkName == Name)
                return Dev.UcAddr;
        }
        return 0;
    }

    uint64_t GetFirst() {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        if (!Devices.empty())
            return Devices[0].UcAddr;
        return 0;
    }

    const DeviceInfo* GetByIndex(size_t Index) {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        if (Index < Devices.size())
            return &Devices[Index];
        return nullptr;
    }

    size_t GetCount() {
        std::lock_guard<std::mutex> Guard(DeviceLock);
        return Devices.size();
    }
}

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject) {
    uint64_t DevUcAddr = UnicornMem::AllocateVariable(UnicornThread::GetCurrentEngine(), sizeof(_DEVICE_OBJECT) + DeviceExtensionSize, "CreatedDeviceObject");
    auto RealDevice = (_DEVICE_OBJECT*)UnicornMem::UcToHost(DevUcAddr);

    memset(RealDevice, 0, sizeof(_DEVICE_OBJECT));

    RealDevice->DeviceType = DeviceType;
    RealDevice->Type = 3;
    RealDevice->Size = sizeof(_DEVICE_OBJECT);
    RealDevice->ReferenceCount = 1;
    RealDevice->DriverObject = DriverObject;
    RealDevice->NextDevice = 0;

    if (DeviceExtensionSize) {
        RealDevice->DeviceExtension = (PVOID)(DevUcAddr + sizeof(_DEVICE_OBJECT));
    }

    auto HostDevObj = (_DEVICE_OBJECT**)UnicornMem::UcToHost((uint64_t)DeviceObject);
    if (HostDevObj) {
        *HostDevObj = (_DEVICE_OBJECT*)DevUcAddr;
    } else {
        uc_mem_write(UnicornThread::GetCurrentEngine(), (uint64_t)DeviceObject, &DevUcAddr, sizeof(DevUcAddr));
    }

    auto HostDevName = DeviceName ? UcPtr(DeviceName) : nullptr;
    std::wstring DevNameStr;
    if (HostDevName && HostDevName->Buffer) {
        auto HostBuf = UcPtr(HostDevName->Buffer);
        if (HostBuf)
            DevNameStr = std::wstring(HostBuf, HostDevName->Length / sizeof(wchar_t));
    }

    Logger::Log("  {GRN}Created device: {WHT}%ls {GRN}-> {WHT}0x%llx{RESET}\n",
        DevNameStr.empty() ? L"(null)" : DevNameStr.c_str(), DevUcAddr);

    {
        std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
        DeviceTracker::Devices.push_back({ DevUcAddr, DevNameStr, L"", DeviceType });
    }

    return 0;
}

NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, void* IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength,
    void* CreateFileType, PVOID InternalParameters, ULONG Options, void* DriverContext) {

    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    Logger::Log("  {YEL}IoCreateFileEx: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

    if (DesiredAccess == 0xC0000000)
        DesiredAccess = 0xC0100080;

    std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";

    if (!LocalPath.empty()) {
        bool IsCreate = (Disposition == 0 || Disposition == 2 || Disposition == 3 || Disposition == 5);
        bool Exists = VirtualFs::LocalExists(LocalPath);

        if (IsCreate || Exists) {
            HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, FileAttributes, ShareAccess, Disposition, CreateOptions);
            if (H != INVALID_HANDLE_VALUE) {
                *HostHandle = H;
                if (HostIsb) {
                    auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                    Isb->Status = 0;
                    Isb->Information = Exists ? 1 : 2;
                }
                Logger::Log("  {GRN}VFS: IoCreateFileEx -> {WHT}%ls {GRN}handle={WHT}%p{RESET}\n", LocalPath.c_str(), H);
                return 0;
            }
        }
    }

    std::wstring RewrittenStorage;
    UNICODE_STRING RewrittenName = {};
    RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
    ULONG SafeOptions = CreateOptions & ~(0x00010000);
    ACCESS_MASK SafeAccess = DesiredAccess;
    if (SafeOptions & (0x10 | 0x20))
        SafeAccess |= SYNCHRONIZE;
    auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocationSize, FileAttributes, ShareAccess,
        Disposition, SafeOptions, EaBuffer, EaLength);
    Logger::Log("  {GRY}IoCreateFileEx OS return: {WHT}%08x{RESET}\n", Ret);
    return Ret;
}

void h_IoDeleteController(PVOID ControllerObject) {
    _EX_FAST_REF* ref = (_EX_FAST_REF*)ControllerObject;
    //TODO This needs to dereference the object, Check ntoskrnl.exe code.
    Logger::Log("{CYN}\tDeleting controller : %llx{RESET}\n", static_cast<const void*>(ControllerObject));
    return;
}

NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName) {

    int TemporaryObject;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE LinkHandle;

    auto HostSymName = UcPtr(SymbolicLinkName);
    UNICODE_STRING LocalSymName = *HostSymName;
    LocalSymName.Buffer = UcPtr(LocalSymName.Buffer);

    Logger::Log("{CYN}\tIoDeleteSymbolicLink: %ls{RESET}\n", LocalSymName.Buffer);

    memset(&ObjectAttributes.Attributes + 1, 0, 20);
    LinkHandle = 0;
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.ObjectName = &LocalSymName;
    *(uintptr_t*)&ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = 576;
    TemporaryObject = __NtRoutine("ZwOpenSymbolicLinkObject", &LinkHandle, 0x10000u, &ObjectAttributes);
    if (TemporaryObject >= 0) {
        TemporaryObject = __NtRoutine("ZwMakeTemporaryObject", LinkHandle);
        if (TemporaryObject >= 0)
            h_ZwClose(&LinkHandle);
    }

    if (TemporaryObject == (int)0xC0000034)
        TemporaryObject = 0;

    return TemporaryObject;
}

//todo impl
NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName) {
    auto HostSym = UcPtr(SymbolicLinkName);
    auto HostDev = UcPtr(DeviceName);
    auto HostSymBuf = UcPtr(HostSym->Buffer);
    auto HostDevBuf = UcPtr(HostDev->Buffer);
    Logger::Log("{CYN}\tSymbolic Link Name : %ls{RESET}\n", HostSymBuf);
    Logger::Log("{CYN}\tDeviceName : %ls{RESET}\n", HostDevBuf);

    std::wstring SymStr(HostSymBuf, HostSym->Length / sizeof(wchar_t));
    std::wstring DevStr(HostDevBuf, HostDev->Length / sizeof(wchar_t));

    {
        std::lock_guard<std::mutex> Guard(DeviceTracker::DeviceLock);
        for (auto& Dev : DeviceTracker::Devices) {
            if (Dev.DeviceName == DevStr) {
                Dev.SymLinkName = SymStr;
                Logger::Log("{CYN}\tLinked symlink {WHT}%ls{CYN} -> device {WHT}%ls{RESET}\n",
                    SymStr.c_str(), DevStr.c_str());
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}

BOOL h_IoIsSystemThread(_ETHREAD* thread) {
    auto HostThread = UcPtr(thread);
    auto ret = (HostThread->Tcb.MiscFlags & 0x400) != 0;
    return ret;
}

void h_IoDeleteDevice(_DEVICE_OBJECT* obj) {

}

//todo definitely will blowup
void* h_IoGetTopLevelIrp() {
    Logger::Log("{YEL}\tIoGetTopLevelIrp blows up sorry{RESET}\n");
    static int irp = 0;
    return &irp;
}

NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info) {
    typedef struct _OBJECT_NAME_INFORMATION {
        UNICODE_STRING Name;
    } aids;
    static aids n;
    auto HostNameInfo = UcPtr(name_info);
    *HostNameInfo = (PVOID)&n;

    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIOpenBlock(LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe((GUID*)Guid, LocalGuid);
    auto HostDbo = UcPtr(DataBlockObject);
    if (HostGuid)
        Logger::Log("{CYN}\tWMI GUID : %08x-%04x-%04x with access : %llx{RESET}\n", HostGuid->Data1, HostGuid->Data2, HostGuid->Data3, DesiredAccess);
    else
        Logger::Log("{YEL}\tWMI GUID : <untranslated %llx> with access : %llx{RESET}\n", (uint64_t)Guid, DesiredAccess);
    if (HostDbo)
        *HostDbo = nullptr;
    return STATUS_SUCCESS;
}

NTSTATUS h_IoWMIQueryAllData(PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer) { return STATUS_SUCCESS; }

//todo impl
void h_IofCompleteRequest(void* pirp, CHAR boost) {
    __try {
        uint64_t IrpUcAddr = (uint64_t)pirp;
        auto HostIrp = (_IRP*)UcPtr((_IRP*)pirp);
        if (!HostIrp) return;

        Logger::Log("{GRY}IofCompleteRequest: IRP=0x%llx Status=0x%08x Info=%llu{RESET}\n",
            IrpUcAddr, HostIrp->IoStatus.Status, HostIrp->IoStatus.Information);

        #define IRP_BUFFERED_IO   0x00000010
        #define IRP_INPUT_OPERATION 0x00000040

        if ((HostIrp->Flags & IRP_BUFFERED_IO) &&
            (HostIrp->Flags & IRP_INPUT_OPERATION) &&
            HostIrp->IoStatus.Information > 0) {
            auto SysBuf = UcPtr((void*)HostIrp->AssociatedIrp.SystemBuffer);
            auto UserBuf = UcPtr(HostIrp->UserBuffer);
            if (SysBuf && UserBuf && SysBuf != UserBuf) {
                __try {
                    memcpy(UserBuf, SysBuf, (size_t)HostIrp->IoStatus.Information);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    Logger::Log("{RED}IofCompleteRequest: exception copying SystemBuffer->UserBuffer{RESET}\n");
                }
            }
        }

        if (HostIrp->UserIosb) {
            __try {
                auto HostUserIosb = (_IO_STATUS_BLOCK*)UcPtr((_IO_STATUS_BLOCK*)HostIrp->UserIosb);
                if (HostUserIosb) {
                    HostUserIosb->Status = HostIrp->IoStatus.Status;
                    HostUserIosb->Information = HostIrp->IoStatus.Information;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Logger::Log("{RED}IofCompleteRequest: exception writing UserIosb{RESET}\n");
            }
        }

        if (HostIrp->UserEvent) {
            __try {
                auto EventUcAddr = (uintptr_t)HostIrp->UserEvent;
                auto hEvent = HandleManager::GetHandle(EventUcAddr);
                if (hEvent)
                    SetEvent((HANDLE)hEvent);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Logger::Log("{RED}IofCompleteRequest: exception signaling UserEvent{RESET}\n");
            }
        }

        IoManager::SignalCompletion(IrpUcAddr, HostIrp->IoStatus.Status, HostIrp->IoStatus.Information);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IofCompleteRequest: outer exception 0x%08x{RESET}\n", GetExceptionCode());
    }
}

NTSTATUS h_IoGetDeviceInterfaces(
    const GUID* InterfaceClassGuid,
    _DEVICE_OBJECT* PhysicalDeviceObject,
    ULONG          Flags,
    wchar_t** SymbolicLinkList
) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe((GUID*)InterfaceClassGuid, LocalGuid);
    auto HostLinkList = UcPtr(SymbolicLinkList);
    wchar_t GUID[256] = { 0 };
    if (HostGuid)
        StringFromGUID2(*HostGuid, GUID, 64);
    Logger::Log("{CYN}\tInterface Class Guid : %ls{RESET}\n", GUID);
    if (PhysicalDeviceObject) {
        auto HostDev = UcPtr(PhysicalDeviceObject);
        if (HostDev->DriverObject) {
            auto HostDrv = UcPtr(HostDev->DriverObject);
            auto HostDrvNameBuf = UcPtr(HostDrv->DriverName.Buffer);
            Logger::Log("{CYN}Device driver name : %ls{RESET}\t", HostDrvNameBuf);
        }
    }
    *HostLinkList = (wchar_t*)0;

    return STATUS_NOT_FOUND;
}

NTSTATUS h_IoCreateNotificationEvent(PUNICODE_STRING EventName, PHANDLE EventHandle) {
    auto HostName = UcPtr(EventName);
    auto HostHandle = UcPtr(EventHandle);
    *HostHandle = (HANDLE)0xFACE;
    return STATUS_SUCCESS;
}

PVOID h_IoGetAttachedDeviceReference(_DEVICE_OBJECT* DeviceObject) {
    return DeviceObject;
}

NTSTATUS h_IoRegisterPlugPlayNotification(uint32_t EventCategory, ULONG EventCategoryFlags, PVOID EventCategoryData, PVOID DriverObject, PVOID CallbackRoutine, PVOID Context, PVOID* NotificationEntry) {
    Logger::Log("Callback registered. EventCategory: {}, EventCategoryFlags: {}, EventCategoryData: {0x:X}, DriverObject: {0x:X}, CallbackRoutine: {0x:X}, Context: {0x:X}, NotificationEntry: {0x:X}",
        EventCategory, EventCategoryFlags, EventCategoryData, DriverObject, CallbackRoutine, Context, NotificationEntry);
    if (NotificationEntry) {
        auto HostPtr = UcPtr(NotificationEntry);
        *HostPtr = (PVOID)0xDEAD;
    }
    return STATUS_SUCCESS;
}

NTSTATUS h_IoUnregisterPlugPlayNotificationEx(PVOID NotificationEntry) {
    return STATUS_SUCCESS;
}

void* h_IoThreadToProcess(void* Thread) {
    Logger::Log("{CYN}\tIoThreadToProcess: thread=%p{RESET}\n", Thread);
    auto HostThread = (_ETHREAD*)UcPtr((_ETHREAD*)Thread);
    if (HostThread) {
        return (void*)HostThread->Tcb.ApcState.Process;
    }
    return nullptr;
}

struct KEVLAR_IO_WORK_ITEM {
    uint64_t DeviceObject;
    uint64_t WorkerRoutine;
    uint32_t QueueType;
    uint64_t Context;
    uint64_t IoObject;
};

PVOID h_IoAllocateWorkItem(_DEVICE_OBJECT* DeviceObject) {
    uint64_t UcAddr = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), sizeof(KEVLAR_IO_WORK_ITEM), 'IoWI');
    if (!UcAddr) {
        Logger::Log("{RED}IoAllocateWorkItem: allocation failed{RESET}\n");
        return NULL;
    }

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UnicornMem::UcToHost(UcAddr);
    if (HostItem) {
        memset(HostItem, 0, sizeof(KEVLAR_IO_WORK_ITEM));
        HostItem->DeviceObject = (uint64_t)DeviceObject;
    }

    Logger::Log("{GRN}IoAllocateWorkItem: DevObj=%p -> WorkItem=0x%llx{RESET}\n", DeviceObject, UcAddr);
    return (PVOID)UcAddr;
}

void h_IoFreeWorkItem(PVOID IoWorkItem) {
    Logger::Log("{GRN}IoFreeWorkItem: 0x%llx{RESET}\n", (uint64_t)IoWorkItem);
    UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), (uint64_t)IoWorkItem);
}

void h_IoQueueWorkItem(PVOID IoWorkItem, PVOID WorkerRoutine, uint32_t QueueType, PVOID Context) {
    Logger::Log("{CYN}IoQueueWorkItem: WorkItem=%p Routine=%p Queue=%u Ctx=%p{RESET}\n",
        IoWorkItem, WorkerRoutine, QueueType, Context);

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UcPtr((KEVLAR_IO_WORK_ITEM*)IoWorkItem);
    if (HostItem) {
        HostItem->WorkerRoutine = (uint64_t)WorkerRoutine;
        HostItem->QueueType = QueueType;
        HostItem->Context = (uint64_t)Context;
    }

    uint64_t DeviceObject = HostItem ? HostItem->DeviceObject : 0;
    ThreadContext* Ctx = nullptr;
    __try {
        Ctx = UnicornThread::CreateEx(
            (uint64_t)WorkerRoutine,
            DeviceObject,
            (uint64_t)Context,
            0, 0,
            nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoQueueWorkItem: exception 0x%08x creating worker thread{RESET}\n", GetExceptionCode());
    }

    if (!Ctx)
        Logger::Log("{RED}IoQueueWorkItem: failed to create worker thread{RESET}\n");
}

void h_IoInitializeWorkItem(PVOID IoObject, PVOID IoWorkItem) {
    Logger::Log("{CYN}IoInitializeWorkItem: IoObj=%p WorkItem=%p{RESET}\n", IoObject, IoWorkItem);

    auto HostItem = (KEVLAR_IO_WORK_ITEM*)UcPtr((KEVLAR_IO_WORK_ITEM*)IoWorkItem);
    if (HostItem) {
        HostItem->IoObject = (uint64_t)IoObject;
    }
}

NTSTATUS h_IoRegisterShutdownNotification(_DEVICE_OBJECT* DeviceObject) {
    return STATUS_SUCCESS;
}

NTSTATUS h_IoCreateDeviceSecure(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType,
    ULONG DeviceCharacteristics, BOOLEAN Exclusive, PUNICODE_STRING DefaultSDDLString, void* DeviceClassGuid, _DEVICE_OBJECT** DeviceObject) {
    Logger::Log("{CYN}IoCreateDeviceSecure: forwarding to IoCreateDevice (SDDL/GUID ignored){RESET}\n");
    return h_IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject);
}

NTSTATUS h_IoValidateDeviceIoControlAccess(void* Irp, ULONG RequiredAccess) {
    Logger::Log("{GRY}IoValidateDeviceIoControlAccess: access=0x%x -> granted{RESET}\n", RequiredAccess);
    return STATUS_SUCCESS;
}
