#include "flt_filter.h"
#include "core/registry/virtual_fs.h"
#include <atomic>

NTSTATUS h_FltRegisterFilter(PVOID Driver, PVOID Registration, PVOID* RetFilter) {
    Logger::Log("{GRN}FltRegisterFilter called{RESET}\n");
    uint64_t FakeFilter = UnicornMem::AllocateVariable(UnicornThread::GetCurrentEngine(), 0x200, "FakeFilter");
    if (RetFilter) {
        auto HostRetFilter = UcPtr(RetFilter);
        *HostRetFilter = (PVOID)FakeFilter;
    }
    return 0;
}

NTSTATUS h_FltStartFiltering(PVOID Filter) {
    Logger::Log("{GRN}FltStartFiltering called{RESET}\n");
    return 0;
}

NTSTATUS h_FltUnregisterFilter(PVOID Filter) {
    Logger::Log("{CYN}FltUnregisterFilter called{RESET}\n");
    return 0;
}

void h_FltObjectDereference(PVOID Object) {
}

NTSTATUS h_FltGetFilterInformation(PVOID Filter, uint32_t InfoClass, PVOID Buffer, ULONG BufSize, PULONG BytesReturned) {
    if (BytesReturned) {
        auto HostRet = UcPtr(BytesReturned);
        *HostRet = 0;
    }
    return 0xC000000D;
}

PVOID h_FltGetRoutineAddress(const char* FltRoutineName) {
    auto HostName = UcPtr(FltRoutineName);
    bool IsAscii = true;
    int Len = 0;
    for (int I = 0; I < 256 && HostName[I]; I++) {
        if ((unsigned char)HostName[I] < 0x20 || (unsigned char)HostName[I] > 0x7E) {
            IsAscii = false;
            break;
        }
        Len++;
    }

    if (IsAscii && Len > 0) {
        Logger::Log("{CYN}FltGetRoutineAddress: %s{RESET}\n", HostName);
        std::string Name(HostName, Len);
        {
            std::shared_lock<std::shared_mutex> Guard(Provider::ProviderLock);
            if (Provider::function_providers.contains(Name)) {
                PVOID Func = Provider::function_providers[Name];
                Guard.unlock();
                return (PVOID)UnicornEmu::AllocateSentinel(Name.c_str(), Func);
            }
        }
    } else {
        Logger::Log("{YEL}FltGetRoutineAddress: (encrypted/unreadable, returning generic stub){RESET}\n");
    }

    static PVOID GenericFltStub = (PVOID)[](uint64_t A1, uint64_t A2, uint64_t A3, uint64_t A4) -> uint64_t {
        Logger::Log("{YEL}\t[FLT-STUB] unimplemented filter routine called a1=%llx a2=%llx{RESET}\n", A1, A2);
        return 0;
    };
    static std::atomic<int> FltStubCounter{0};
    char StubName[64];
    sprintf(StubName, "FltAutoStub_%d", FltStubCounter.fetch_add(1));
    {
        std::unique_lock<std::shared_mutex> Guard(Provider::ProviderLock);
        Provider::function_providers[StubName] = GenericFltStub;
    }
    uint64_t Sentinel = UnicornEmu::AllocateSentinel(StubName, GenericFltStub);
    Logger::Log("{YEL}\t-> flt auto-stub sentinel 0x%llx{RESET}\n", Sentinel);
    return (PVOID)Sentinel;
}

void h_FltSetCallbackDataDirty(PVOID Data) {
}

NTSTATUS h_FltGetDiskDeviceObject(PVOID Volume, PVOID* DiskDevice) {
    if (DiskDevice) {
        auto HostPtr = UcPtr(DiskDevice);
        *HostPtr = nullptr;
    }
    return 0xC000000D;
}

NTSTATUS h_FltGetVolumeFromInstance(PVOID Instance, PVOID* Volume) {
    if (Volume) {
        auto HostPtr = UcPtr(Volume);
        *HostPtr = nullptr;
    }
    return 0xC000000D;
}

NTSTATUS h_FltAllocateCallbackData(PVOID Instance, PVOID FileObject, PVOID* RetNewCbdData) {
    if (RetNewCbdData) {
        auto HostPtr = UcPtr(RetNewCbdData);
        uint64_t FakeCbd = UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), 0x200);
        *HostPtr = (PVOID)FakeCbd;
    }
    return 0;
}

void h_FltFreeCallbackData(PVOID CbdData) {
}

NTSTATUS h_FltPerformSynchronousIo(PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltCancellableWaitForSingleObject(PVOID Object, PLARGE_INTEGER Timeout, PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltCancellableWaitForMultipleObjects(ULONG Count, PVOID* ObjectArray, uint32_t WaitType, PLARGE_INTEGER Timeout, PVOID WaitBlockArray, PVOID CbdData) {
    return 0;
}

NTSTATUS h_FltClose(PVOID* FileObject) {
    return 0;
}

NTSTATUS h_FltCreateFile(PVOID Filter, PVOID Instance, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjAttr, PVOID IoStatusBlock, PLARGE_INTEGER AllocSize, ULONG FileAttrs, ULONG ShareAccess, ULONG CreateDisp, ULONG CreateOpts, PVOID EaBuffer, ULONG EaLength, ULONG Flags) {
    Logger::Log("{CYN}FltCreateFile called{RESET}\n");

    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);

    if (ObjAttr) {
        OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
        TranslateObjAttr((OBJECT_ATTRIBUTES*)ObjAttr, LocalOa, LocalName);

        const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
        Logger::Log("  {YEL}FltCreateFile: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

        std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";
        if (!LocalPath.empty()) {
            HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, FileAttrs, ShareAccess, CreateDisp, CreateOpts);
            if (H != INVALID_HANDLE_VALUE) {
                *HostHandle = H;
                if (HostIsb) {
                    auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                    Isb->Status = 0;
                    Isb->Information = 2;
                }
                Logger::Log("  {GRN}VFS: FltCreateFile -> {WHT}%ls{RESET}\n", LocalPath.c_str());
                return 0;
            }
        }

        std::wstring RewrittenStorage;
        UNICODE_STRING RewrittenName = {};
        RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
        ULONG SafeOpts = CreateOpts & ~(0x00010000);
        ACCESS_MASK SafeAccess = DesiredAccess;
        if (SafeOpts & (0x10 | 0x20))
            SafeAccess |= SYNCHRONIZE;
        auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocSize, FileAttrs, ShareAccess,
            CreateDisp, SafeOpts, EaBuffer, EaLength);
        Logger::Log("  {GRY}FltCreateFile OS return: {WHT}%08x{RESET}\n", Ret);
        return Ret;
    }

    if (HostHandle)
        *HostHandle = (HANDLE)0x1234;
    return 0;
}

NTSTATUS h_FltGetVolumeProperties(PVOID Volume, PVOID VolumeProperties, ULONG Length, PULONG LengthReturned) {
    if (LengthReturned) {
        auto HostPtr = UcPtr(LengthReturned);
        *HostPtr = 0;
    }
    return 0xC000000D;
}
