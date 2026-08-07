#include "core/io/io_manager.h"
#include "core/io/irp_dispatch.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"
#include "include/ntoskrnl_struct.h"
#include <Logger/Logger.h>

std::unordered_map<uint64_t, IoManager::IrpCompletionInfo> CompletionMap;
std::mutex CompletionLock;

void IoManager::Initialize() {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    CompletionMap.clear();
}

void IoManager::Shutdown() {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    for (auto& Pair : CompletionMap) {
        if (Pair.second.Event) {
            SetEvent(Pair.second.Event);
            CloseHandle(Pair.second.Event);
        }
    }
    CompletionMap.clear();
}

void IoManager::SignalCompletion(uint64_t IrpUcAddr, NTSTATUS Status, ULONG_PTR Information) {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    auto It = CompletionMap.find(IrpUcAddr);
    if (It != CompletionMap.end()) {
        It->second.Status = Status;
        It->second.Information = Information;
        It->second.Completed = true;
        if (It->second.Event) {
            SetEvent(It->second.Event);
        }
        Logger::Log("{CYN}IoManager::SignalCompletion IRP=0x%llx Status=0x%08x Info=0x%llx{RESET}\n",
            IrpUcAddr, Status, (uint64_t)Information);
    }
}

uint64_t IoManager::AllocateIrp(uc_engine* Uc, CCHAR StackSize) {
    uint64_t TotalSize = sizeof(_IRP) + (uint64_t)StackSize * sizeof(_IO_STACK_LOCATION);
    uint64_t IrpUcAddr = UnicornMem::AllocateVariable(Uc, TotalSize, "IRP");
    if (!IrpUcAddr) {
        Logger::Log("{RED}IoManager::AllocateIrp failed to allocate %llu bytes{RESET}\n", TotalSize);
        return 0;
    }

    auto IrpHost = (_IRP*)UnicornMem::UcToHost(IrpUcAddr);
    if (!IrpHost) {
        Logger::Log("{RED}IoManager::AllocateIrp UcToHost failed for 0x%llx{RESET}\n", IrpUcAddr);
        return 0;
    }

    memset(IrpHost, 0, (size_t)TotalSize);

    IrpHost->Type = 6;
    IrpHost->Size = (USHORT)sizeof(_IRP);
    IrpHost->StackCount = StackSize;
    IrpHost->CurrentLocation = StackSize + 1;

    uint64_t PastEndSlotUcAddr = IrpUcAddr + sizeof(_IRP) + (uint64_t)StackSize * sizeof(_IO_STACK_LOCATION);
    IrpHost->Tail.Overlay.CurrentStackLocation = (_IO_STACK_LOCATION*)PastEndSlotUcAddr;

    Logger::Log("{GRN}IoManager::AllocateIrp UC=0x%llx StackSize=%d TotalBytes=%llu{RESET}\n",
        IrpUcAddr, StackSize, TotalSize);

    return IrpUcAddr;
}

void IoManager::FreeIrp(uint64_t IrpUcAddr) {
    if (IrpUcAddr) {
        Logger::Log("{GRY}IoManager::FreeIrp 0x%llx{RESET}\n", IrpUcAddr);
    }
}

uint64_t IoManager::AllocateFileObject(uc_engine* Uc, uint64_t DeviceObjUcAddr) {
    uint64_t FileObjUcAddr = UnicornMem::AllocateVariable(Uc, sizeof(_FILE_OBJECT), "FileObject");
    if (!FileObjUcAddr) {
        Logger::Log("{RED}IoManager::AllocateFileObject allocation failed{RESET}\n");
        return 0;
    }

    auto FileObjHost = (_FILE_OBJECT*)UnicornMem::UcToHost(FileObjUcAddr);
    if (!FileObjHost) {
        Logger::Log("{RED}IoManager::AllocateFileObject UcToHost failed{RESET}\n");
        return 0;
    }

    memset(FileObjHost, 0, sizeof(_FILE_OBJECT));
    FileObjHost->Type = 5;
    FileObjHost->Size = (SHORT)sizeof(_FILE_OBJECT);
    FileObjHost->DeviceObject = (_DEVICE_OBJECT*)DeviceObjUcAddr;

    Logger::Log("{GRN}IoManager::AllocateFileObject UC=0x%llx DevObj=0x%llx{RESET}\n",
        FileObjUcAddr, DeviceObjUcAddr);

    return FileObjUcAddr;
}

void IoManager::FreeFileObject(uint64_t FileObjUcAddr) {
    if (FileObjUcAddr) {
        Logger::Log("{GRY}IoManager::FreeFileObject 0x%llx{RESET}\n", FileObjUcAddr);
    }
}

uint64_t ReadDispatchRoutine(_DRIVER_OBJECT* DrvObjHost, UCHAR MajorFunction) {
    if (MajorFunction >= 28)
        return 0;
    return (uint64_t)DrvObjHost->MajorFunction[MajorFunction];
}

void CompletionMapInsert(uint64_t IrpUcAddr, HANDLE Event) {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    CompletionMap[IrpUcAddr] = { Event, 0, 0, false };
}

void CompletionMapRemove(uint64_t IrpUcAddr) {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    CompletionMap.erase(IrpUcAddr);
}

bool CompletionMapRead(uint64_t IrpUcAddr, NTSTATUS* OutStatus, ULONG_PTR* OutInfo) {
    std::lock_guard<std::mutex> Guard(CompletionLock);
    auto It = CompletionMap.find(IrpUcAddr);
    if (It != CompletionMap.end() && It->second.Completed) {
        *OutStatus = It->second.Status;
        *OutInfo = It->second.Information;
        return true;
    }
    return false;
}

static IoManager::DispatchResult DispatchSimpleIrpSeh(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr, UCHAR MajorFunction) {
    IoManager::DispatchResult Result = {};
    Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
    Result.Information = 0;
    Result.TimedOut = false;

    auto DrvObjHost = (_DRIVER_OBJECT*)UnicornMem::UcToHost(DRIVER_OBJ_BASE_UC);
    if (!DrvObjHost) {
        Logger::Log("{RED}IoManager::DispatchSimple: cannot resolve DRIVER_OBJECT{RESET}\n");
        Result.Status = (NTSTATUS)0xC0000001;
        return Result;
    }

    uint64_t DispatchAddr = ReadDispatchRoutine(DrvObjHost, MajorFunction);
    if (!DispatchAddr) {
        Logger::Log("{YEL}IoManager::DispatchSimple MJ=0x%02x: no dispatch routine registered{RESET}\n", MajorFunction);
        Result.Status = (NTSTATUS)0xC0000010;
        return Result;
    }

    uint64_t IrpUcAddr = IoManager::AllocateIrp(UnicornEmu::PrimaryEngine, 1);
    if (!IrpUcAddr) {
        Result.Status = (NTSTATUS)0xC000009A;
        return Result;
    }

    auto IrpHost = (_IRP*)UnicornMem::UcToHost(IrpUcAddr);
    if (!IrpHost) {
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    uint64_t IoSlUcAddr = IrpUcAddr + sizeof(_IRP);
    auto IoSlHost = (_IO_STACK_LOCATION*)UnicornMem::UcToHost(IoSlUcAddr);
    if (!IoSlHost) {
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    IoSlHost->MajorFunction = MajorFunction;
    IoSlHost->MinorFunction = 0;
    IoSlHost->Flags = 0;
    IoSlHost->Control = 0;
    IoSlHost->DeviceObject = (_DEVICE_OBJECT*)DeviceObjUcAddr;
    IoSlHost->FileObject = (_FILE_OBJECT*)FileObjUcAddr;

    IrpHost->RequestorMode = 1;
    IrpHost->CurrentLocation = 1;
    IrpHost->Tail.Overlay.CurrentStackLocation = (_IO_STACK_LOCATION*)IoSlUcAddr;

    HANDLE CompletionEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!CompletionEvent) {
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    CompletionMapInsert(IrpUcAddr, CompletionEvent);

    Logger::Log("{CYN}IoManager::Dispatch MJ=0x%02x -> 0x%llx DevObj=0x%llx IRP=0x%llx{RESET}\n",
        MajorFunction, DispatchAddr, DeviceObjUcAddr, IrpUcAddr);

    ThreadContext* DispatchThread = UnicornThread::CreateEx(
        DispatchAddr,
        DeviceObjUcAddr,
        IrpUcAddr,
        0, 0,
        nullptr);

    if (!DispatchThread) {
        Logger::Log("{RED}IoManager::Dispatch MJ=0x%02x: failed to create dispatch thread{RESET}\n", MajorFunction);
        CompletionMapRemove(IrpUcAddr);
        CloseHandle(CompletionEvent);
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    DWORD WaitResult = WaitForSingleObject(CompletionEvent, 30000);

    if (WaitResult == WAIT_TIMEOUT) {
        Logger::Log("{YEL}IoManager::Dispatch MJ=0x%02x: timed out after 30s{RESET}\n", MajorFunction);

        if (DispatchThread->Running) {
            WaitForSingleObject(DispatchThread->HostThread, 5000);
        }

        auto FreshIrpHost = (_IRP*)UnicornMem::UcToHost(IrpUcAddr);
        if (FreshIrpHost) {
            Result.Status = FreshIrpHost->IoStatus.Status;
            Result.Information = FreshIrpHost->IoStatus.Information;
        }
        Result.TimedOut = true;
    } else {
        NTSTATUS CompStatus = 0;
        ULONG_PTR CompInfo = 0;
        if (CompletionMapRead(IrpUcAddr, &CompStatus, &CompInfo)) {
            Result.Status = CompStatus;
            Result.Information = CompInfo;
        } else {
            auto FreshIrpHost = (_IRP*)UnicornMem::UcToHost(IrpUcAddr);
            if (FreshIrpHost) {
                Result.Status = FreshIrpHost->IoStatus.Status;
                Result.Information = FreshIrpHost->IoStatus.Information;
            }
        }
    }

    CompletionMapRemove(IrpUcAddr);
    CloseHandle(CompletionEvent);
    IoManager::FreeIrp(IrpUcAddr);

    Logger::Log("{CYN}IoManager::Dispatch MJ=0x%02x result: Status=0x%08x Info=0x%llx%s{RESET}\n",
        MajorFunction, Result.Status, (uint64_t)Result.Information,
        Result.TimedOut ? " (TIMEOUT)" : "");

    return Result;
}

static IoManager::DispatchResult DispatchSimpleIrp(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr, UCHAR MajorFunction) {
    __try {
        return DispatchSimpleIrpSeh(DeviceObjUcAddr, FileObjUcAddr, MajorFunction);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoManager::DispatchSimple MJ=0x%02x: exception 0x%08x{RESET}\n",
            MajorFunction, GetExceptionCode());
        IoManager::DispatchResult Result = {};
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }
}

IoManager::DispatchResult IoManager::DispatchCreate(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr) {
    return DispatchSimpleIrp(DeviceObjUcAddr, FileObjUcAddr, 0x00);
}

IoManager::DispatchResult IoManager::DispatchClose(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr) {
    return DispatchSimpleIrp(DeviceObjUcAddr, FileObjUcAddr, 0x02);
}

IoManager::DispatchResult IoManager::DispatchCleanup(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr) {
    return DispatchSimpleIrp(DeviceObjUcAddr, FileObjUcAddr, 0x12);
}
