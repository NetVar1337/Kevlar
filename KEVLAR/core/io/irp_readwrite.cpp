#include "core/io/irp_dispatch.h"
#include "core/io/io_manager.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"
#include "include/ntoskrnl_struct.h"
#include <Logger/Logger.h>

static IoManager::DispatchResult DispatchWriteSeh(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* WriteBuffer, ULONG WriteLength,
    ULONG WriteOffset, ULONG* BytesWritten)
{
    IoManager::DispatchResult Result = {};
    Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
    Result.Information = 0;
    Result.TimedOut = false;

    if (BytesWritten)
        *BytesWritten = 0;

    auto DrvObjHost = (_DRIVER_OBJECT*)UnicornMem::UcToHost(DRIVER_OBJ_BASE_UC);
    if (!DrvObjHost) {
        Logger::Log("{RED}IoManager::DispatchWrite: cannot resolve DRIVER_OBJECT{RESET}\n");
        Result.Status = (NTSTATUS)0xC0000001;
        return Result;
    }

    uint64_t DispatchAddr = ReadDispatchRoutine(DrvObjHost, 0x04);
    if (!DispatchAddr) {
        Logger::Log("{YEL}IoManager::DispatchWrite: IRP_MJ_WRITE not registered{RESET}\n");
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

    uint64_t SystemBufferUcAddr = 0;
    void* SystemBufferHost = nullptr;

    if (WriteLength > 0) {
        SystemBufferUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, WriteLength, "IRP_WriteBuffer");
        if (!SystemBufferUcAddr) {
            IoManager::FreeIrp(IrpUcAddr);
            Result.Status = (NTSTATUS)0xC000009A;
            return Result;
        }

        SystemBufferHost = UnicornMem::UcToHost(SystemBufferUcAddr);
        if (SystemBufferHost && WriteBuffer)
            memcpy(SystemBufferHost, WriteBuffer, WriteLength);
    }

    IrpHost->AssociatedIrp.SystemBuffer = (void*)SystemBufferUcAddr;
    IrpHost->UserBuffer = (void*)SystemBufferUcAddr;
    IrpHost->Flags = 0x10 | 0x20;

    IoSlHost->MajorFunction = 0x04;
    IoSlHost->MinorFunction = 0;
    IoSlHost->Flags = 0;
    IoSlHost->Control = 0;
    IoSlHost->Parameters.Write.Length = WriteLength;
    IoSlHost->Parameters.Write.ByteOffset.QuadPart = WriteOffset;
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

    Logger::Log("{CYN}IoManager::DispatchWrite -> 0x%llx DevObj=0x%llx IRP=0x%llx Len=%u{RESET}\n",
        DispatchAddr, DeviceObjUcAddr, IrpUcAddr, WriteLength);

    ThreadContext* DispatchThread = UnicornThread::CreateEx(
        DispatchAddr,
        DeviceObjUcAddr,
        IrpUcAddr,
        0, 0,
        nullptr);

    if (!DispatchThread) {
        Logger::Log("{RED}IoManager::DispatchWrite: failed to create dispatch thread{RESET}\n");
        CompletionMapRemove(IrpUcAddr);
        CloseHandle(CompletionEvent);
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    DWORD WaitResult = WaitForSingleObject(CompletionEvent, 30000);

    if (WaitResult == WAIT_TIMEOUT) {
        Logger::Log("{YEL}IoManager::DispatchWrite: timed out after 30s{RESET}\n");
        if (DispatchThread->Running)
            WaitForSingleObject(DispatchThread->HostThread, 5000);
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

    if (BytesWritten)
        *BytesWritten = (ULONG)Result.Information;

    CompletionMapRemove(IrpUcAddr);
    CloseHandle(CompletionEvent);
    IoManager::FreeIrp(IrpUcAddr);

    Logger::Log("{CYN}IoManager::DispatchWrite result: Status=0x%08x Info=0x%llx%s{RESET}\n",
        Result.Status, (uint64_t)Result.Information,
        Result.TimedOut ? " (TIMEOUT)" : "");

    return Result;
}

IoManager::DispatchResult IoManager::DispatchWrite(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* WriteBuffer, ULONG WriteLength,
    ULONG WriteOffset, ULONG* BytesWritten)
{
    __try {
        return DispatchWriteSeh(DeviceObjUcAddr, FileObjUcAddr,
            WriteBuffer, WriteLength, WriteOffset, BytesWritten);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoManager::DispatchWrite: exception 0x%08x{RESET}\n", GetExceptionCode());
        DispatchResult Result = {};
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        if (BytesWritten)
            *BytesWritten = 0;
        return Result;
    }
}

static IoManager::DispatchResult DispatchReadSeh(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* ReadBuffer, ULONG ReadLength,
    ULONG ReadOffset, ULONG* BytesRead)
{
    IoManager::DispatchResult Result = {};
    Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
    Result.Information = 0;
    Result.TimedOut = false;

    if (BytesRead)
        *BytesRead = 0;

    auto DrvObjHost = (_DRIVER_OBJECT*)UnicornMem::UcToHost(DRIVER_OBJ_BASE_UC);
    if (!DrvObjHost) {
        Logger::Log("{RED}IoManager::DispatchRead: cannot resolve DRIVER_OBJECT{RESET}\n");
        Result.Status = (NTSTATUS)0xC0000001;
        return Result;
    }

    uint64_t DispatchAddr = ReadDispatchRoutine(DrvObjHost, 0x03);
    if (!DispatchAddr) {
        Logger::Log("{YEL}IoManager::DispatchRead: IRP_MJ_READ not registered{RESET}\n");
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

    uint64_t OutputBufUcAddr = 0;
    void* OutputBufHost = nullptr;

    if (ReadLength > 0) {
        OutputBufUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, ReadLength, "IRP_ReadBuffer");
        if (!OutputBufUcAddr) {
            IoManager::FreeIrp(IrpUcAddr);
            Result.Status = (NTSTATUS)0xC000009A;
            return Result;
        }
        OutputBufHost = UnicornMem::UcToHost(OutputBufUcAddr);
        if (OutputBufHost)
            memset(OutputBufHost, 0, ReadLength);
    }

    IrpHost->AssociatedIrp.SystemBuffer = (void*)OutputBufUcAddr;
    IrpHost->UserBuffer = (void*)OutputBufUcAddr;
    IrpHost->Flags = 0x10 | 0x40;

    IoSlHost->MajorFunction = 0x03;
    IoSlHost->MinorFunction = 0;
    IoSlHost->Flags = 0;
    IoSlHost->Control = 0;
    IoSlHost->Parameters.Read.Length = ReadLength;
    IoSlHost->Parameters.Read.ByteOffset.QuadPart = ReadOffset;
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

    Logger::Log("{CYN}IoManager::DispatchRead -> 0x%llx DevObj=0x%llx IRP=0x%llx Len=%u{RESET}\n",
        DispatchAddr, DeviceObjUcAddr, IrpUcAddr, ReadLength);

    ThreadContext* DispatchThread = UnicornThread::CreateEx(
        DispatchAddr,
        DeviceObjUcAddr,
        IrpUcAddr,
        0, 0,
        nullptr);

    if (!DispatchThread) {
        Logger::Log("{RED}IoManager::DispatchRead: failed to create dispatch thread{RESET}\n");
        CompletionMapRemove(IrpUcAddr);
        CloseHandle(CompletionEvent);
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    DWORD WaitResult = WaitForSingleObject(CompletionEvent, 30000);

    if (WaitResult == WAIT_TIMEOUT) {
        Logger::Log("{YEL}IoManager::DispatchRead: timed out after 30s{RESET}\n");
        if (DispatchThread->Running)
            WaitForSingleObject(DispatchThread->HostThread, 5000);
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

    if (ReadBuffer && ReadLength > 0 && OutputBufHost) {
        ULONG CopyLen = (ReadLength < (ULONG)Result.Information) ? ReadLength : (ULONG)Result.Information;
        if (CopyLen > 0)
            memcpy(ReadBuffer, OutputBufHost, CopyLen);
    }

    if (BytesRead)
        *BytesRead = (ULONG)Result.Information;

    CompletionMapRemove(IrpUcAddr);
    CloseHandle(CompletionEvent);
    IoManager::FreeIrp(IrpUcAddr);

    Logger::Log("{CYN}IoManager::DispatchRead result: Status=0x%08x Info=0x%llx%s{RESET}\n",
        Result.Status, (uint64_t)Result.Information,
        Result.TimedOut ? " (TIMEOUT)" : "");

    return Result;
}

IoManager::DispatchResult IoManager::DispatchRead(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* ReadBuffer, ULONG ReadLength,
    ULONG ReadOffset, ULONG* BytesRead)
{
    __try {
        return DispatchReadSeh(DeviceObjUcAddr, FileObjUcAddr,
            ReadBuffer, ReadLength, ReadOffset, BytesRead);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoManager::DispatchRead: exception 0x%08x{RESET}\n", GetExceptionCode());
        DispatchResult Result = {};
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        if (BytesRead)
            *BytesRead = 0;
        return Result;
    }
}
