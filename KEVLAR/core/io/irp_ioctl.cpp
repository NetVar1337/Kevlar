#include "core/io/irp_dispatch.h"
#include "core/io/io_manager.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"
#include "include/ntoskrnl_struct.h"
#include <Logger/Logger.h>

static IoManager::DispatchResult DispatchDeviceIoControlSeh(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    ULONG IoControlCode,
    void* InputBuffer, ULONG InputLength,
    void* OutputBuffer, ULONG OutputLength,
    ULONG* BytesReturned)
{
    IoManager::DispatchResult Result = {};
    Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
    Result.Information = 0;
    Result.TimedOut = false;

    if (BytesReturned)
        *BytesReturned = 0;

    auto DrvObjHost = (_DRIVER_OBJECT*)UnicornMem::UcToHost(DRIVER_OBJ_BASE_UC);
    if (!DrvObjHost) {
        Logger::Log("{RED}IoManager::DispatchIoctl: cannot resolve DRIVER_OBJECT{RESET}\n");
        Result.Status = (NTSTATUS)0xC0000001;
        return Result;
    }

    uint64_t DispatchAddr = ReadDispatchRoutine(DrvObjHost, 0x0E);
    if (!DispatchAddr) {
        Logger::Log("{YEL}IoManager::DispatchIoctl: IRP_MJ_DEVICE_CONTROL not registered{RESET}\n");
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

    ULONG Method = IoControlCode & 3;
    uint64_t SystemBufferUcAddr = 0;
    uint64_t OutputBufUcAddr = 0;
    uint64_t InputBufUcAddr = 0;
    void* SystemBufferHost = nullptr;

    switch (Method) {
    case 0: {
        ULONG BufSize = (InputLength > OutputLength) ? InputLength : OutputLength;
        if (BufSize == 0) BufSize = 1;

        SystemBufferUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, BufSize, "IRP_SystemBuffer");
        if (!SystemBufferUcAddr) {
            IoManager::FreeIrp(IrpUcAddr);
            Result.Status = (NTSTATUS)0xC000009A;
            return Result;
        }

        SystemBufferHost = UnicornMem::UcToHost(SystemBufferUcAddr);
        if (SystemBufferHost && InputBuffer && InputLength > 0)
            memcpy(SystemBufferHost, InputBuffer, InputLength);

        IrpHost->AssociatedIrp.SystemBuffer = (void*)SystemBufferUcAddr;
        IrpHost->UserBuffer = (void*)SystemBufferUcAddr;

        IrpHost->Flags = 0x10 | 0x20;
        if (OutputLength > 0)
            IrpHost->Flags |= 0x40;
        break;
    }
    case 1:
    case 2: {
        if (InputLength > 0) {
            SystemBufferUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, InputLength, "IRP_DirectInput");
            if (SystemBufferUcAddr) {
                SystemBufferHost = UnicornMem::UcToHost(SystemBufferUcAddr);
                if (SystemBufferHost && InputBuffer)
                    memcpy(SystemBufferHost, InputBuffer, InputLength);
            }
        }

        if (OutputLength > 0)
            OutputBufUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, OutputLength, "IRP_DirectOutput");

        IrpHost->AssociatedIrp.SystemBuffer = (void*)SystemBufferUcAddr;
        IrpHost->MdlAddress = nullptr;
        IrpHost->UserBuffer = (void*)OutputBufUcAddr;
        break;
    }
    case 3: {
        if (InputLength > 0) {
            InputBufUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, InputLength, "IRP_NeitherInput");
            if (InputBufUcAddr) {
                auto InputHostPtr = UnicornMem::UcToHost(InputBufUcAddr);
                if (InputHostPtr && InputBuffer)
                    memcpy(InputHostPtr, InputBuffer, InputLength);
            }
        }

        if (OutputLength > 0)
            OutputBufUcAddr = UnicornMem::AllocateVariable(UnicornEmu::PrimaryEngine, OutputLength, "IRP_NeitherOutput");

        IoSlHost->Parameters.DeviceIoControl.Type3InputBuffer = (void*)InputBufUcAddr;
        IrpHost->UserBuffer = (void*)OutputBufUcAddr;
        break;
    }
    }

    IoSlHost->MajorFunction = 0x0E;
    IoSlHost->MinorFunction = 0;
    IoSlHost->Flags = 0;
    IoSlHost->Control = 0;
    IoSlHost->Parameters.DeviceIoControl.IoControlCode = IoControlCode;
    IoSlHost->Parameters.DeviceIoControl.InputBufferLength = InputLength;
    IoSlHost->Parameters.DeviceIoControl.OutputBufferLength = OutputLength;
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

    Logger::Log("{CYN}IoManager::DispatchIoctl IOCTL=0x%08x Method=%u InLen=%u OutLen=%u -> 0x%llx{RESET}\n",
        IoControlCode, Method, InputLength, OutputLength, DispatchAddr);

    ThreadContext* DispatchThread = UnicornThread::CreateEx(
        DispatchAddr,
        DeviceObjUcAddr,
        IrpUcAddr,
        0, 0,
        nullptr);

    if (!DispatchThread) {
        Logger::Log("{RED}IoManager::DispatchIoctl: failed to create dispatch thread{RESET}\n");
        CompletionMapRemove(IrpUcAddr);
        CloseHandle(CompletionEvent);
        IoManager::FreeIrp(IrpUcAddr);
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        return Result;
    }

    DWORD WaitResult = WaitForSingleObject(CompletionEvent, 30000);

    if (WaitResult == WAIT_TIMEOUT) {
        Logger::Log("{YEL}IoManager::DispatchIoctl IOCTL=0x%08x: timed out after 30s{RESET}\n", IoControlCode);

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

    if (Method == 0 && OutputBuffer && OutputLength > 0) {
        ULONG CopyLen = (OutputLength < (ULONG)Result.Information) ? OutputLength : (ULONG)Result.Information;
        if (CopyLen > 0 && SystemBufferHost)
            memcpy(OutputBuffer, SystemBufferHost, CopyLen);
    } else if ((Method == 1 || Method == 2) && OutputBuffer && OutputLength > 0 && OutputBufUcAddr) {
        auto OutputHostPtr = UnicornMem::UcToHost(OutputBufUcAddr);
        ULONG CopyLen = (OutputLength < (ULONG)Result.Information) ? OutputLength : (ULONG)Result.Information;
        if (CopyLen > 0 && OutputHostPtr)
            memcpy(OutputBuffer, OutputHostPtr, CopyLen);
    } else if (Method == 3 && OutputBuffer && OutputLength > 0 && OutputBufUcAddr) {
        auto OutputHostPtr = UnicornMem::UcToHost(OutputBufUcAddr);
        ULONG CopyLen = (OutputLength < (ULONG)Result.Information) ? OutputLength : (ULONG)Result.Information;
        if (CopyLen > 0 && OutputHostPtr)
            memcpy(OutputBuffer, OutputHostPtr, CopyLen);
    }

    if (BytesReturned)
        *BytesReturned = (ULONG)Result.Information;

    CompletionMapRemove(IrpUcAddr);
    CloseHandle(CompletionEvent);
    IoManager::FreeIrp(IrpUcAddr);

    Logger::Log("{CYN}IoManager::DispatchIoctl IOCTL=0x%08x result: Status=0x%08x Info=0x%llx%s{RESET}\n",
        IoControlCode, Result.Status, (uint64_t)Result.Information,
        Result.TimedOut ? " (TIMEOUT)" : "");

    return Result;
}

IoManager::DispatchResult IoManager::DispatchDeviceIoControl(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    ULONG IoControlCode,
    void* InputBuffer, ULONG InputLength,
    void* OutputBuffer, ULONG OutputLength,
    ULONG* BytesReturned)
{
    __try {
        return DispatchDeviceIoControlSeh(DeviceObjUcAddr, FileObjUcAddr,
            IoControlCode, InputBuffer, InputLength, OutputBuffer, OutputLength, BytesReturned);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}IoManager::DispatchIoctl IOCTL=0x%08x: exception 0x%08x{RESET}\n",
            IoControlCode, GetExceptionCode());
        DispatchResult Result = {};
        Result.Status = KEVLAR_STATUS_INTERNAL_ERROR;
        if (BytesReturned)
            *BytesReturned = 0;
        return Result;
    }
}
