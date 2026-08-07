#pragma once

#include <windows.h>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <mutex>

namespace IoManager {

struct IrpCompletionInfo {
    HANDLE Event;
    NTSTATUS Status;
    ULONG_PTR Information;
    bool Completed;
};

void Initialize();
void Shutdown();

void SignalCompletion(uint64_t IrpUcAddr, NTSTATUS Status, ULONG_PTR Information);

uint64_t AllocateIrp(uc_engine* Uc, CCHAR StackSize);
void FreeIrp(uint64_t IrpUcAddr);

uint64_t AllocateFileObject(uc_engine* Uc, uint64_t DeviceObjUcAddr);
void FreeFileObject(uint64_t FileObjUcAddr);

struct DispatchResult {
    NTSTATUS Status;
    ULONG_PTR Information;
    bool TimedOut;
};

DispatchResult DispatchCreate(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchClose(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchCleanup(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr);
DispatchResult DispatchDeviceIoControl(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    ULONG IoControlCode,
    void* InputBuffer, ULONG InputLength,
    void* OutputBuffer, ULONG OutputLength,
    ULONG* BytesReturned);
DispatchResult DispatchWrite(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* WriteBuffer, ULONG WriteLength,
    ULONG WriteOffset, ULONG* BytesWritten);
DispatchResult DispatchRead(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* ReadBuffer, ULONG ReadLength,
    ULONG ReadOffset, ULONG* BytesRead);

}
