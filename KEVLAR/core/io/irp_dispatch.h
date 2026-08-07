#pragma once

#include <windows.h>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include "core/io/io_manager.h"
#include "include/ntoskrnl_struct.h"

#define KEVLAR_STATUS_INTERNAL_ERROR ((NTSTATUS)0xC00000E5L)

extern std::unordered_map<uint64_t, IoManager::IrpCompletionInfo> CompletionMap;
extern std::mutex CompletionLock;

uint64_t ReadDispatchRoutine(_DRIVER_OBJECT* DrvObjHost, UCHAR MajorFunction);
void CompletionMapInsert(uint64_t IrpUcAddr, HANDLE Event);
void CompletionMapRemove(uint64_t IrpUcAddr);
bool CompletionMapRead(uint64_t IrpUcAddr, NTSTATUS* OutStatus, ULONG_PTR* OutInfo);
