#pragma once
#include "include/common.h"

LONG h_KeSetEvent(_KEVENT* Event, LONG Increment, BOOLEAN Wait);
NTSTATUS h_KeWaitForSingleObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

int h_ExpUnblockPushLock(volatile __int64* A1, void* A2, char A3);
int h_ExfUnblockPushLock(volatile __int64* A1, void* A2);
__int64 h_ExEnumHandleTable(__int64 A1Uc, __int64 (__fastcall *A2CbUc)(__int64, signed __int64*, uint64_t, __int64), __int64 A3Uc, uint64_t* A4Uc);
