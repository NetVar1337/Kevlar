#pragma once
#include "include/common.h"

void h_KeInitializeEvent(_KEVENT* Event, _EVENT_TYPE Type, BOOLEAN State);
LONG h_KeSetEvent(_KEVENT* Event, LONG Increment, BOOLEAN Wait);
void h_KeClearEvent(_KEVENT* Event);
NTSTATUS h_KeWaitForSingleObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NTSTATUS h_KeWaitForMutextObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NTSTATUS h_KeWaitForMultipleObjects(ULONG Count, PVOID Object[], uint32_t WaitType, _KWAIT_REASON WaitReason, uint32_t WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout, _KWAIT_BLOCK* WaitBlockArray);
