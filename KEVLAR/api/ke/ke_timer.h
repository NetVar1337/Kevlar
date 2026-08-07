#pragma once
#include "include/common.h"

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc);
void h_KeInitializeTimer(_KTIMER* Timer);
BOOLEAN h_KeCancelTimer(_KTIMER* Timer);
BOOLEAN h_KeReadStateTimer(_KTIMER* timer);
void h_KeInitializeDpc(PVOID Dpc, PVOID DeferredRoutine, PVOID DeferredContext);
BOOLEAN h_KeInsertQueueDpc(_KDPC* Dpc, PVOID SystemArgument1, PVOID SystemArgument2);
BOOLEAN h_KeRemoveQueueDpc(_KDPC* Dpc);
void h_KeFlushQueuedDpcs();
void h_KeInitializeTimerEx(_KTIMER* Timer, uint32_t Type);
BOOLEAN h_KeSetTimerEx(_KTIMER* Timer, LARGE_INTEGER DueTime, LONG Period, _KDPC* Dpc);
