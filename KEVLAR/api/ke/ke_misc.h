#pragma once
#include "include/common.h"

_ETHREAD* h_KeGetCurrentThread();
uint64_t h_KeAreAllApcsDisabled();
uint64_t h_KeAreApcsDisabled();
ULONG h_KeQueryTimeIncrement();
NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);
ULONG_PTR h_KeIpiGenericCall(PVOID BroadcastFunction, ULONG_PTR Context);
uint64_t h_KeGetCurrentIrql();
uint64_t h_KeRaiseIrqlToDpcLevel();
UCHAR h_KfRaiseIrql(UCHAR NewIrql);
UCHAR h_KeRaiseIrql(UCHAR NewIrql);
void h_KeLowerIrql(UCHAR NewIrql);
void h_KfLowerIrql(UCHAR NewIrql);
LARGE_INTEGER h_KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency);
void h_KeStackAttachProcess(void* Process, void* ApcState);
void h_KeUnstackDetachProcess(void* ApcState);
void h_KeInitializeApc(_KAPC* Apc, _KTHREAD* Thread, uint8_t Environment, void* KernelRoutine, void* RundownRoutine, void* NormalRoutine, uint8_t ApcMode, void* NormalContext);
BOOLEAN h_KeInsertQueueApc(_KAPC* Apc, void* SystemArgument1, void* SystemArgument2, uint8_t Increment);
BOOLEAN h_KeRemoveQueueApc(_KAPC* Apc);
BOOLEAN h_KeTestAlertThread(uint8_t AlertMode);
BOOLEAN h_KeAlertThread(void* Thread, uint8_t AlertMode);
// Deliver queued kernel APCs on the current thread; returns how many ran.
// Called from wait/alert delivery points (ke_event, ke_misc) and KeInsertQueueApc.
int DeliverPendingApcs();
// Wake event for the current thread's wait (per-thread for workers, a lazily
// created shared event for the primary DriverEntry thread). Returns nullptr if
// no context exists at all. Waits wait on it so a cross-thread APC wakes them.
HANDLE KeCurrentWakeEvent();
uint64_t h_KeQueryActiveProcessorCountEx(uint16_t GroupNumber);
void h_KeQuerySystemTimePrecise(PLARGE_INTEGER CurrentTime);
