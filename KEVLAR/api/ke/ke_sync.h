#pragma once
#include "include/common.h"

UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock);
void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql);
void h_KeInitializeSpinLock(PKSPIN_LOCK SpinLock);
UCHAR h_KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK SpinLock);
void h_KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK SpinLock);
void h_KeInitializeMutex(PVOID Mutex, ULONG Level);
LONG h_KeReleaseMutex(PVOID Mutex, BOOLEAN Wait);
void h_KeInitializeGuardedMutex(_KGUARDED_MUTEX* Mutex);
void h_KeEnterCriticalRegion();
void h_KeLeaveCriticalRegion();
void h_KeEnterGuardedRegion();
void h_KeLeaveGuardedRegion();
void h_KeLeaveCriticalRegionThread(_KTHREAD* A1);
void h_KeInitializeSemaphore(PVOID Semaphore, LONG Count, LONG Limit);
LONG h_KeReleaseSemaphore(PVOID Semaphore, LONG Increment, LONG Adjustment, BOOLEAN Wait);
void h_KeCapturePersistentThreadState(PVOID Thread, ULONG BugCheckCode, ULONG BugCheckParameter1, ULONG BugCheckParameter2, ULONG BugCheckParameter3, ULONG BugCheckParameter4, PVOID Context);
