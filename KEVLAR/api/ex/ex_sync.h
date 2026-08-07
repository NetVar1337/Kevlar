#pragma once
#include "include/common.h"

void h_ExAcquireFastMutex(PFAST_MUTEX FastMutex);
void h_ExReleaseFastMutex(PFAST_MUTEX FastMutex);
_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead);
BOOLEAN h_ExAcquireResourceExclusiveLite(_ERESOURCE* Resource, BOOLEAN Wait);
BOOLEAN h_ExAcquireResourceSharedLite(_ERESOURCE* Resource, BOOLEAN Wait);
void h_ExReleaseResourceLite(_ERESOURCE* Resource);
NTSTATUS h_ExInitializeResourceLite(_ERESOURCE* Resource);
NTSTATUS h_ExDeleteResourceLite(_ERESOURCE* Resource);
BOOLEAN h_ExIsResourceAcquiredSharedLite(_ERESOURCE* Resource);
BOOLEAN h_ExIsResourceAcquiredExclusiveLite(_ERESOURCE* Resource);
uint64_t h_ExAcquireSpinLockExclusive(volatile LONG* SpinLock);
uint64_t h_ExAcquireSpinLockShared(volatile LONG* SpinLock);
void h_ExReleaseSpinLockShared(volatile LONG* SpinLock, uint32_t OldIrql);
void h_ExReleaseSpinLockExclusive(volatile LONG* SpinLock, uint32_t OldIrql);
void h_ExInitializeRundownProtection(_EX_RUNDOWN_REF* RunRef);
BOOLEAN h_ExAcquireRundownProtection(_EX_RUNDOWN_REF* RunRef);
void h_ExReleaseRundownProtection(_EX_RUNDOWN_REF* RunRef);
void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef);
void h_ExAcquireFastMutexUnsafe(PFAST_MUTEX FastMutex);
void h_ExReleaseFastMutexUnsafe(PFAST_MUTEX FastMutex);
void h_ExInitializePushLock(volatile uint64_t* PushLock);
void h_ExAcquirePushLockExclusiveEx(volatile uint64_t* PushLock, uint32_t Flags);
void h_ExReleasePushLockExclusiveEx(volatile uint64_t* PushLock, uint32_t Flags);
void h_ExAcquireSpinLockExclusiveAtDpcLevel(volatile LONG* SpinLock);
void h_ExReleaseSpinLockExclusiveFromDpcLevel(volatile LONG* SpinLock);
