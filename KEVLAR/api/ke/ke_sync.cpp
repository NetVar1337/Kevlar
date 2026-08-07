#include "include/common.h"
#include "ke_sync.h"

UCHAR h_KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    while (_InterlockedCompareExchange64((volatile LONG64*)HostLock, 1, 0) != 0)
        _mm_pause();
    return (UCHAR)0x00;
}

void h_KeReleaseSpinLock(PKSPIN_LOCK SpinLock, UCHAR NewIrql) {
    auto HostLock = UcPtr(SpinLock);
    _InterlockedExchange64((volatile LONG64*)HostLock, 0);
}

void h_KeInitializeSpinLock(PKSPIN_LOCK SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    *HostLock = 0;
}

UCHAR h_KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    while (_InterlockedCompareExchange64((volatile LONG64*)HostLock, 1, 0) != 0)
        _mm_pause();
    return 0;
}

void h_KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    _InterlockedExchange64((volatile LONG64*)HostLock, 0);
}

void h_KeInitializeMutex(PVOID Mutex, ULONG Level) {
    Logger::Log("{MAG}\tKeInitializeMutex: mutex=%p level=%u{RESET}\n", Mutex, Level);

    auto HostObj = UcPtr((_DISPATCHER_HEADER*)Mutex);
    if (HostObj) {
        memset(HostObj, 0, sizeof(_DISPATCHER_HEADER));
        HostObj->Type = 2;
        HostObj->SignalState = 1;
        uint64_t WlhUcAddr = (uint64_t)Mutex + offsetof(_DISPATCHER_HEADER, WaitListHead);
        HostObj->WaitListHead.Flink = (PLIST_ENTRY)WlhUcAddr;
        HostObj->WaitListHead.Blink = (PLIST_ENTRY)WlhUcAddr;
    }

    HANDLE HostMutex = CreateMutexW(NULL, FALSE, NULL);
    if (HostMutex) {
        {
            std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
            MutexManager::mutex_manager[(uintptr_t)Mutex] = (uint64_t)HostMutex;
        }
        HandleManager::AddMap((uintptr_t)Mutex, (uintptr_t)HostMutex);
    }
}

LONG h_KeReleaseMutex(PVOID Mutex, BOOLEAN Wait) {
    Logger::Log("{MAG}\tKeReleaseMutex: mutex=%p wait=%u{RESET}\n", Mutex, Wait);
    HANDLE HostMutex = nullptr;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (MutexManager::mutex_manager.contains((uintptr_t)Mutex))
            HostMutex = (HANDLE)MutexManager::mutex_manager[(uintptr_t)Mutex];
    }
    if (HostMutex)
        ReleaseMutex(HostMutex);
    return 0;
}

void h_KeInitializeGuardedMutex(_KGUARDED_MUTEX* Mutex) {
    auto HostMutex = UcPtr(Mutex);
    HostMutex->Owner = 0i64;
    HostMutex->Count = 1;
    HostMutex->Contention = 0;
    Logger::Log("{MAG}\tMutex gate : %llx{RESET}\n", &Mutex->Gate);
    HostMutex->Gate.Header.Type = 1;
    HostMutex->Gate.Header.Size = 6;
    HostMutex->Gate.Header.Signalling = 0;
    HostMutex->Gate.Header.SignalState = 0;
    uint64_t GateWlhUcAddr = (uint64_t)Mutex + offsetof(_KGUARDED_MUTEX, Gate.Header.WaitListHead);
    HostMutex->Gate.Header.WaitListHead.Flink = (PLIST_ENTRY)GateWlhUcAddr;
    HostMutex->Gate.Header.WaitListHead.Blink = (PLIST_ENTRY)GateWlhUcAddr;
    auto hMutex = CreateMutex(NULL, false, NULL);
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        MutexManager::mutex_manager.insert(std::pair((uintptr_t)Mutex, (uintptr_t)hMutex));
    }
}

void h_KeEnterCriticalRegion() {}
void h_KeLeaveCriticalRegion() {}
void h_KeEnterGuardedRegion() {}
void h_KeLeaveGuardedRegion() {}

void h_KeInitializeSemaphore(PVOID Semaphore, LONG Count, LONG Limit) {
    Logger::Log("{MAG}\tKeInitializeSemaphore: sem=%p count=%d limit=%d{RESET}\n", Semaphore, Count, Limit);

    auto HostObj = UcPtr((_KSEMAPHORE*)Semaphore);
    if (HostObj) {
        memset(HostObj, 0, sizeof(_KSEMAPHORE));
        HostObj->Header.Type = 5;
        HostObj->Header.SignalState = Count;
        HostObj->Limit = Limit;
        uint64_t WlhUcAddr = (uint64_t)Semaphore + offsetof(_KSEMAPHORE, Header.WaitListHead);
        HostObj->Header.WaitListHead.Flink = (PLIST_ENTRY)WlhUcAddr;
        HostObj->Header.WaitListHead.Blink = (PLIST_ENTRY)WlhUcAddr;
    }

    HANDLE HostSem = CreateSemaphoreW(NULL, Count, Limit, NULL);
    if (HostSem) {
        {
            std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
            MutexManager::mutex_manager[(uintptr_t)Semaphore] = (uint64_t)HostSem;
        }
        HandleManager::AddMap((uintptr_t)Semaphore, (uintptr_t)HostSem);
    }
}

LONG h_KeReleaseSemaphore(PVOID Semaphore, LONG Increment, LONG Adjustment, BOOLEAN Wait) {
    Logger::Log("{MAG}\tKeReleaseSemaphore: sem=%p adj=%d{RESET}\n", Semaphore, Adjustment);
    HANDLE HostSem = nullptr;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (MutexManager::mutex_manager.contains((uintptr_t)Semaphore))
            HostSem = (HANDLE)MutexManager::mutex_manager[(uintptr_t)Semaphore];
    }
    LONG PreviousCount = 0;
    if (HostSem)
        ReleaseSemaphore(HostSem, Adjustment > 0 ? Adjustment : 1, &PreviousCount);
    return PreviousCount;
}

void h_KeCapturePersistentThreadState(PVOID Thread, ULONG BugCheckCode, ULONG BugCheckParameter1, ULONG BugCheckParameter2, ULONG BugCheckParameter3, ULONG BugCheckParameter4, PVOID Context) {
    Logger::Log("{GRY}\tKeCapturePersistentThreadState: thread=%p bugcheck=0x%x{RESET}\n", Thread, BugCheckCode);
}

void h_KeLeaveCriticalRegionThread(_KTHREAD* A1) {
    auto A1Host = UcPtr(A1);
    if (!A1Host) return;
    SHORT* ApcDisable = (SHORT*)((uint8_t*)A1Host + 0x1E4);
    if ((*ApcDisable)++ == (SHORT)0xFFFF) {
    }
}
