#include "include/common.h"
#include "ex_sync.h"

#define EX_SPIN_LOCK volatile LONG

_ETHREAD* h_KeGetCurrentThread();

void h_ExAcquireFastMutex(PFAST_MUTEX FastMutex) {
    uint64_t hMutex = 0;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (!MutexManager::mutex_manager.contains((uintptr_t)FastMutex)) {
            auto NewMutex = CreateMutex(NULL, FALSE, NULL);
            MutexManager::mutex_manager[(uintptr_t)FastMutex] = (uint64_t)NewMutex;
            hMutex = (uint64_t)NewMutex;
        } else {
            hMutex = MutexManager::mutex_manager[(uintptr_t)FastMutex];
        }
    }

    WaitForSingleObject((HANDLE)hMutex, 30000);

    auto HostPtr = UnicornMem::UcToHost((uint64_t)FastMutex);
    if (HostPtr) {
        auto Fm = (PFAST_MUTEX)HostPtr;
        Fm->OldIrql = 0;
        Fm->Owner = (_KTHREAD*)h_KeGetCurrentThread();
        Fm->Count--;
    }
}

void h_ExReleaseFastMutex(PFAST_MUTEX FastMutex) {
    uint64_t hMutex = 0;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (!MutexManager::mutex_manager.contains((uintptr_t)FastMutex)) {
            return;
        }
        hMutex = MutexManager::mutex_manager[(uintptr_t)FastMutex];
    }
    ReleaseMutex((HANDLE)hMutex);

    auto HostPtr = UnicornMem::UcToHost((uint64_t)FastMutex);
    if (HostPtr) {
        auto Fm = (PFAST_MUTEX)HostPtr;
        Fm->OldIrql = 0;
        Fm->Owner = 0;
        Fm->Count++;
    }
}

_SLIST_ENTRY* h_ExpInterlockedPopEntrySList(PSLIST_HEADER SListHead) { return 0; }

void h_ExAcquireFastMutexUnsafe(PFAST_MUTEX FastMutex) {
    uint64_t HostMutex = 0;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (!MutexManager::mutex_manager.contains((uintptr_t)FastMutex)) {
            auto NewMutex = CreateMutex(NULL, FALSE, NULL);
            MutexManager::mutex_manager[(uintptr_t)FastMutex] = (uint64_t)NewMutex;
            HostMutex = (uint64_t)NewMutex;
        } else {
            HostMutex = MutexManager::mutex_manager[(uintptr_t)FastMutex];
        }
    }
    WaitForSingleObject((HANDLE)HostMutex, 30000);
    auto HostPtr = UnicornMem::UcToHost((uint64_t)FastMutex);
    if (HostPtr) {
        auto Fm = (PFAST_MUTEX)HostPtr;
        Fm->Owner = (_KTHREAD*)h_KeGetCurrentThread();
        Fm->Count--;
    }
}

void h_ExReleaseFastMutexUnsafe(PFAST_MUTEX FastMutex) {
    uint64_t HostMutex = 0;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (!MutexManager::mutex_manager.contains((uintptr_t)FastMutex))
            return;
        HostMutex = MutexManager::mutex_manager[(uintptr_t)FastMutex];
    }
    ReleaseMutex((HANDLE)HostMutex);
    auto HostPtr = UnicornMem::UcToHost((uint64_t)FastMutex);
    if (HostPtr) {
        auto Fm = (PFAST_MUTEX)HostPtr;
        Fm->Owner = 0;
        Fm->Count++;
    }
}

void h_ExInitializePushLock(volatile uint64_t* PushLock) {
    auto HostLock = UcPtr((uint64_t*)PushLock);
    *HostLock = 0;
}

void h_ExAcquirePushLockExclusiveEx(volatile uint64_t* PushLock, uint32_t Flags) {
    auto HostLock = (volatile LONG64*)UcPtr((uint64_t*)PushLock);
    while (_InterlockedCompareExchange64(HostLock, 1, 0) != 0)
        _mm_pause();
}

void h_ExReleasePushLockExclusiveEx(volatile uint64_t* PushLock, uint32_t Flags) {
    auto HostLock = (volatile LONG64*)UcPtr((uint64_t*)PushLock);
    _InterlockedExchange64(HostLock, 0);
}

void h_ExAcquireSpinLockExclusiveAtDpcLevel(volatile LONG* SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    while (_InterlockedCompareExchange(HostLock, 1, 0) != 0)
        _mm_pause();
}

void h_ExReleaseSpinLockExclusiveFromDpcLevel(volatile LONG* SpinLock) {
    auto HostLock = UcPtr(SpinLock);
    _InterlockedExchange(HostLock, 0);
}

BOOLEAN h_ExAcquireResourceExclusiveLite(_ERESOURCE* Resource, BOOLEAN Wait) {
    //Resource->OwnerEntry.OwnerThread = (uint64_t)h_KeGetCurrentThread();

    return true;
}

BOOLEAN h_ExAcquireResourceSharedLite(_ERESOURCE* Resource, BOOLEAN Wait) {
    return TRUE;
}

void h_ExReleaseResourceLite(_ERESOURCE* Resource) {}

NTSTATUS h_ExInitializeResourceLite(_ERESOURCE* Resource) {
    auto HostRes = UcPtr(Resource);
    memset(HostRes, 0, sizeof(_ERESOURCE));
    return STATUS_SUCCESS;
}

NTSTATUS h_ExDeleteResourceLite(_ERESOURCE* Resource) {
    return STATUS_SUCCESS;
}

BOOLEAN h_ExIsResourceAcquiredSharedLite(_ERESOURCE* Resource) { return FALSE; }
BOOLEAN h_ExIsResourceAcquiredExclusiveLite(_ERESOURCE* Resource) { return FALSE; }

__int64 __fastcall ExpWaitForSpinLockSharedAndAcquire(EX_SPIN_LOCK* a1)
{
    unsigned int v2;
    unsigned __int32 v4;
    bool v6;
    signed __int32 v7;

    v2 = 0;
    do
    {
        v4 = *a1;
        while (v4 < 0)
        {
            if ((v4 & 0x40000000) == 0)
            {
                v7 = _InterlockedCompareExchange(a1, v4 | 0x40000000, v4);
                v6 = v4 == v7;
                v4 = v7;
                if (!v6)
                    continue;
            }

            ++v2;
            _mm_pause();
            v4 = *a1;
        }
    } while (v4 != _InterlockedCompareExchange(a1, (v4 + 1) & 0xBFFFFFFF, v4));
    return v2;
}

__int64 __fastcall ExpWaitForSpinLockExclusiveAndAcquire(volatile LONG* a1)
{
    unsigned int v2;
    signed __int32 v4;
    signed __int32 v6;

    v2 = 0;
    do
    {
        v4 = *a1;
        while (v4 < 0)
        {
            if ((v4 & 0x40000000) == 0)
            {
                v6 = v4;
                v4 = _InterlockedCompareExchange(a1, v4 | 0x40000000, v4);
                if (v6 != v4)
                    continue;
            }

            ++v2;
            _mm_pause();

            v4 = *a1;
        }
    } while (_interlockedbittestandset(a1, 0x1Fu));
    return v2;
}


uint64_t  h_ExAcquireSpinLockExclusive(EX_SPIN_LOCK* SpinLock)
{
    auto HostLock = UcPtr(SpinLock);

    __int64 v2;
    bool v3;
    unsigned __int32 v4;
    int v5;

    v5 = 0;
    if (_interlockedbittestandset(HostLock, 0x1Fu))
        v5 = ExpWaitForSpinLockExclusiveAndAcquire(HostLock);
    v2 = *(unsigned int*)HostLock;
    if ((*HostLock & 0xBFFFFFFF) != 0x80000000)
    {
        do
        {
            if ((v2 & 0x40000000) == 0)
            {
                v4 = _InterlockedCompareExchange(HostLock, v2 | 0x40000000, v2);
                v3 = (DWORD)v2 == v4;
                v2 = v4;
                if (!v3)
                    continue;
            }
            Sleep(0);
            v2 = *(unsigned int*)HostLock;
        } while ((v2 & 0xBFFFFFFF) != 0x80000000);
    }
    return 0;
}

uint64_t  h_ExAcquireSpinLockShared(EX_SPIN_LOCK* SpinLock)
{
    auto HostLock = UcPtr(SpinLock);

    _m_prefetchw((const void*)HostLock);
    int v2 = *HostLock & 0x7FFFFFFF;
    if (v2 != _InterlockedCompareExchange(HostLock, v2 + 1, v2))
        ExpWaitForSpinLockSharedAndAcquire(HostLock);
    return 0;
}

void  h_ExReleaseSpinLockShared(EX_SPIN_LOCK* SpinLock, uint32_t OldIrql)
{
    auto HostLock = UcPtr(SpinLock);
    _InterlockedAnd(HostLock, 0xBFFFFFFF);
    _InterlockedDecrement(HostLock);
}

void  h_ExReleaseSpinLockExclusive(EX_SPIN_LOCK* SpinLock, uint32_t OldIrql)
{
    auto HostLock = UcPtr(SpinLock);
    *HostLock = 0;
}

static BOOLEAN ExfAcquireRundownProtectionImpl(volatile LONG64* Count) {
    LONG64 cur = *Count;
    if (cur & 1)
        return FALSE;

    while (true) {
        LONG64 prev = _InterlockedCompareExchange64(Count, cur + 2, cur);
        if (prev == cur)
            return TRUE;
        cur = prev;
        if (cur & 1)
            return FALSE;
    }
}

static BOOLEAN ExAcquireRundownProtectionImpl(volatile LONG64* Count) {
    _mm_prefetch((const char*)Count, _MM_HINT_T0);

    LONG64 expected = *Count & ~1LL;
    if (_InterlockedCompareExchange64(Count, expected + 2, expected) == expected)
        return TRUE;

    return ExfAcquireRundownProtectionImpl(Count);
}

static void ExReleaseRundownProtectionImpl(volatile LONG64* Count) {
    LONG64 cur = *Count;
    while (true) {
        LONG64 prev = _InterlockedCompareExchange64(Count, cur - 2, cur);
        if (prev == cur)
            break;
        cur = prev;
    }
}

void h_ExInitializeRundownProtection(_EX_RUNDOWN_REF* RunRef) {
    auto HostRef = UcPtr(RunRef);
    if (HostRef)
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&HostRef->Count), 0);
}

BOOLEAN h_ExAcquireRundownProtection(_EX_RUNDOWN_REF* RunRef) {
    auto HostRef = UcPtr(RunRef);
    if (!HostRef)
        return FALSE;
    return ExAcquireRundownProtectionImpl(reinterpret_cast<volatile LONG64*>(&HostRef->Count));
}

void h_ExReleaseRundownProtection(_EX_RUNDOWN_REF* RunRef) {
    auto HostRef = UcPtr(RunRef);
    if (!HostRef)
        return;
    ExReleaseRundownProtectionImpl(reinterpret_cast<volatile LONG64*>(&HostRef->Count));
}

void h_ExWaitForRundownProtectionRelease(_EX_RUNDOWN_REF* RunRef) {
    auto HostRef = UcPtr(RunRef);
    if (!HostRef)
        return;

    auto Count = reinterpret_cast<volatile LONG64*>(&HostRef->Count);
    LONG64 cur = *Count;
    while (!(cur & 1)) {
        LONG64 prev = _InterlockedCompareExchange64(Count, cur | 1, cur);
        if (prev == cur)
            break;
        cur = prev;
    }

    while ((*Count & ~1LL) != 0)
        _mm_pause();
}
