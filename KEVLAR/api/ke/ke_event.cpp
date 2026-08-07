#include "include/common.h"
#include "ke_event.h"
#include "ke_misc.h"

void h_KeInitializeEvent(_KEVENT* Event, _EVENT_TYPE Type, BOOLEAN State) {
    auto HostPtr = UnicornMem::UcToHost((uint64_t)Event);
    if (HostPtr) {
        auto HostEvent = (_KEVENT*)HostPtr;
        HostEvent->Header.SignalState = State;
        uint64_t WlhUcAddr = (uint64_t)Event + offsetof(_KEVENT, Header.WaitListHead);
        HostEvent->Header.WaitListHead.Flink = (PLIST_ENTRY)WlhUcAddr;
        HostEvent->Header.WaitListHead.Blink = (PLIST_ENTRY)WlhUcAddr;
        HostEvent->Header.Type = Type;
        *(WORD*)((char*)&HostEvent->Header.Lock + 1) = 0x600;
    }

    auto hEvent = CreateEvent(NULL, NULL, State, NULL);
    auto hMutex = CreateMutex(NULL, false, NULL);
    HandleManager::AddMap((uintptr_t)Event, (uintptr_t)hEvent);
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        MutexManager::mutex_manager.insert(std::pair((uintptr_t)Event, (uintptr_t)hMutex));
    }

    Logger::Log("  {GRY}Event object: {WHT}%llx{RESET}\n", Event);
}

LONG h_KeSetEvent(_KEVENT* Event, LONG Increment, BOOLEAN Wait) {
    LONG PreviousState = 0;

    auto HostPtr = UnicornMem::UcToHost((uint64_t)Event);
    if (HostPtr) {
        auto HostEvent = (_KEVENT*)HostPtr;
        if ((HostEvent->Header.Type == 0) && (HostEvent->Header.SignalState == 1) && !(Wait)) {
            return TRUE;
        }
        PreviousState = HostEvent->Header.SignalState;
        HostEvent->Header.SignalState = 1;
    }

    auto hEvent = HandleManager::GetHandle((uintptr_t)Event);
    if (hEvent)
        SetEvent((HANDLE)hEvent);
    return PreviousState;
}

void h_KeClearEvent(_KEVENT* Event) {

    auto hEvent = HandleManager::GetHandle((uintptr_t)Event);

    if (!hEvent) {
        Logger::Log("{YEL}\tKeClearEvent: no handle for event %llx{RESET}\n", Event);
        return;
    }

    uint64_t hMutex = 0;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (MutexManager::mutex_manager.contains((uintptr_t)Event))
            hMutex = MutexManager::mutex_manager[(uintptr_t)Event];
    }

    if (hMutex)
        ReleaseMutex((HANDLE)hMutex);
    ResetEvent((HANDLE)hEvent);

    return;
}

NTSTATUS h_KeWaitForSingleObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

    DeliverPendingApcs();   // kernel APCs deliver at PASSIVE waits

    auto Handle = HandleManager::GetHandle((uintptr_t)Object);
    if (!Handle) {
        Logger::Log("{YEL}\tKeWaitForSingleObject: no handle for object %llx -> returning success{RESET}\n", Object);
        return STATUS_SUCCESS;
    }

    DWORD WaitMs = INFINITE;
    bool IsInfinite = (Timeout == nullptr);

    if (Timeout) {
        auto HostTimeout = UcPtr(Timeout);
        if (HostTimeout->QuadPart == 0) {
            WaitMs = 0;
        } else if (HostTimeout->QuadPart < 0) {
            LONGLONG Positive = HostTimeout->QuadPart * -1;
            WaitMs = (DWORD)(Positive / 10000);
            if (WaitMs == 0 && Positive > 0)
                WaitMs = 1;
        } else {
            WaitMs = (DWORD)(HostTimeout->QuadPart / 10000);
        }
    }

    // Wait on the object and the thread's wake event so a cross-thread kernel APC
    // (signaled by KeInsertQueueApc) interrupts the wait and is delivered here.
    HANDLE WakeEvent = KeCurrentWakeEvent();

    if (IsInfinite) {
        const DWORD ChunkMs = 5000;
        int RetryCount = 0;
        while (true) {
            LARGE_INTEGER PreWait;
            QueryPerformanceCounter(&PreWait);
            DWORD WaitResult;
            if (WakeEvent) {
                HANDLE Handles[2] = { (HANDLE)Handle, WakeEvent };
                ResetEvent(WakeEvent);
                WaitResult = WaitForMultipleObjects(2, Handles, FALSE, ChunkMs);
            } else {
                WaitResult = WaitForSingleObject((HANDLE)Handle, ChunkMs);
            }
            LARGE_INTEGER PostWait;
            QueryPerformanceCounter(&PostWait);
            InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

            if (WaitResult == WAIT_OBJECT_0)
                return STATUS_SUCCESS;
            if (WaitResult == WAIT_OBJECT_0 + 1) {
                DeliverPendingApcs();   // woken by an APC; resume the wait
                continue;
            }

            RetryCount++;
            if (RetryCount % 6 == 0) {
                Logger::Log("{YEL}\tKeWaitForSingleObject: obj=%llx infinite wait, %ds elapsed...{RESET}\n",
                    Object, RetryCount * 5);
            }
        }
    }

    DWORD WaitResult;
    if (WakeEvent) {
        // Chunked wait so a cross-thread APC is delivered within ~5s even on a
        // long finite wait, while still honoring the remaining timeout.
        LONGLONG RemainingMs = WaitMs;
        WaitResult = WAIT_TIMEOUT;
        HANDLE Handles[2] = { (HANDLE)Handle, WakeEvent };
        while (RemainingMs > 0) {
            LARGE_INTEGER PreWait;
            QueryPerformanceCounter(&PreWait);
            ResetEvent(WakeEvent);
            DWORD Chunk = (DWORD)((RemainingMs > 5000) ? 5000 : RemainingMs);
            WaitResult = WaitForMultipleObjects(2, Handles, FALSE, Chunk);
            LARGE_INTEGER PostWait;
            QueryPerformanceCounter(&PostWait);
            InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

            if (WaitResult == WAIT_OBJECT_0)
                break;
            if (WaitResult == WAIT_OBJECT_0 + 1)
                DeliverPendingApcs();   // woken by an APC; keep waiting on the object
            RemainingMs -= Chunk;
        }
    } else {
        LARGE_INTEGER PreWait;
        QueryPerformanceCounter(&PreWait);
        WaitResult = WaitForSingleObject((HANDLE)Handle, WaitMs);
        LARGE_INTEGER PostWait;
        QueryPerformanceCounter(&PostWait);
        InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));
    }

    if (WaitResult == WAIT_TIMEOUT)
        return 0x00000102;

    return STATUS_SUCCESS;
}


NTSTATUS h_KeWaitForMutextObject(PVOID Object, void* WaitReason, void* WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    DeliverPendingApcs();

    HANDLE HostMutex = nullptr;
    {
        std::lock_guard<std::mutex> Guard(MutexManager::MutexLock);
        if (!MutexManager::mutex_manager.contains((uintptr_t)Object)) {
            Logger::Log("{YEL}\tKeWaitForMutextObject: no mutex for %p, returning success{RESET}\n", Object);
            return STATUS_SUCCESS;
        }
        HostMutex = (HANDLE)MutexManager::mutex_manager[(uintptr_t)Object];
    }

    DWORD WaitMs = INFINITE;
    bool IsInfinite = (Timeout == nullptr);

    if (Timeout) {
        auto HostTimeout = UcPtr(Timeout);
        if (HostTimeout->QuadPart == 0) {
            WaitMs = 0;
        } else if (HostTimeout->QuadPart < 0) {
            LONGLONG Positive = HostTimeout->QuadPart * -1;
            WaitMs = (DWORD)(Positive / 10000);
            if (WaitMs == 0 && Positive > 0)
                WaitMs = 1;
        } else {
            WaitMs = (DWORD)(HostTimeout->QuadPart / 10000);
        }
    }

    HANDLE WakeEvent = KeCurrentWakeEvent();

    if (IsInfinite) {
        const DWORD ChunkMs = 5000;
        int RetryCount = 0;
        while (true) {
            LARGE_INTEGER PreWait;
            QueryPerformanceCounter(&PreWait);
            DWORD WaitResult;
            if (WakeEvent) {
                HANDLE Handles[2] = { HostMutex, WakeEvent };
                ResetEvent(WakeEvent);
                WaitResult = WaitForMultipleObjects(2, Handles, FALSE, ChunkMs);
            } else {
                WaitResult = WaitForSingleObject(HostMutex, ChunkMs);
            }
            LARGE_INTEGER PostWait;
            QueryPerformanceCounter(&PostWait);
            InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

            if (WaitResult == WAIT_OBJECT_0)
                return STATUS_SUCCESS;
            if (WaitResult == WAIT_OBJECT_0 + 1) {
                DeliverPendingApcs();
                continue;
            }

            RetryCount++;
            if (RetryCount % 6 == 0) {
                Logger::Log("{YEL}\tKeWaitForMutextObject: mutex=%p infinite wait, %ds elapsed...{RESET}\n",
                    Object, RetryCount * 5);
            }
        }
    }

    DWORD WaitResult;
    if (WakeEvent) {
        LONGLONG RemainingMs = WaitMs;
        WaitResult = WAIT_TIMEOUT;
        HANDLE Handles[2] = { HostMutex, WakeEvent };
        while (RemainingMs > 0) {
            LARGE_INTEGER PreWait;
            QueryPerformanceCounter(&PreWait);
            ResetEvent(WakeEvent);
            DWORD Chunk = (DWORD)((RemainingMs > 5000) ? 5000 : RemainingMs);
            WaitResult = WaitForMultipleObjects(2, Handles, FALSE, Chunk);
            LARGE_INTEGER PostWait;
            QueryPerformanceCounter(&PostWait);
            InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

            if (WaitResult == WAIT_OBJECT_0)
                break;
            if (WaitResult == WAIT_OBJECT_0 + 1)
                DeliverPendingApcs();
            RemainingMs -= Chunk;
        }
    } else {
        LARGE_INTEGER PreWait;
        QueryPerformanceCounter(&PreWait);
        WaitResult = WaitForSingleObject(HostMutex, WaitMs);
        LARGE_INTEGER PostWait;
        QueryPerformanceCounter(&PostWait);
        InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));
    }

    if (WaitResult == WAIT_TIMEOUT)
        return 0x00000102;

    return STATUS_SUCCESS;
}

// Map a WaitForMultipleObjects result back to the original object index.
static NTSTATUS WaitResultToStatus(DWORD Ret, ULONG* OrigIndex, ULONG ValidCount, BOOL WaitAll) {
    if (Ret == WAIT_TIMEOUT || Ret == WAIT_FAILED)
        return (Ret == WAIT_TIMEOUT) ? STATUS_TIMEOUT : STATUS_SUCCESS;
    ULONG Idx = Ret - WAIT_OBJECT_0;
    if (Idx >= ValidCount)
        return STATUS_SUCCESS;
    return WaitAll ? STATUS_SUCCESS : (STATUS_WAIT_0 + OrigIndex[Idx]);
}

NTSTATUS
h_KeWaitForMultipleObjects(ULONG Count, PVOID Object[], uint32_t WaitType, _KWAIT_REASON WaitReason, uint32_t WaitMode, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout, _KWAIT_BLOCK* WaitBlockArray) {
    DeliverPendingApcs();

    auto HostObjArray = UcPtr(Object);
    HANDLE* HandleList = (HANDLE*)malloc(sizeof(HANDLE) * Count);
    ULONG* OrigIndex = (ULONG*)malloc(sizeof(ULONG) * Count);
    ULONG ValidCount = 0;
    for (ULONG I = 0; I < Count; I++) {
        auto H = HandleManager::GetHandle((uintptr_t)HostObjArray[I]);
        if (H) {
            HandleList[ValidCount] = (HANDLE)H;
            OrigIndex[ValidCount] = I;
            ValidCount++;
        }
    }

    if (ValidCount == 0) {
        free(HandleList);
        free(OrigIndex);
        return STATUS_SUCCESS;
    }

    BOOL WaitAll = (WaitType == 0);

    DWORD WaitMs = INFINITE;
    bool IsInfinite = (Timeout == nullptr);

    if (Timeout) {
        auto HostTimeout = UcPtr(Timeout);
        if (HostTimeout->QuadPart == 0) {
            WaitMs = 0;
        } else if (HostTimeout->QuadPart < 0) {
            LONGLONG Positive = HostTimeout->QuadPart * -1;
            WaitMs = (DWORD)(Positive / 10000);
            if (WaitMs == 0 && Positive > 0)
                WaitMs = 1;
        } else {
            WaitMs = (DWORD)(HostTimeout->QuadPart / 10000);
        }
    }

    // Append the thread's wake event (index ValidCount) so a cross-thread kernel
    // APC signaled by KeInsertQueueApc interrupts the wait promptly.
    HANDLE WakeEvent = KeCurrentWakeEvent();
    bool HasWake = (WakeEvent != nullptr);

    // One wait call: objects + wake event (WaitAny), with an explicit all-signaled
    // check below to preserve WaitAll completion semantics.
    auto WaitOnce = [&](DWORD ChunkMs) -> DWORD {
        if (!HasWake)
            return WaitForMultipleObjects(ValidCount, HandleList, WaitAll, ChunkMs);
        ResetEvent(WakeEvent);
        HANDLE* Wh = (HANDLE*)malloc(sizeof(HANDLE) * (ValidCount + 1));
        memcpy(Wh, HandleList, sizeof(HANDLE) * ValidCount);
        Wh[ValidCount] = WakeEvent;
        DWORD R = WaitForMultipleObjects(ValidCount + 1, Wh, FALSE, ChunkMs);
        free(Wh);
        return R;
    };

    auto AllObjectsSignaled = [&]() -> bool {
        for (ULONG I = 0; I < ValidCount; I++)
            if (WaitForSingleObject(HandleList[I], 0) != WAIT_OBJECT_0)
                return false;
        return true;
    };

    const DWORD ChunkMs = 5000;
    DWORD Ret = WAIT_TIMEOUT;

    if (IsInfinite) {
        int RetryCount = 0;
        while (true) {
            LARGE_INTEGER PreWait;
            QueryPerformanceCounter(&PreWait);
            Ret = WaitOnce(ChunkMs);
            LARGE_INTEGER PostWait;
            QueryPerformanceCounter(&PostWait);
            InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

            if (HasWake && Ret == WAIT_OBJECT_0 + ValidCount) {
                DeliverPendingApcs();   // woken by an APC; resume the wait
                continue;
            }
            if (Ret != WAIT_TIMEOUT) {
                if (WaitAll && !AllObjectsSignaled())
                    continue;   // WaitAll: not all signaled yet
                NTSTATUS St = WaitResultToStatus(Ret, OrigIndex, ValidCount, WaitAll);
                free(HandleList);
                free(OrigIndex);
                return St;
            }

            RetryCount++;
            if (RetryCount % 6 == 0) {
                Logger::Log("{YEL}\tKeWaitForMultipleObjects: count=%u infinite wait, %ds elapsed...{RESET}\n",
                    Count, RetryCount * 5);
            }
        }
    }

    LONGLONG RemainingMs = WaitMs;
    while (RemainingMs > 0) {
        LARGE_INTEGER PreWait;
        QueryPerformanceCounter(&PreWait);
        DWORD Chunk = (DWORD)((RemainingMs > ChunkMs) ? ChunkMs : RemainingMs);
        Ret = WaitOnce(Chunk);
        LARGE_INTEGER PostWait;
        QueryPerformanceCounter(&PostWait);
        InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostWait.QuadPart - PreWait.QuadPart));

        if (HasWake && Ret == WAIT_OBJECT_0 + ValidCount) {
            DeliverPendingApcs();
            RemainingMs -= Chunk;
            continue;
        }
        if (Ret != WAIT_TIMEOUT) {
            if (WaitAll && !AllObjectsSignaled()) {
                RemainingMs -= Chunk;
                continue;
            }
            break;
        }
        RemainingMs -= Chunk;
    }

    NTSTATUS FinalSt = WaitResultToStatus(Ret, OrigIndex, ValidCount, WaitAll);
    free(HandleList);
    free(OrigIndex);
    return FinalSt;
}
