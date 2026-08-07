#include "include/common.h"
#include "ke_timer.h"
#include "core/process/unicorn_threading.h"

struct TimerFireInfo {
    _KTIMER* Timer;
    _KDPC* Dpc;
    uint64_t DpcRoutine;
    uint64_t DpcContext;
    DWORD DelayMs;
    LONG PeriodMs;
    volatile LONG Canceled;
};

static std::unordered_map<_KTIMER*, TimerFireInfo*> g_PendingTimerFires;
static std::mutex g_TimerFireLock;

static void RegisterTimerFire(_KTIMER* Timer, TimerFireInfo* Info) {
    std::lock_guard<std::mutex> Lock(g_TimerFireLock);
    g_PendingTimerFires[Timer] = Info;
}

// Fire the timer's DPC (on the fire thread); returns false if canceled in flight.
static bool FireTimerDpc(TimerFireInfo* Info) {
    if (Info->Canceled) return false;

    auto HostTimer = UcPtr(Info->Timer);
    if (HostTimer) HostTimer->Header.SignalState = 1;

    auto hEvent = HandleManager::GetHandle((uintptr_t)Info->Timer);
    if (hEvent) SetEvent((HANDLE)hEvent);

    Logger::Log("{CYN}\tDPC timer fired: timer=%llx routine=%llx ctx=%llx — spawning UC thread{RESET}\n",
        Info->Timer, Info->DpcRoutine, Info->DpcContext);

    if (Info->DpcRoutine) {
        UnicornThread::CreateEx(
            Info->DpcRoutine,
            (uint64_t)Info->Dpc,
            Info->DpcContext,
            0, 0,
            nullptr);
    }
    return true;
}

// __try lives in a function with no C++ objects needing unwinding (C2712).
static void FireThreadBody(TimerFireInfo* Info) {
    __try {
        Sleep(Info->DelayMs);
        if (FireTimerDpc(Info)) {
            // periodic re-fire until canceled (KeCancelTimer) or the timer is re-set
            while (Info->PeriodMs != 0 && !Info->Canceled) {
                Sleep(Info->PeriodMs);
                FireTimerDpc(Info);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}DPC fire thread exception 0x%08x{RESET}\n", GetExceptionCode());
    }
}

static void FireThreadMain(TimerFireInfo* Info) {
    FireThreadBody(Info);
    {
        std::lock_guard<std::mutex> Lock(g_TimerFireLock);
        g_PendingTimerFires.erase(Info->Timer);
    }
    delete Info;
}

static void SetTimerImpl(_KTIMER* Timer, LARGE_INTEGER DueTime, LONG Period, _KDPC* Dpc) {
    auto HostTimer = UcPtr(Timer);
    if (!HostTimer) return;

    memcpy(&HostTimer->DueTime, &DueTime, sizeof(DueTime));
    HostTimer->Period = Period;

    {
        std::lock_guard<std::mutex> Guard(TimerManager::TimerLock);
        TimerManager::timer_manager[Timer] = GetTickCount64();
    }
    HostTimer->Header.SignalState = 0;

    if (Dpc) {
        auto HostDpc = UcPtr(Dpc);
        DWORD DueMs = 0;
        if (DueTime.QuadPart < 0)
            DueMs = (DWORD)(DueTime.QuadPart * -1 / 10000);
        // ponytail: clamp due/period to [10ms, 5s] -- harness granularity; a driver
        // that needs sub-10ms timing must be calibrated against a real trace
        if (DueMs < 10) DueMs = 10;
        if (DueMs > 5000) DueMs = 5000;

        LONG PeriodMs = 0;
        if (Period != 0) {
            LONGLONG AbsPeriod = Period < 0 ? -(LONGLONG)Period : (LONGLONG)Period;
            PeriodMs = (LONG)(AbsPeriod / 10000);
            if (PeriodMs < 10) PeriodMs = 10;
            if (PeriodMs > 5000) PeriodMs = 5000;
        }

        auto Info = new TimerFireInfo{
            Timer, Dpc,
            (uint64_t)HostDpc->DeferredRoutine,
            (uint64_t)HostDpc->DeferredContext,
            DueMs, PeriodMs, 0 };
        RegisterTimerFire(Timer, Info);

        CreateThread(nullptr, 0, [](LPVOID Param) -> DWORD {
            FireThreadMain((TimerFireInfo*)Param);
            return 0;
        }, Info, 0, nullptr);
    }
}

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc) {
    Logger::Log("{CYN}\tTimer object : %llx{RESET}\n", Timer);
    Logger::Log("{CYN}\tDPC object : %llx{RESET}\n", Dpc);
    SetTimerImpl(Timer, DueTime, 0, Dpc);
    return true;
}

void h_KeInitializeTimer(_KTIMER* Timer) {
    auto HostTimer = UcPtr(Timer);
    uint64_t TleUcAddr = (uint64_t)Timer + offsetof(_KTIMER, TimerListEntry);
    HostTimer->TimerListEntry.Flink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->TimerListEntry.Blink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->Header.SignalState = 0;
}

BOOLEAN h_KeCancelTimer(_KTIMER* Timer) {
    bool WasPending = false;
    {
        std::lock_guard<std::mutex> Lock(g_TimerFireLock);
        auto It = g_PendingTimerFires.find(Timer);
        if (It != g_PendingTimerFires.end()) {
            It->second->Canceled = 1;   // fire thread checks before spawning the DPC
            g_PendingTimerFires.erase(It);
            WasPending = true;
        }
    }
    {
        std::lock_guard<std::mutex> Guard(TimerManager::TimerLock);
        WasPending |= TimerManager::timer_manager.erase(Timer) > 0;
    }
    auto HostTimer = UcPtr(Timer);
    if (HostTimer) HostTimer->Header.SignalState = 0;
    return WasPending;
}

BOOLEAN h_KeReadStateTimer(_KTIMER* timer) {
    auto HostTimer = UcPtr(timer);
    {
        std::lock_guard<std::mutex> Guard(TimerManager::TimerLock);
        if (TimerManager::timer_manager.contains(timer)) {
            auto timeSet = TimerManager::timer_manager[timer];
            if ((HostTimer->DueTime.QuadPart * -1 / 10000) + timeSet < GetTickCount64()) {
                HostTimer->Header.SignalState = 1;
                return true;
            }
            else {
                return false;
            }
        }
        else {
            Logger::Log("{YEL}\tKeReadStateTimer: timer %llx not tracked, returning false{RESET}\n", timer);
        }
    }
    return false;
}

void h_KeInitializeDpc(PVOID Dpc, PVOID DeferredRoutine, PVOID DeferredContext) {
    auto HostDpc = UcPtr((_KDPC*)Dpc);
    if (!HostDpc) return;
    memset(HostDpc, 0, sizeof(_KDPC));
    HostDpc->Type = 0x13;                                  // DpcObject
    HostDpc->DeferredRoutine = (VOID(*)(_KDPC*, VOID*, VOID*, VOID*))DeferredRoutine;
    HostDpc->DeferredContext = DeferredContext;
}

struct DpcFireInfo { _KDPC* Dpc; };
static void FireDpcWorker(DpcFireInfo* FI);

BOOLEAN h_KeInsertQueueDpc(_KDPC* Dpc, PVOID SystemArgument1, PVOID SystemArgument2) {
    auto HostDpc = UcPtr(Dpc);
    if (!HostDpc || !HostDpc->DeferredRoutine) return FALSE;

    {
        std::lock_guard<std::mutex> Lock(DpcManager::DpcLock);
        if (DpcManager::dpc_queue.contains(Dpc)) return FALSE;
        DpcManager::dpc_queue.insert(Dpc);
    }

    HostDpc->SystemArgument1 = SystemArgument1;
    HostDpc->SystemArgument2 = SystemArgument2;

    // Fire on a host worker running the routine via a shared-map UC thread --
    // the same pattern the timer-DPC path uses (DeferredRoutine(Dpc, Ctx, A1, A2)).
    auto Info = new DpcFireInfo{ Dpc };
    CreateThread(nullptr, 0, [](LPVOID Param) -> DWORD {
        __try {
            FireDpcWorker((DpcFireInfo*)Param);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::Log("{RED}DPC fire thread exception 0x%08x{RESET}\n", GetExceptionCode());
        }
        return 0;
    }, Info, 0, nullptr);

    return TRUE;
}

// __try lives in the lambda above; the worker keeps C++ objects (lock_guard) out of it.
static void FireDpcWorker(DpcFireInfo* FI) {
    auto HostDpc = UcPtr(FI->Dpc);
    {
        std::lock_guard<std::mutex> Lock(DpcManager::DpcLock);
        DpcManager::dpc_queue.erase(FI->Dpc);
    }
    if (HostDpc && HostDpc->DeferredRoutine) {
        Logger::Log("{CYN}\tDPC fired: dpc=%llx routine=%llx ctx=%llx{RESET}\n",
            FI->Dpc, (uint64_t)HostDpc->DeferredRoutine, (uint64_t)HostDpc->DeferredContext);
        UnicornThread::CreateEx(
            (uint64_t)HostDpc->DeferredRoutine,
            (uint64_t)FI->Dpc,
            (uint64_t)HostDpc->DeferredContext,
            (uint64_t)HostDpc->SystemArgument1,
            (uint64_t)HostDpc->SystemArgument2,
            nullptr);
    }
    delete FI;
}

BOOLEAN h_KeRemoveQueueDpc(_KDPC* Dpc) {
    std::lock_guard<std::mutex> Lock(DpcManager::DpcLock);
    return DpcManager::dpc_queue.erase(Dpc) > 0;
}

// ponytail: flush is a no-op -- DPCs fire on their own worker thread the moment they're
// queued, so nothing is left pending for the calling thread to flush.
void h_KeFlushQueuedDpcs() {}

void h_KeInitializeTimerEx(_KTIMER* Timer, uint32_t Type) {
    auto HostTimer = UcPtr(Timer);
    memset(HostTimer, 0, sizeof(_KTIMER));
    HostTimer->Header.Type = (UCHAR)Type;
    uint64_t TleUcAddr = (uint64_t)Timer + offsetof(_KTIMER, TimerListEntry);
    HostTimer->TimerListEntry.Flink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->TimerListEntry.Blink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->Header.SignalState = 0;
}

BOOLEAN h_KeSetTimerEx(_KTIMER* Timer, LARGE_INTEGER DueTime, LONG Period, _KDPC* Dpc) {
    SetTimerImpl(Timer, DueTime, Period, Dpc);
    return TRUE;
}
