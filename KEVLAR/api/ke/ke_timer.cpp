#include "include/common.h"
#include "ke_timer.h"
#include "core/process/unicorn_threading.h"

BOOLEAN h_KeSetTimer(_KTIMER* Timer, LARGE_INTEGER DueTime, _KDPC* Dpc) {
    auto HostTimer = UcPtr(Timer);
    Logger::Log("{CYN}\tTimer object : %llx{RESET}\n", Timer);
    Logger::Log("{CYN}\tDPC object : %llx{RESET}\n", Dpc);

    if (Dpc) {
        auto HostDpc = UcPtr(Dpc);
        Logger::Log("{YEL}\tKeSetTimer: DPC provided (routine=%llx ctx=%llx) — DPC will fire when timer expires{RESET}\n",
            HostDpc->DeferredRoutine, HostDpc->DeferredContext);
    }

    memcpy(&HostTimer->DueTime, &DueTime, sizeof(DueTime));

    {
        std::lock_guard<std::mutex> Guard(TimerManager::TimerLock);
        if (TimerManager::timer_manager.contains(Timer))
            TimerManager::timer_manager[Timer] = GetTickCount64();
        else
            TimerManager::timer_manager.insert(std::pair(Timer, GetTickCount64()));
    }

    HostTimer->Header.SignalState = 0;

    if (Dpc) {
        auto HostDpc = UcPtr(Dpc);
        uint64_t DpcRoutine = (uint64_t)HostDpc->DeferredRoutine;
        uint64_t DpcContext = (uint64_t)HostDpc->DeferredContext;
        DWORD DueMs = 0;
        if (DueTime.QuadPart < 0)
            DueMs = (DWORD)(DueTime.QuadPart * -1 / 10000);
        if (DueMs < 10) DueMs = 10;
        if (DueMs > 5000) DueMs = 5000;

        struct DpcFireInfo {
            _KTIMER* Timer;
            _KDPC* Dpc;
            uint64_t DpcRoutine;
            uint64_t DpcContext;
            DWORD DelayMs;
        };
        auto Info = new DpcFireInfo{ Timer, Dpc, DpcRoutine, DpcContext, DueMs };

        CreateThread(nullptr, 0, [](LPVOID Param) -> DWORD {
            __try {
            auto FI = (DpcFireInfo*)Param;
            Sleep(FI->DelayMs);

            auto HostTimer = UcPtr(FI->Timer);
            HostTimer->Header.SignalState = 1;

            auto hEvent = HandleManager::GetHandle((uintptr_t)FI->Timer);
            if (hEvent)
                SetEvent((HANDLE)hEvent);

            Logger::Log("{CYN}\tDPC timer fired: timer=%llx routine=%llx ctx=%llx — spawning UC thread{RESET}\n",
                FI->Timer, FI->DpcRoutine, FI->DpcContext);

            if (FI->DpcRoutine) {
                UnicornThread::CreateEx(
                    FI->DpcRoutine,
                    (uint64_t)FI->Dpc,
                    FI->DpcContext,
                    0, 0,
                    nullptr);
            }

            delete FI;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Logger::Log("{RED}DPC fire thread exception 0x%08x{RESET}\n", GetExceptionCode());
            }
            return 0;
        }, Info, 0, nullptr);
    }

    return true;
}

void h_KeInitializeTimer(_KTIMER* Timer) {
    auto HostTimer = UcPtr(Timer);
    uint64_t TleUcAddr = (uint64_t)Timer + offsetof(_KTIMER, TimerListEntry);
    HostTimer->TimerListEntry.Flink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->TimerListEntry.Blink = (PLIST_ENTRY)TleUcAddr;
    HostTimer->Header.SignalState = 0;
}

BOOLEAN h_KeCancelTimer(_KTIMER* Timer) { return true; }

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
    memset(HostDpc, 0, sizeof(_KDPC));
}

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
    auto HostTimer = UcPtr(Timer);
    memcpy(&HostTimer->DueTime, &DueTime, sizeof(DueTime));
    {
        std::lock_guard<std::mutex> Guard(TimerManager::TimerLock);
        if (TimerManager::timer_manager.contains(Timer))
            TimerManager::timer_manager[Timer] = GetTickCount64();
        else
            TimerManager::timer_manager.insert(std::pair(Timer, GetTickCount64()));
    }
    HostTimer->Header.SignalState = 0;
    return TRUE;
}
