#include "include/common.h"
#include "ke_misc.h"

_ETHREAD* h_KeGetCurrentThread() { return UnicornThread::GetCurrentEthread(); }

// ApcDisable lives at ETHREAD+0x1E4 (the offset h_KeLeaveCriticalRegionThread already uses).
static constexpr size_t ETHREAD_APC_DISABLE_OFFSET = 0x1E4;
static SHORT* ApcDisableField(_ETHREAD* Thread) {
    return (SHORT*)((uint8_t*)Thread + ETHREAD_APC_DISABLE_OFFSET);
}

uint64_t h_KeAreAllApcsDisabled() {
    auto Thread = UnicornThread::GetCurrentEthread();
    return Thread ? *ApcDisableField(Thread) > 1 : 0;
}

uint64_t h_KeAreApcsDisabled() {
    auto Thread = UnicornThread::GetCurrentEthread();
    return Thread ? *ApcDisableField(Thread) > 0 : 0;
}

ULONG h_KeQueryTimeIncrement() {
    return 156250; //machine with no hv
}

NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval) {
    DeliverPendingApcs();

    auto HostInterval = UcPtr(Interval);
    DWORD SleepMs = (DWORD)(HostInterval->QuadPart * -1 / 10000);
    LARGE_INTEGER PreSleep;
    QueryPerformanceCounter(&PreSleep);
    Sleep(SleepMs);
    LARGE_INTEGER PostSleep;
    QueryPerformanceCounter(&PostSleep);
    InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, -(PostSleep.QuadPart - PreSleep.QuadPart));
    return STATUS_SUCCESS;
}

ULONG_PTR h_KeIpiGenericCall(PVOID BroadcastFunction, ULONG_PTR Context) {
    uint64_t FuncAddr = (uint64_t)BroadcastFunction;
    Logger::Log("{CYN}\tKeIpiGenericCall: func=%llx ctx=%llx -> executing callback{RESET}\n", FuncAddr, Context);

    auto ThrCtx = UnicornThread::GetCurrent();
    uc_engine* Uc = ThrCtx ? ThrCtx->Engine : UnicornEmu::PrimaryEngine;
    if (!Uc || !FuncAddr) {
        Logger::Log("{RED}\tKeIpiGenericCall: no engine or null callback, returning 0{RESET}\n");
        return 0;
    }

    uint64_t SaveRcx, SaveRdx, SaveR8, SaveR9, SaveR10, SaveR11;
    uint64_t SaveRsp, SaveRax, SaveRbx, SaveRdi, SaveRsi, SaveRbp;
    uint64_t SaveR12, SaveR13, SaveR14, SaveR15;
    uc_reg_read(Uc, UC_X86_REG_RCX, &SaveRcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &SaveRdx);
    uc_reg_read(Uc, UC_X86_REG_R8, &SaveR8);
    uc_reg_read(Uc, UC_X86_REG_R9, &SaveR9);
    uc_reg_read(Uc, UC_X86_REG_R10, &SaveR10);
    uc_reg_read(Uc, UC_X86_REG_R11, &SaveR11);
    uc_reg_read(Uc, UC_X86_REG_R12, &SaveR12);
    uc_reg_read(Uc, UC_X86_REG_R13, &SaveR13);
    uc_reg_read(Uc, UC_X86_REG_R14, &SaveR14);
    uc_reg_read(Uc, UC_X86_REG_R15, &SaveR15);
    uc_reg_read(Uc, UC_X86_REG_RSP, &SaveRsp);
    uc_reg_read(Uc, UC_X86_REG_RAX, &SaveRax);
    uc_reg_read(Uc, UC_X86_REG_RBX, &SaveRbx);
    uc_reg_read(Uc, UC_X86_REG_RDI, &SaveRdi);
    uc_reg_read(Uc, UC_X86_REG_RSI, &SaveRsi);
    uc_reg_read(Uc, UC_X86_REG_RBP, &SaveRbp);

    uint64_t Rcx = Context;
    uc_reg_write(Uc, UC_X86_REG_RCX, &Rcx);

    uint64_t Rsp = SaveRsp - 0x28;
    uint64_t Zero = 0;
    uc_mem_write(Uc, Rsp + 0x08, &Zero, 8);
    uc_mem_write(Uc, Rsp + 0x10, &Zero, 8);
    uc_mem_write(Uc, Rsp + 0x18, &Zero, 8);
    uc_mem_write(Uc, Rsp + 0x20, &Zero, 8);
    uint64_t RetAddr = SENTINEL_RET_ADDR;
    uc_mem_write(Uc, Rsp, &RetAddr, 8);
    uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);

    uc_err EmuErr = uc_emu_start(Uc, FuncAddr, SENTINEL_RET_ADDR, 0, 0);

    uint64_t Result = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Result);

    uint64_t FinalRip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &FinalRip);
    Logger::Log("{CYN}\tKeIpiGenericCall: emu_start returned %d (%s), RAX=0x%llx, RIP=0x%llx{RESET}\n",
        EmuErr, uc_strerror(EmuErr), Result, FinalRip);

    uc_reg_write(Uc, UC_X86_REG_RCX, &SaveRcx);
    uc_reg_write(Uc, UC_X86_REG_RDX, &SaveRdx);
    uc_reg_write(Uc, UC_X86_REG_R8, &SaveR8);
    uc_reg_write(Uc, UC_X86_REG_R9, &SaveR9);
    uc_reg_write(Uc, UC_X86_REG_R10, &SaveR10);
    uc_reg_write(Uc, UC_X86_REG_R11, &SaveR11);
    uc_reg_write(Uc, UC_X86_REG_R12, &SaveR12);
    uc_reg_write(Uc, UC_X86_REG_R13, &SaveR13);
    uc_reg_write(Uc, UC_X86_REG_R14, &SaveR14);
    uc_reg_write(Uc, UC_X86_REG_R15, &SaveR15);
    uc_reg_write(Uc, UC_X86_REG_RSP, &SaveRsp);
    uc_reg_write(Uc, UC_X86_REG_RAX, &SaveRax);
    uc_reg_write(Uc, UC_X86_REG_RBX, &SaveRbx);
    uc_reg_write(Uc, UC_X86_REG_RDI, &SaveRdi);
    uc_reg_write(Uc, UC_X86_REG_RSI, &SaveRsi);
    uc_reg_write(Uc, UC_X86_REG_RBP, &SaveRbp);

    Logger::Log("{CYN}\tKeIpiGenericCall: callback returned %llx{RESET}\n", Result);
    return (ULONG_PTR)Result;
}

// --- IRQL model ---
// Guest-visible IRQL lives in the KPCR at offset 0x50 (_KPCR.Irql). Each thread has
// its own KPCR (per-thread buffer for workers, KpcrBlock for the primary); the guest
// reads it directly via gs:[0x50], so we must write the backing buffer, not FakeKPCR.
// (IRQL names differ from the wdm.h macros PASSIVE_LEVEL/DISPATCH_LEVEL.)
static constexpr size_t KPCR_IRQL_OFFSET = 0x50;
static constexpr UCHAR KEV_IRQL_PASSIVE = 0;
static constexpr UCHAR KEV_IRQL_DISPATCH = 2;

static UCHAR KeGetCurrentIrqlRaw() {
    auto Kpcr = UnicornThread::GetCurrentKpcr();
    return Kpcr ? *(UCHAR*)(Kpcr + KPCR_IRQL_OFFSET) : KEV_IRQL_PASSIVE;
}

static void KeSetCurrentIrqlRaw(UCHAR NewIrql) {
    auto Kpcr = UnicornThread::GetCurrentKpcr();
    if (Kpcr) *(UCHAR*)(Kpcr + KPCR_IRQL_OFFSET) = NewIrql;
}

uint64_t h_KeGetCurrentIrql() { return KeGetCurrentIrqlRaw(); }

uint64_t h_KeRaiseIrqlToDpcLevel() { return h_KfRaiseIrql(KEV_IRQL_DISPATCH); }

UCHAR h_KfRaiseIrql(UCHAR NewIrql) {
    UCHAR Old = KeGetCurrentIrqlRaw();
    KeSetCurrentIrqlRaw(NewIrql);
    return Old;
}

UCHAR h_KeRaiseIrql(UCHAR NewIrql) { return h_KfRaiseIrql(NewIrql); }

void h_KeLowerIrql(UCHAR NewIrql) { KeSetCurrentIrqlRaw(NewIrql); }
void h_KfLowerIrql(UCHAR NewIrql) { KeSetCurrentIrqlRaw(NewIrql); }

// --- APC model ---
// Host-side per-thread queue. KeGetCurrentThread returns &FakeKernelThread for the
// primary thread and Ctx->EthreadHostPtr for workers, so APCs key on those pointers.
// ponytail: guest ApcListHead stays initialized but unused; add guest-list walking
// when a driver is seen doing it. Kernel APCs are delivered by spawning a delivery
// thread (CreateEx5) sharing the primary memory map -- same pattern as timer DPCs.
static std::mutex g_ApcQueueLock;          // ponytail: single global lock; per-thread locks if throughput matters
static std::vector<_KAPC*> g_PrimaryApcs;  // queue for the primary (DriverEntry) thread

// Resolve the target thread's APC queue. Requires no lock held on the queue itself.
static std::vector<_KAPC*>* ApcQueueForTarget(_KTHREAD* Thread) {
    if (!Thread || (uint64_t)Thread == (uint64_t)&FakeKernelThread)
        return &g_PrimaryApcs;
    std::lock_guard<std::mutex> Lock(UnicornThread::ThreadLock);
    for (auto& [Id, Ctx] : UnicornThread::ThreadMap) {
        if (Ctx && (uint64_t)Ctx->EthreadHostPtr == (uint64_t)Thread)
            return &Ctx->PendingApcs;
    }
    return nullptr;
}

// Run a queued kernel APC on a delivery thread. KernelRoutine gets the real
// _PKERNEL_ROUTINE argument layout: RCX=Apc, RDX=&NormalRoutine, R8=&NormalContext,
// R9=&SystemArgument1, [RSP+0x28]=&SystemArgument2.
// ponytail: NormalRoutine runs in the delivery thread, not the target's context;
// most kernel-APC users drive work off KernelRoutine only.
static void DeliverOneApc(_KAPC* ApcUc, _KAPC* HostApc) {
    uint64_t KernelRoutine = (uint64_t)HostApc->Reserved[0];
    uint64_t NormalRoutine = (uint64_t)HostApc->Reserved[2];
    if (!KernelRoutine) return;

    if (NormalRoutine)
        Logger::Log("{GRY}\tAPC: NormalRoutine=0x%llx runs on delivery thread (no target context){RESET}\n", NormalRoutine);

    uint64_t ApcAddr = (uint64_t)ApcUc;
    UnicornThread::CreateEx5(
        KernelRoutine,
        ApcAddr,               // RCX = Apc
        ApcAddr + 0x30,        // RDX = &Apc->NormalRoutine
        ApcAddr + 0x38,        // R8  = &Apc->NormalContext
        ApcAddr + 0x40,        // R9  = &Apc->SystemArgument1
        ApcAddr + 0x48,        // [RSP+0x28] = &Apc->SystemArgument2
        nullptr);
}

int DeliverPendingApcs() {
    auto CurThread = UnicornThread::GetCurrentEthread();
    if (CurThread && *ApcDisableField(CurThread) > 0)   // critical region
        return 0;
    if (KeGetCurrentIrqlRaw() >= KEV_IRQL_DISPATCH)
        return 0;

    std::vector<_KAPC*> ToDeliver;
    {
        std::lock_guard<std::mutex> Lock(g_ApcQueueLock);
        auto* Queue = ((uint64_t)CurThread == (uint64_t)&FakeKernelThread)
            ? &g_PrimaryApcs
            : &UnicornThread::GetCurrent()->PendingApcs;
        ToDeliver.swap(*Queue);
    }

    for (auto* ApcUc : ToDeliver) {
        auto HostApc = UcPtr(ApcUc);
        if (!HostApc) continue;
        HostApc->Inserted = 0;
        DeliverOneApc(ApcUc, HostApc);
    }
    return (int)ToDeliver.size();
}

// --- Critical / guarded regions ---
// Critical regions disable kernel APCs by bumping the thread's ApcDisable counter.
void h_KeEnterCriticalRegion() {
    auto Thread = UnicornThread::GetCurrentEthread();
    if (Thread) ++(*ApcDisableField(Thread));
}

void h_KeLeaveCriticalRegion() {
    auto Thread = UnicornThread::GetCurrentEthread();
    if (Thread) {
        SHORT* V = ApcDisableField(Thread);
        if (*V > 0) --(*V);
    }
}

void h_KeEnterGuardedRegion() { h_KeEnterCriticalRegion(); }
void h_KeLeaveGuardedRegion() { h_KeLeaveCriticalRegion(); }

LARGE_INTEGER h_KeQueryPerformanceCounter(PLARGE_INTEGER PerformanceFrequency) {
    LARGE_INTEGER Result;

    LARGE_INTEGER CurrentQpc;
    QueryPerformanceCounter(&CurrentQpc);
    int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
    int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
    if (EmulatedElapsed < 0) EmulatedElapsed = 0;
    Result.QuadPart = UnicornEmu::EmulationStartQpc + EmulatedElapsed;

    if (PerformanceFrequency) {
        auto HostFreq = UcPtr(PerformanceFrequency);
        QueryPerformanceFrequency(HostFreq);
    }
    return Result;
}

void h_KeStackAttachProcess(void* Process, void* ApcState) {
    Logger::Log("{CYN}\tKeStackAttachProcess: process=%p{RESET}\n", Process);
}

void h_KeUnstackDetachProcess(void* ApcState) {
    Logger::Log("{CYN}\tKeUnstackDetachProcess{RESET}\n");
}

void h_KeInitializeApc(
    _KAPC* Apc,
    _KTHREAD* Thread,
    uint8_t Environment,
    void* KernelRoutine,
    void* RundownRoutine,
    void* NormalRoutine,
    uint8_t ApcMode,
    void* NormalContext)
{
    Logger::Log("{CYN}\tKeInitializeApc: apc=%p thread=%p env=%u mode=%u{RESET}\n",
        Apc, Thread, Environment, ApcMode);
    auto HostApc = UcPtr(Apc);
    if (!HostApc) return;
    memset(HostApc, 0, sizeof(_KAPC));
    HostApc->Type = 0x12;
    HostApc->Size = sizeof(_KAPC);
    HostApc->Thread = Thread;
    HostApc->ApcStateIndex = (CHAR)Environment;
    HostApc->Reserved[0] = KernelRoutine;
    HostApc->Reserved[1] = RundownRoutine;
    HostApc->Reserved[2] = NormalRoutine;
    HostApc->ApcMode = (CHAR)ApcMode;
    HostApc->NormalContext = NormalContext;
}

BOOLEAN h_KeInsertQueueApc(
    _KAPC* Apc,
    void* SystemArgument1,
    void* SystemArgument2,
    uint8_t Increment)
{
    auto HostApc = UcPtr(Apc);
    if (!HostApc) return FALSE;
    if (HostApc->Inserted) return FALSE;

    HostApc->SystemArgument1 = SystemArgument1;
    HostApc->SystemArgument2 = SystemArgument2;

    std::vector<_KAPC*>* Queue;
    {
        std::lock_guard<std::mutex> Lock(g_ApcQueueLock);
        Queue = ApcQueueForTarget(HostApc->Thread);
        if (!Queue) {
            Logger::Log("{YEL}\tKeInsertQueueApc: target thread %p not found, dropping{RESET}\n", HostApc->Thread);
            return FALSE;
        }
        Queue->push_back(Apc);
        HostApc->Inserted = 1;
    }

    Logger::Log("{CYN}\tKeInsertQueueApc: apc=%p routine=%p{RESET}\n", Apc, HostApc->Reserved[0]);

    // Deliver immediately when targeting the current thread at PASSIVE outside a
    // critical region (otherwise it waits for the next wait/alert delivery point).
    if ((uint64_t)HostApc->Thread == (uint64_t)UnicornThread::GetCurrentEthread())
        DeliverPendingApcs();

    return TRUE;
}

BOOLEAN h_KeRemoveQueueApc(_KAPC* Apc) {
    auto HostApc = UcPtr(Apc);
    if (!HostApc) return FALSE;

    std::lock_guard<std::mutex> Lock(g_ApcQueueLock);
    auto* Queue = ApcQueueForTarget(HostApc->Thread);
    if (!Queue) return FALSE;
    for (auto It = Queue->begin(); It != Queue->end(); ++It) {
        if (*It == Apc) {
            Queue->erase(It);
            HostApc->Inserted = 0;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN h_KeTestAlertThread(uint8_t AlertMode) {
    Logger::Log("{CYN}\tKeTestAlertThread: mode=%u{RESET}\n", AlertMode);
    return DeliverPendingApcs() > 0;
}

BOOLEAN h_KeAlertThread(void* Thread, uint8_t AlertMode) {
    Logger::Log("{MAG}\tKeAlertThread: thread=%p mode=%u{RESET}\n", Thread, AlertMode);
    // Only the current thread's alert can be acted on synchronously.
    if ((uint64_t)Thread == (uint64_t)UnicornThread::GetCurrentEthread())
        return DeliverPendingApcs() > 0;
    return FALSE;
}

uint64_t h_KeQueryActiveProcessorCountEx(uint16_t GroupNumber) {
    SYSTEM_INFO Si;
    GetNativeSystemInfo(&Si);
    uint64_t Count = Si.dwNumberOfProcessors;
    if (Count < 4) Count = 4;
    Logger::Log("{CYN}\tKeQueryActiveProcessorCountEx: group=%u returning %llu{RESET}\n", GroupNumber, Count);
    return Count;
}

void h_KeQuerySystemTimePrecise(PLARGE_INTEGER CurrentTime) {
    auto HostTime = UcPtr(CurrentTime);
    if (!HostTime) return;

    LARGE_INTEGER CurrentQpc;
    QueryPerformanceCounter(&CurrentQpc);
    int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
    int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
    if (EmulatedElapsed < 0) EmulatedElapsed = 0;

    int64_t ElapsedIn100Ns = 0;
    if (UnicornEmu::QpcFrequency > 0)
        ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;

    HostTime->QuadPart = UnicornEmu::EmulationStartSystemTime + ElapsedIn100Ns;
}
