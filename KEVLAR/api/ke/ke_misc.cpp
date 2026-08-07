#include "include/common.h"
#include "ke_misc.h"

_ETHREAD* h_KeGetCurrentThread() { return UnicornThread::GetCurrentEthread(); }

uint64_t h_KeAreAllApcsDisabled() {
    return 0;
}

uint64_t h_KeAreApcsDisabled() { return 0; }

ULONG h_KeQueryTimeIncrement() {
    return 156250; //machine with no hv
}

NTSTATUS h_KeDelayExecutionThread(char WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval) {
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

uint64_t h_KeGetCurrentIrql() { return 0; }
uint64_t h_KeRaiseIrqlToDpcLevel() { return 0; }
void h_KfRaiseIrql(UCHAR NewIrql) {}
void h_KeLowerIrql(UCHAR NewIrql) {}
void h_KfLowerIrql(UCHAR NewIrql) {}

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
    Logger::Log("{CYN}\tKeInsertQueueApc: apc=%p{RESET}\n", Apc);
    return TRUE;
}

BOOLEAN h_KeTestAlertThread(uint8_t AlertMode) {
    Logger::Log("{CYN}\tKeTestAlertThread: mode=%u{RESET}\n", AlertMode);
    return FALSE;
}

BOOLEAN h_KeAlertThread(void* Thread, uint8_t AlertMode) {
    Logger::Log("{MAG}\tKeAlertThread: thread=%p mode=%u{RESET}\n", Thread, AlertMode);
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
