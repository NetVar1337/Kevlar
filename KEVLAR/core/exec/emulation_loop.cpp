#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include "core/exec/instruction_emulator.h"
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"

struct EmulationLoopResult {
    bool Ok;
    bool HostCrash;
    DWORD ExceptionCode;
    uint64_t CrashRip, CrashRsp, CrashRax, CrashRcx, CrashRdx, CrashR8, CrashR9, CrashRbx;
};

static EmulationLoopResult RunEmulationLoop(uc_engine* Uc, uint64_t EntryPoint) {
    EmulationLoopResult R = {};
    R.Ok = true;
    uint64_t CurrentEmuRip = EntryPoint;
    UnicornEmu::SseFault.Active = false;

    __try {
    for (;;) {
        uc_err Err = uc_emu_start(Uc, CurrentEmuRip, SENTINEL_RET_ADDR, 0, 0);

        if (UnicornEmu::SseFault.Active) {
            UnicornEmu::SseFault.Active = false;
            Logger::Log("{MAG}SSE fault: dispatching exception for RIP=0x%llx addr=0x%llx{RESET}\n",
                UnicornEmu::SseFault.FaultRip, UnicornEmu::SseFault.MemAddr);

            uc_reg_write(Uc, UC_X86_REG_RIP, &UnicornEmu::SseFault.FaultRip);
            if (SehDispatch::DispatchException(Uc, UnicornEmu::SseFault.ExceptionCode, UnicornEmu::SseFault.MemAddr)) {
                uc_reg_read(Uc, UC_X86_REG_RIP, &CurrentEmuRip);
                continue;
            }

            Logger::Log("{RED}SSE alignment fault unhandled at 0x%llx - stopping{RESET}\n", UnicornEmu::SseFault.FaultRip);
            R.Ok = false;
            return R;
        }

        if (Err != UC_ERR_OK) {
            uint64_t CurrentRip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &CurrentRip);

            if (Err == UC_ERR_INSN_INVALID) {
                if (InsnEmulator::TryEmulate(Uc, CurrentRip)) {
                    uc_reg_read(Uc, UC_X86_REG_RIP, &CurrentEmuRip);
                    continue;
                }
            }

            Logger::Log("{RED}Emulation error at RIP={WHT}0x%llx{RED}: %s{RESET}\n", CurrentRip, uc_strerror(Err));
            R.Ok = false;
            return R;
        }

        break;
    }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        R.HostCrash = true;
        R.ExceptionCode = GetExceptionCode();
        uc_reg_read(Uc, UC_X86_REG_RIP, &R.CrashRip);
        uc_reg_read(Uc, UC_X86_REG_RSP, &R.CrashRsp);
        uc_reg_read(Uc, UC_X86_REG_RAX, &R.CrashRax);
        uc_reg_read(Uc, UC_X86_REG_RCX, &R.CrashRcx);
        uc_reg_read(Uc, UC_X86_REG_RDX, &R.CrashRdx);
        uc_reg_read(Uc, UC_X86_REG_R8, &R.CrashR8);
        uc_reg_read(Uc, UC_X86_REG_R9, &R.CrashR9);
        uc_reg_read(Uc, UC_X86_REG_RBX, &R.CrashRbx);
        R.Ok = false;
    }

    return R;
}

bool UnicornEmu::StartEmulation(uc_engine* Uc, uint64_t EntryPoint) {
    uint64_t StackTop = STACK_BASE_UC + STACK_SIZE_UC - 0x100;
    uc_reg_write(Uc, UC_X86_REG_RSP, &StackTop);

    uc_mem_map(Uc, SENTINEL_RET_ADDR & ~0xFFFULL, 0x1000, UC_PROT_ALL);

    uint64_t RetAddr = SENTINEL_RET_ADDR;
    StackTop -= 8;
    uc_mem_write(Uc, StackTop, &RetAddr, 8);
    uc_reg_write(Uc, UC_X86_REG_RSP, &StackTop);

    uint64_t Rcx = DRIVER_OBJ_BASE_UC;
    uint64_t Rdx = REGISTRY_PATH_BASE_UC;
    uc_reg_write(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_write(Uc, UC_X86_REG_RDX, &Rdx);

    uint64_t Rflags = 0x10286;
    uc_reg_write(Uc, UC_X86_REG_RFLAGS, &Rflags);

    Logger::Log("{CYN}Starting emulation at 0x%llx (until 0x%llx){RESET}\n", EntryPoint, SENTINEL_RET_ADDR);

    static volatile bool HeartbeatRunning = true;
    static uc_engine* HeartbeatUc = Uc;
    HANDLE HeartbeatThread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        LARGE_INTEGER Freq, Start;
        QueryPerformanceFrequency(&Freq);
        QueryPerformanceCounter(&Start);
        while (HeartbeatRunning) {
            Sleep(5000);
            if (!HeartbeatRunning) break;
            UnicornEmu::UpdateKusdTimeValues();
            uint64_t Rip = 0;
            uc_reg_read(HeartbeatUc, UC_X86_REG_RIP, &Rip);
            LARGE_INTEGER Now;
            QueryPerformanceCounter(&Now);
            double Elapsed = (double)(Now.QuadPart - Start.QuadPart) / (double)Freq.QuadPart;
            uint64_t DriverRva = (Rip >= DRIVER_BASE_UC) ? (Rip - DRIVER_BASE_UC) : 0;
            Logger::Log("{GRY}[HEARTBEAT %.1fs] RIP=0x%llx (drv+0x%llx){RESET}\n", Elapsed, Rip, DriverRva);

            if (IntelCpuSpoofEnabled) {
                static bool PtDetected = false;
                uint32_t PtMsrs[] = { 0x570, 0x571, 0x572, 0x560, 0x561, 0x580, 0x581, 0x582, 0x583 };
                const char* PtNames[] = { "RTIT_CTL", "RTIT_STATUS", "RTIT_CR3_MATCH", "RTIT_OUTPUT_BASE", "RTIT_OUTPUT_MASK", "RTIT_ADDR0_A", "RTIT_ADDR0_B", "RTIT_ADDR1_A", "RTIT_ADDR1_B" };
                for (int I = 0; I < 9; I++) {
                    uc_x86_msr MsrVal = {};
                    MsrVal.rid = PtMsrs[I];
                    MsrVal.value = 0;
                    uc_reg_read(HeartbeatUc, UC_X86_REG_MSR, &MsrVal);
                    if (MsrVal.value != 0) {
                        Logger::Log("{RED}[INTEL PT] MSR 0x%x (%s) = 0x%llx *** PT ACTIVE ***{RESET}\n",
                            PtMsrs[I], PtNames[I], MsrVal.value);
                        PtDetected = true;
                    }
                }
                if (!PtDetected && ((int)Elapsed % 30 == 0)) {
                    Logger::Log("{GRY}[INTEL PT] No PT MSR activity at %.0fs{RESET}\n", Elapsed);
                }
            }
        }
        return 0;
    }, nullptr, 0, nullptr);

    auto LoopResult = RunEmulationLoop(Uc, EntryPoint);
    if (LoopResult.HostCrash) {
        Logger::Log("{RED}HOST CRASH in primary emulation thread! Exception code: 0x%08x{RESET}\n", LoopResult.ExceptionCode);
        Logger::Log("{RED}  UC RIP=0x%llx (drv+0x%llx) RSP=0x%llx{RESET}\n", LoopResult.CrashRip,
            LoopResult.CrashRip >= DRIVER_BASE_UC ? LoopResult.CrashRip - DRIVER_BASE_UC : 0, LoopResult.CrashRsp);
        Logger::Log("{RED}  RAX=0x%llx RCX=0x%llx RDX=0x%llx RBX=0x%llx{RESET}\n",
            LoopResult.CrashRax, LoopResult.CrashRcx, LoopResult.CrashRdx, LoopResult.CrashRbx);
        Logger::Log("{RED}  R8=0x%llx R9=0x%llx{RESET}\n", LoopResult.CrashR8, LoopResult.CrashR9);
        return false;
    }
    if (!LoopResult.Ok)
        return false;

    HeartbeatRunning = false;
    WaitForSingleObject(HeartbeatThread, 1000);
    CloseHandle(HeartbeatThread);

    uint64_t Rax = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);

    if (VgkErrorOverrideEnabled && (Rax == 0xC0000022 || Rax == 0xC000007A)) {
        Logger::Log("{GRN}[FINAL OVERRIDE] DriverEntry returned 0x%08x -> forcing STATUS_SUCCESS (0){RESET}\n", (uint32_t)Rax);
        Rax = 0;
        uc_reg_write(Uc, UC_X86_REG_RAX, &Rax);
    }

    if (Rax != 0) {
        uint64_t FinalRip = 0, FinalRsp = 0, FinalRcx = 0, FinalRdx = 0, FinalR8 = 0, FinalRbp = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &FinalRip);
        uc_reg_read(Uc, UC_X86_REG_RSP, &FinalRsp);
        uc_reg_read(Uc, UC_X86_REG_RCX, &FinalRcx);
        uc_reg_read(Uc, UC_X86_REG_RDX, &FinalRdx);
        uc_reg_read(Uc, UC_X86_REG_R8, &FinalR8);
        uc_reg_read(Uc, UC_X86_REG_RBP, &FinalRbp);
        Logger::Log("{RED}[FAIL DIAG] RAX=0x%llx RIP=0x%llx RSP=0x%llx RBP=0x%llx{RESET}\n",
            Rax, FinalRip, FinalRsp, FinalRbp);

        Logger::Log("{RED}[FAIL DIAG] Scanning stack for driver return addresses:{RESET}\n");
        uint64_t StackBase = STACK_BASE_UC;
        uint64_t StackTop2 = STACK_BASE_UC + STACK_SIZE_UC;
        int Found = 0;
        for (uint64_t Scan = FinalRsp; Scan < StackTop2 && Found < 32; Scan += 8) {
            uint64_t StackVal = 0;
            uc_mem_read(Uc, Scan, &StackVal, 8);
            if (StackVal == 0) continue;
            bool InDriver = (StackVal >= DRIVER_BASE_UC && StackVal < DRIVER_BASE_UC + 0x10000000ULL);
            bool InSentinel = (StackVal >= SENTINEL_BASE_UC && StackVal < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE);
            bool InNtos = false;
            for (auto& Mod : MappedSysMods) {
                if (StackVal >= Mod.UcBase && StackVal < Mod.UcBase + Mod.Size) {
                    InNtos = true;
                    break;
                }
            }
            if (InDriver || InSentinel || InNtos) {
                uint64_t Rva = StackVal - DRIVER_BASE_UC;
                std::string Disasm = "";
                if (InDriver) Disasm = DisassembleAt(Uc, StackVal);
                Logger::Log("{GRY}  [SP+0x%llx] 0x%llx %s%s{RESET}\n",
                    Scan - FinalRsp, StackVal,
                    InDriver ? "drv+" : (InSentinel ? "SENTINEL" : "SYSMOD"),
                    InDriver ? std::to_string(Rva).c_str() : "");
                if (InDriver && !Disasm.empty())
                    Logger::Log("{GRY}    -> %s{RESET}\n", Disasm.c_str());
                Found++;
            }
        }
    }

    Logger::Log("{CYN}DriverEntry returned: {WHT}0x%llx{RESET}\n", Rax);
    if (Rax == 0) Logger::Log("{GRN}  STATUS_SUCCESS{RESET}\n");
    else if (Rax == 0xC0000001) Logger::Log("{RED}  STATUS_UNSUCCESSFUL{RESET}\n");
    else if (Rax == 0xC0000002) Logger::Log("{RED}  STATUS_NOT_IMPLEMENTED{RESET}\n");
    else if (Rax == 0xC0000005) Logger::Log("{RED}  STATUS_ACCESS_VIOLATION{RESET}\n");
    else if (Rax == 0xC000000D) Logger::Log("{RED}  STATUS_INVALID_PARAMETER{RESET}\n");
    else if (Rax == 0xC0000022) Logger::Log("{RED}  STATUS_ACCESS_DENIED{RESET}\n");
    else if (Rax == 0xC0000034) Logger::Log("{RED}  STATUS_OBJECT_NAME_NOT_FOUND{RESET}\n");
    else if (Rax == 0xC000007A) Logger::Log("{RED}  STATUS_PROCEDURE_NOT_FOUND{RESET}\n");
    else if (Rax == 0xC00000BB) Logger::Log("{RED}  STATUS_NOT_SUPPORTED{RESET}\n");
    else if (Rax == 0xC0000420) Logger::Log("{RED}  STATUS_ASSERTION_FAILURE{RESET}\n");
    else if (Rax == 0xC0000423) Logger::Log("{RED}  STATUS_INCOMPATIBLE_DRIVER_BLOCKED{RESET}\n");
    else if (Rax == 0xC0000424) Logger::Log("{RED}  STATUS_HIVE_UNLOADED{RESET}\n");
    else Logger::Log("{RED}  NTSTATUS 0x%08x{RESET}\n", (uint32_t)Rax);

    Logger::Log("{CYN}Total interrupts: %d{RESET}\n", TotalInterruptCount);
    if (TotalInterruptCount > 0) {
        for (int I = 0; I < 256; I++) {
            if (InterruptCounts[I] > 0) {
                Logger::Log("{GRY}  INT 0x%02x: %d times{RESET}\n", I, InterruptCounts[I]);
            }
        }
    }
    Logger::Log("{CYN}[NTOS READS FINAL] total=%d hdr=%d rdata=%d pdata=%d idata=%d edata=%d gfids=%d code=%d data=%d nomod=%d{RESET}\n",
        NtoskrnlReadCount, NtoskrnlHdrReadCount, NtoskrnlRdataReadCount, NtoskrnlPdataReadCount,
        NtoskrnlIdataReadCount, NtoskrnlEdataReadCount, NtoskrnlGfidsReadCount,
        NtoskrnlCodeReadCount, NtoskrnlDataReadCount, NtoskrnlNoModCount);
    Logger::Log("{CYN}Export resolutions: %d ordinal reads, %d func addr reads{RESET}\n", OrdinalReadCount, FuncAddrReadCount);
    Logger::Log("{CYN}Last 64 ordinal+funcaddr reads:{RESET}\n");
    {
        int Total = OrdRingIdx;
        int DumpStart = (Total > 64) ? Total - 64 : 0;
        for (int I = DumpStart; I < Total; I++) {
            auto& O = OrdRingBuf[I % 64];
            Logger::Log("{GRY}  [%d] ordinal=%d funcRVA=0x%x RIP=0x%llx{RESET}\n",
                I, O.Ordinal, O.FuncRva, O.Rip);
        }
    }

    Logger::Log("{CYN}[DRV SELF-READS FINAL] total=%d hdr=%d iat=%d{RESET}\n",
        DrvSelfReadCount, DrvSelfHdrReadCount, DrvSelfIatReadCount);

    Logger::Log("{CYN}Last 64 header reads:{RESET}\n");
    {
        int Total = HdrRingIdx;
        int DumpStart = (Total > 64) ? Total - 64 : 0;
        for (int I = DumpStart; I < Total; I++) {
            auto& H = HdrRingBuf[I % 64];
            Logger::Log("{GRY}  [%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
                I, H.Rva, H.Size, H.Val, H.Rip);
        }
    }

    Logger::Log("{CYN}Last %d SysMod calls:{RESET}\n", SYSMOD_RING_SIZE);
    {
        int Total = SysModRingIdx;
        int DumpStart = (Total > SYSMOD_RING_SIZE) ? Total - SYSMOD_RING_SIZE : 0;
        for (int I = DumpStart; I < Total; I++) {
            auto& S = SysModRing[I % SYSMOD_RING_SIZE];
            uint64_t CallerRva = (S.CallerRip >= DRIVER_BASE_UC && S.CallerRip < DRIVER_BASE_UC + 0x10000000ULL)
                ? S.CallerRip - DRIVER_BASE_UC : 0;
            if (CallerRva)
                Logger::Log("{GRY}  [%d] %s -> 0x%llx  caller=drv+0x%llx{RESET}\n", I, S.FuncName, S.RetVal, CallerRva);
            else
                Logger::Log("{GRY}  [%d] %s -> 0x%llx  caller=0x%llx{RESET}\n", I, S.FuncName, S.RetVal, S.CallerRip);
        }
    }

    Logger::Log("{CYN}Last 32 edata reads:{RESET}\n");
    int Start = (EdataRingIdx > 32) ? EdataRingIdx - 32 : 0;
    for (int I = Start; I < EdataRingIdx; I++) {
        auto& E = EdataRingBuf[I % 32];
        Logger::Log("{GRY}  [%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
            I, E.Rva, E.Size, E.Val, E.Rip);
    }

    Logger::Log("{CYN}RIP ring: %llu total instructions, dumping last %d:{RESET}\n", RipRingTotal, RIP_RING_SIZE);
    if (Rax != 0 && RipRingIdx > 0) {
        int DumpCount = (RipRingIdx > RIP_RING_SIZE) ? RIP_RING_SIZE : RipRingIdx;
        int DumpStart = RipRingIdx - DumpCount;
        uint64_t PrevRax = 0;
        int RaxChangeCount = 0;
        for (int I = DumpStart; I < RipRingIdx; I++) {
            auto& R = RipRingBuf[I % RIP_RING_SIZE];
            if (R.Rax != PrevRax || I == DumpStart) {
                uint64_t Rva = R.Rip - DRIVER_BASE_UC;
                std::string Disasm = DisassembleAt(Uc, R.Rip);
                Logger::Log("{MAG}  [%d] RIP=drv+0x%llx RAX=0x%llx %s{RESET}\n",
                    I, Rva, R.Rax, Disasm.c_str());
                PrevRax = R.Rax;
                RaxChangeCount++;
                if (RaxChangeCount > 200) {
                    Logger::Log("{MAG}  ... (truncated, too many RAX changes){RESET}\n");
                    break;
                }
            }
        }
        Logger::Log("{CYN}Last 32 RIP entries:{RESET}\n");
        int Last32Start = RipRingIdx - 32;
        if (Last32Start < 0) Last32Start = 0;
        for (int I = Last32Start; I < RipRingIdx; I++) {
            auto& R = RipRingBuf[I % RIP_RING_SIZE];
            uint64_t Rva = R.Rip - DRIVER_BASE_UC;
            std::string Disasm = DisassembleAt(Uc, R.Rip);
            Logger::Log("{GRY}  [%d] drv+0x%llx RAX=0x%llx %s{RESET}\n", I, Rva, R.Rax, Disasm.c_str());
        }
    }

    return true;
}
