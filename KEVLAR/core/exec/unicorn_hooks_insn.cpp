#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include "core/diagnostics/diag_center.h"
#include <intrin.h>

void UnicornEmu::Hooks::OnCpuid(uc_engine* Uc, void* UserData) {
    uint64_t Rax = 0, Rcx = 0, Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    int CpuInfo[4] = { 0 };
    __cpuidex(CpuInfo, (int)Rax, (int)Rcx);
    uint64_t DriverRva = Rip - DRIVER_BASE_UC;

    if (DiagnosticHooksEnabled) {
        const char* LeafName = "unknown";
        switch ((uint32_t)Rax) {
        case 0x00: LeafName = "MaxLeaf+VendorID"; break;
        case 0x01: LeafName = "VersionInfo+Features"; break;
        case 0x02: LeafName = "CacheDescriptors"; break;
        case 0x03: LeafName = "SerialNumber"; break;
        case 0x04: LeafName = "CacheParams"; break;
        case 0x05: LeafName = "MONITOR/MWAIT"; break;
        case 0x06: LeafName = "ThermalPower"; break;
        case 0x07: LeafName = "ExtendedFeatures"; break;
        case 0x09: LeafName = "DirectCacheAccess"; break;
        case 0x0A: LeafName = "PerfMonitoring"; break;
        case 0x0B: LeafName = "ExtTopology"; break;
        case 0x0D: LeafName = "XSAVE"; break;
        case 0x0F: LeafName = "QoSMonitoring"; break;
        case 0x10: LeafName = "QoSEnforcement"; break;
        case 0x12: LeafName = "SGX"; break;
        case 0x14: LeafName = "ProcessorTrace"; break;
        case 0x15: LeafName = "TSC/CoreCrystal"; break;
        case 0x16: LeafName = "ProcessorFreq"; break;
        case 0x17: LeafName = "SoCVendor"; break;
        case 0x18: LeafName = "TLBDeterministic"; break;
        case 0x1A: LeafName = "HybridInfo"; break;
        case 0x40000000: LeafName = "HV_MaxLeaf+VendorID"; break;
        case 0x40000001: LeafName = "HV_InterfaceID"; break;
        case 0x40000002: LeafName = "HV_OSIdentity"; break;
        case 0x40000003: LeafName = "HV_Features"; break;
        case 0x40000004: LeafName = "HV_ImplLimits"; break;
        case 0x40000005: LeafName = "HV_ImplHW"; break;
        case 0x40000006: LeafName = "HV_NestedFeatures"; break;
        case 0x80000000: LeafName = "ExtMaxLeaf"; break;
        case 0x80000001: LeafName = "ExtFeatures"; break;
        case 0x80000002: LeafName = "BrandString[0]"; break;
        case 0x80000003: LeafName = "BrandString[1]"; break;
        case 0x80000004: LeafName = "BrandString[2]"; break;
        case 0x80000005: LeafName = "L1Cache+TLB"; break;
        case 0x80000006: LeafName = "L2Cache"; break;
        case 0x80000007: LeafName = "APM+InvariantTSC"; break;
        case 0x80000008: LeafName = "AddrSizes+Features"; break;
        case 0x8FFFFFFF: LeafName = "AMD_EasterEgg"; break;
        }
        Logger::Log("{RED}[CPUID] leaf=0x%x (%s) subleaf=0x%x @ RIP=0x%llx (drv+0x%llx){RESET}\n",
            (uint32_t)Rax, LeafName, (uint32_t)Rcx, Rip, DriverRva);
        Logger::Log("{RED}  [PRE-SPOOF]  EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x{RESET}\n",
            CpuInfo[0], CpuInfo[1], CpuInfo[2], CpuInfo[3]);
    }

    if (Rax == 0) {
        if (IntelCpuSpoofEnabled) {
            CpuInfo[0] = 0x20;
            CpuInfo[1] = 0x756E6547;
            CpuInfo[2] = 0x6C65746E;
            CpuInfo[3] = 0x49656E69;
        }
        if (DiagnosticHooksEnabled) {
            char VendorStr[13] = {};
            memcpy(VendorStr + 0, &CpuInfo[1], 4);
            memcpy(VendorStr + 4, &CpuInfo[3], 4);
            memcpy(VendorStr + 8, &CpuInfo[2], 4);
            VendorStr[12] = 0;
            Logger::Log("{RED}  [CPUID 0] VendorID: %s  MaxLeaf: %d{RESET}\n", VendorStr, CpuInfo[0]);
        }
    }

    if (Rax == 1) {
        CpuInfo[2] &= ~(1 << 31);
        CpuInfo[2] |= (1 << 31);
        if (IntelCpuSpoofEnabled) {
            CpuInfo[0] = 0x000B0671;
            CpuInfo[1] = (CpuInfo[1] & 0x0000FFFF) | 0x10100000;
            CpuInfo[2] |= (1 << 0) | (1 << 9) | (1 << 19) | (1 << 20) | (1 << 23) | (1 << 25) | (1 << 28);
            CpuInfo[3] |= (1 << 0) | (1 << 25) | (1 << 26);
        }
    }

    if (Rax == 7 && Rcx == 0) {
        CpuInfo[1] &= ~(1 << 29);
        if (IntelCpuSpoofEnabled) {
            CpuInfo[1] |= (1 << 25);
        }
    }

    if ((uint32_t)Rax >= 0x40000000 && (uint32_t)Rax <= 0x4FFFFFFF) {
        if (Rax == 0x40000000) {
            CpuInfo[0] = 0x40000006;
            CpuInfo[1] = 0x756E6547;
            CpuInfo[2] = 0x6C65746E;
            CpuInfo[3] = 0x49656E69;
        }
        else if (Rax == 0x40000001) {
            CpuInfo[0] = 0x31237648;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else if (Rax == 0x40000002) {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else if (Rax == 0x40000003) {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else if (Rax == 0x40000004) {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else if (Rax == 0x40000005) {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else if (Rax == 0x40000006) {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
        else {
            CpuInfo[0] = 0;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
    }

    if (IntelCpuSpoofEnabled) {
        static const char IntelBrand[] = "13th Gen Intel(R) Core(TM) i9-13900K";
        if (Rax == 0x80000002) { memset(CpuInfo, 0, 16); memcpy(CpuInfo, IntelBrand, 16); }
        if (Rax == 0x80000003) { memset(CpuInfo, 0, 16); memcpy(CpuInfo, IntelBrand + 16, 16); }
        if (Rax == 0x80000004) { memset(CpuInfo, 0, 16); size_t Rem = strlen(IntelBrand) - 32; if (Rem > 16) Rem = 16; memcpy(CpuInfo, IntelBrand + 32, Rem); }
        if (Rax == 0x80000000) { CpuInfo[0] = 0x80000008; }
        if (Rax == 0x15) {
            CpuInfo[0] = 2;
            CpuInfo[1] = 168;
            CpuInfo[2] = 38400000;
            CpuInfo[3] = 0;
        }
        if (Rax == 0x16) {
            CpuInfo[0] = 3000;
            CpuInfo[1] = 5800;
            CpuInfo[2] = 100;
            CpuInfo[3] = 0;
        }
        if (Rax == 0x14 && Rcx == 0) {
            CpuInfo[0] = 1;
            CpuInfo[1] = 0x0000000F;
            CpuInfo[2] = 0x00000006;
            CpuInfo[3] = 0;
        }
        if (Rax == 0x14 && Rcx == 1) {
            CpuInfo[0] = 0x02490002;
            CpuInfo[1] = 0;
            CpuInfo[2] = 0;
            CpuInfo[3] = 0;
        }
    }

    if (DiagnosticHooksEnabled) {
        if (Rax == 0x80000002 || Rax == 0x80000003 || Rax == 0x80000004) {
            char BrandChunk[17] = {};
            memcpy(BrandChunk, CpuInfo, 16);
            BrandChunk[16] = 0;
            Logger::Log("{RED}  [CPUID Brand] chunk: \"%s\"{RESET}\n", BrandChunk);
        }

        if (Rax == 0x15) {
            Logger::Log("{RED}  [CPUID 0x15] TSC/Crystal: denom=%u numer=%u crystal_hz=%u{RESET}\n",
                CpuInfo[0], CpuInfo[1], CpuInfo[2]);
        }

        if (Rax == 0x16) {
            Logger::Log("{RED}  [CPUID 0x16] Freq: base=%uMHz max=%uMHz bus=%uMHz{RESET}\n",
                CpuInfo[0] & 0xFFFF, CpuInfo[1] & 0xFFFF, CpuInfo[2] & 0xFFFF);
        }

        if (Rax == 0x80000007) {
            bool InvariantTsc = (CpuInfo[3] >> 8) & 1;
            Logger::Log("{RED}  [CPUID 80000007] InvariantTSC bit (EDX.8): %d{RESET}\n", InvariantTsc);
        }

        Logger::Log("{RED}  [POST-SPOOF] EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x{RESET}\n",
            CpuInfo[0], CpuInfo[1], CpuInfo[2], CpuInfo[3]);
    }

    uint64_t OutEax = (uint32_t)CpuInfo[0];
    uint64_t OutEbx = (uint32_t)CpuInfo[1];
    uint64_t OutEcx = (uint32_t)CpuInfo[2];
    uint64_t OutEdx = (uint32_t)CpuInfo[3];

    uc_reg_write(Uc, UC_X86_REG_RAX, &OutEax);
    uc_reg_write(Uc, UC_X86_REG_RBX, &OutEbx);
    uc_reg_write(Uc, UC_X86_REG_RCX, &OutEcx);
    uc_reg_write(Uc, UC_X86_REG_RDX, &OutEdx);

    if (DIAG_IS_ENABLED()) {
        CpuidEvent Ev = {};
        Ev.Base.Sequence = DIAG_SEQ;
        Ev.Base.Rip = Rip;
        DiagCenter::Instance().ResolveVaToModule(Rip, Ev.Base.ModuleBase, Ev.Base.ModuleRva, Ev.ModuleName, sizeof(Ev.ModuleName));
        {
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.ModuleName, sizeof(Ev.ModuleName));
            Ev.Base.ModuleBase = TmpBase;
            Ev.Base.ModuleRva = TmpRva;
        }
        Ev.Leaf = (uint32_t)Rax;
        Ev.SubLeaf = (uint32_t)Rcx;
        int OrigCpuInfo[4] = {};
        __cpuidex(OrigCpuInfo, (int)Rax, (int)Rcx);
        Ev.PreEax = (uint32_t)OrigCpuInfo[0];
        Ev.PreEbx = (uint32_t)OrigCpuInfo[1];
        Ev.PreEcx = (uint32_t)OrigCpuInfo[2];
        Ev.PreEdx = (uint32_t)OrigCpuInfo[3];
        Ev.PostEax = (uint32_t)CpuInfo[0];
        Ev.PostEbx = (uint32_t)CpuInfo[1];
        Ev.PostEcx = (uint32_t)CpuInfo[2];
        Ev.PostEdx = (uint32_t)CpuInfo[3];
        Ev.ChangedBits[0] = (Ev.PreEax != Ev.PostEax) ? 1 : 0;
        Ev.ChangedBits[1] = (Ev.PreEbx != Ev.PostEbx) ? 1 : 0;
        Ev.ChangedBits[2] = (Ev.PreEcx != Ev.PostEcx) ? 1 : 0;
        Ev.ChangedBits[3] = (Ev.PreEdx != Ev.PostEdx) ? 1 : 0;
        Ev.HypervisorPresent = ((uint32_t)Rax == 1) ? ((CpuInfo[2] >> 31) & 1) : 0;
        Ev.SelfModify = 0;
        char VendorStr[13] = {};
        memcpy(VendorStr + 0, &CpuInfo[1], 4);
        memcpy(VendorStr + 4, &CpuInfo[3], 4);
        memcpy(VendorStr + 8, &CpuInfo[2], 4);
        VendorStr[12] = 0;
        memcpy(Ev.VendorStr, VendorStr, 13);
        const char* LeafName = "Unknown";
        if ((uint32_t)Rax == 0) LeafName = "MaxStdLeaf+Vendor";
        else if ((uint32_t)Rax == 1) LeafName = "FeatureBits";
        else if ((uint32_t)Rax == 7) LeafName = "ExtendedFeatures";
        else if ((uint32_t)Rax == 0x0B) LeafName = "Topology";
        else if ((uint32_t)Rax == 0x0D) LeafName = "XSave";
        else if ((uint32_t)Rax == 0x15) LeafName = "TSCCoreFreq";
        else if ((uint32_t)Rax >= 0x40000000 && (uint32_t)Rax <= 0x40000006) LeafName = "HV_Leaf";
        else if ((uint32_t)Rax == 0x80000000) LeafName = "MaxExtLeaf";
        else if ((uint32_t)Rax == 0x80000001) LeafName = "ExtFeatures";
        strncpy(Ev.LeafName, LeafName, sizeof(Ev.LeafName) - 1);
        DIAG_CPUID(Ev);
    }

    TlsCpuidBetweenRdtsc = true;
}

void UnicornEmu::Hooks::OnRdtsc(uc_engine* Uc, void* UserData) {
    LARGE_INTEGER CurrentQpc;
    QueryPerformanceCounter(&CurrentQpc);

    static uint64_t RdtscCallCount = 0, RdtscDetectionCount = 0;
    if (++RdtscDetectionCount <= 10) {
        uint64_t DrvRva = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &DrvRva);
        if (DrvRva >= DRIVER_BASE_UC) DrvRva -= DRIVER_BASE_UC;
    }
    RdtscCallCount++;
    if (RdtscCallCount <= 5 || RdtscCallCount % 100000 == 0) {
        uint64_t Rip2 = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip2);
        uint64_t DrvRva = (Rip2 >= DRIVER_BASE_UC) ? Rip2 - DRIVER_BASE_UC : Rip2;
        Logger::Log("{MAG}[RDTSC #%llu] drv+0x%llx{RESET}\n", RdtscCallCount, DrvRva);
    }

    uint64_t Rip = 0;
    if (DiagnosticHooksEnabled)
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
    int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
    if (EmulatedElapsed < 0) EmulatedElapsed = 0;

    uint64_t BaseTsc = UnicornEmu::VirtualTsc + (uint64_t)((double)EmulatedElapsed * UnicornEmu::TscPerQpcTick);

    uint64_t EmulatedTsc;

    if (TlsCpuidBetweenRdtsc && TlsLastRdtscValue > 0) {
        uint64_t CpuidCost = 50 + (TscFastRand() % 201);
        EmulatedTsc = TlsLastRdtscValue + CpuidCost;
        TlsCpuidBetweenRdtsc = false;
        TlsShortIntervalCount = 0;
    } else if (TlsLastRdtscQpc > 0) {
        int64_t DeltaQpc = CurrentQpc.QuadPart - TlsLastRdtscQpc;
        double DeltaSeconds = (double)DeltaQpc / (double)UnicornEmu::QpcFrequency;

        if (DeltaSeconds < ShortIntervalThreshold) {
            TlsShortIntervalCount++;
            if (TlsShortIntervalCount > BusyWaitThreshold) {
                uint64_t JumpTicks;
                if (TlsShortIntervalCount > 5000) {
                    JumpTicks = 300000 + (TscFastRand() % 100000);
                } else if (TlsShortIntervalCount > 1000) {
                    JumpTicks = 100000 + (TscFastRand() % 50000);
                } else if (TlsShortIntervalCount > 200) {
                    JumpTicks = 30000 + (TscFastRand() % 10000);
                } else {
                    JumpTicks = 5000 + (TscFastRand() % 3000);
                }
                EmulatedTsc = TlsLastRdtscValue + JumpTicks;
            } else {
                double RawDelta = (double)DeltaQpc * UnicornEmu::TscPerQpcTick;
                double ScaledDelta = RawDelta / EmulationSpeedRatio;
                double Variance = 1.0 + (double)(TscFastRand() % 100) / 500.0;
                ScaledDelta *= Variance;
                if (ScaledDelta < 20.0) ScaledDelta = 20.0;
                if (ScaledDelta > 5000.0) ScaledDelta = 5000.0;
                EmulatedTsc = TlsLastRdtscValue + (uint64_t)ScaledDelta;
            }
        } else {
            TlsShortIntervalCount = 0;
            EmulatedTsc = BaseTsc;
        }
    } else {
        EmulatedTsc = BaseTsc;
    }

    int64_t Jitter = TscGaussianJitter(15.0);
    int64_t JitteredTsc = (int64_t)EmulatedTsc + Jitter;
    if (JitteredTsc > (int64_t)TlsLastRdtscValue) {
        EmulatedTsc = (uint64_t)JitteredTsc;
    }

    if (EmulatedTsc <= TlsLastRdtscValue) {
        EmulatedTsc = TlsLastRdtscValue + 1 + (TscFastRand() % 5);
    }

    TlsLastRdtscValue = EmulatedTsc;
    TlsLastRdtscQpc = CurrentQpc.QuadPart;

    if (DiagnosticHooksEnabled) {
        static int RdtscLogCount = 0;
        RdtscLogCount++;
        uint64_t DriverRva = Rip - DRIVER_BASE_UC;
        if (RdtscLogCount <= 30 || (RdtscLogCount % 1000 == 0)) {
            Logger::Log("{YEL}[RDTSC #%d] @ RIP=0x%llx (drv+0x%llx) TSC=0x%llx elapsed=%lld shortStreak=%d{RESET}\n",
                RdtscLogCount, Rip, DriverRva, EmulatedTsc, EmulatedElapsed, TlsShortIntervalCount);
        }
    }

    uint64_t Eax = EmulatedTsc & 0xFFFFFFFF;
    uint64_t Edx = (EmulatedTsc >> 32) & 0xFFFFFFFF;

    uc_reg_write(Uc, UC_X86_REG_RAX, &Eax);
    uc_reg_write(Uc, UC_X86_REG_RDX, &Edx);

    static uint64_t LastKusdUpdateTsc = 0;
    if (EmulatedTsc - LastKusdUpdateTsc > 10000) {
        UpdateKusdTimeValues();
        LastKusdUpdateTsc = EmulatedTsc;
    }
}

static int TraceInstrCount = 0;
static const int TraceInstrMax = 100000;
static int TraceLogCount = 0;
static const int TraceLogMax = 2000;

void UnicornEmu::Hooks::OnDriverTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    TraceInstrCount++;

    if (TraceLogCount >= TraceLogMax)
        return;

    bool IsCall = false;
    bool IsRet = false;
    uint8_t Buf[15] = { 0 };
    uc_mem_read(Uc, Addr, Buf, 15);

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus Status = ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Buf, 15, &Instr, Operands);
    if (ZYAN_SUCCESS(Status)) {
        IsCall = (Instr.mnemonic == ZYDIS_MNEMONIC_CALL);
        IsRet = (Instr.mnemonic == ZYDIS_MNEMONIC_RET);
    }

    if (TraceInstrCount <= 20) {
        std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);
        uint64_t Rax = 0, Rcx = 0, Rdx = 0, Rsp = 0;
        uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
        uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
        uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
        uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
        Logger::Log("{GRY}[TRACE %d] 0x%llx: %s  | RAX=%llx RCX=%llx RDX=%llx RSP=%llx{RESET}\n",
            TraceInstrCount, Addr, Disasm.c_str(), Rax, Rcx, Rdx, Rsp);
        TraceLogCount++;
        return;
    }

    if (IsCall) {
        std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);
        uint64_t Rcx = 0, Rdx = 0, R8 = 0, R9 = 0;
        uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
        uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
        uc_reg_read(Uc, UC_X86_REG_R8, &R8);
        uc_reg_read(Uc, UC_X86_REG_R9, &R9);
        Logger::Log("{GRY}[TRACE CALL #%d] 0x%llx: %s | RCX=%llx RDX=%llx R8=%llx R9=%llx{RESET}\n",
            TraceInstrCount, Addr, Disasm.c_str(), Rcx, Rdx, R8, R9);
        TraceLogCount++;
        return;
    }

    if (IsRet && TraceInstrCount > 100) {
        uint64_t Rsp = 0, Rax = 0;
        uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
        uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);

        uint64_t RetTarget = 0;
        uc_mem_read(Uc, Rsp, &RetTarget, 8);

        if (RetTarget < DRIVER_BASE_UC || RetTarget >= DRIVER_BASE_UC + 0x10000000ULL) {
            Logger::Log("{GRY}[TRACE RET #%d] 0x%llx: ret -> 0x%llx | RAX=%llx{RESET}\n",
                TraceInstrCount, Addr, RetTarget, Rax);
            TraceLogCount++;
        }
    }

    if (TraceInstrCount % 10000 == 0) {
        uint64_t Rax = 0;
        uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
        std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);
        Logger::Log("{GRY}[TRACE TICK %d] 0x%llx: %s | RAX=%llx{RESET}\n",
            TraceInstrCount, Addr, Disasm.c_str(), Rax);
        TraceLogCount++;
    }
}

void UnicornEmu::InstallDriverTrace(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize) {
    TraceInstrCount = 0;
    uc_hook Hh;
    uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnDriverTrace, nullptr,
        DriverBase, DriverBase + DriverSize - 1);
    Logger::Log("{CYN}Driver trace installed: 0x%llx - 0x%llx (max %d instructions){RESET}\n",
        DriverBase, DriverBase + DriverSize - 1, TraceInstrMax);
}

static bool RaxErrorCaught = false;
static uint64_t LastRaxErrorRip = 0;
static uint64_t LastRaxErrorInsn = 0;
static int RaxErrorStreak = 0;
void OnRipRingTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    uint64_t Rax = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    auto& E = RipRingBuf[RipRingIdx % RIP_RING_SIZE];
    E.Rip = Addr;
    E.Rax = Rax;

    if (Rax == 0xC0000022) {
        if (RaxErrorStreak == 0)
            LastRaxErrorRip = Addr;
        RaxErrorStreak++;
        if (RaxErrorStreak == 5 && !RaxErrorCaught) {
            RaxErrorCaught = true;
            uint64_t DriverRva = LastRaxErrorRip - DRIVER_BASE_UC;
            Logger::Log("{RED}[ERROR PERSIST] RAX=0xC0000022 persisted at RIP=0x%llx (drv+0x%llx) insn#%llu{RESET}\n",
                LastRaxErrorRip, DriverRva, RipRingTotal - 4);
            uint32_t Start = (RipRingIdx > 80) ? RipRingIdx - 80 : 0;
            for (uint32_t I = Start; I <= RipRingIdx; I++) {
                auto& Prev = RipRingBuf[I % RIP_RING_SIZE];
                uint64_t PrevRva = Prev.Rip - DRIVER_BASE_UC;
                Logger::Log("  [%llu] drv+0x%llx RAX=0x%llx\n", (uint64_t)I, PrevRva, Prev.Rax);
            }
            uint64_t Rcx = 0, Rdx = 0, R8 = 0, R9 = 0, Rsp = 0, Rbx = 0, Rdi = 0, Rsi = 0;
            uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
            uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
            uc_reg_read(Uc, UC_X86_REG_R8, &R8);
            uc_reg_read(Uc, UC_X86_REG_R9, &R9);
            uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
            uc_reg_read(Uc, UC_X86_REG_RBX, &Rbx);
            uc_reg_read(Uc, UC_X86_REG_RDI, &Rdi);
            uc_reg_read(Uc, UC_X86_REG_RSI, &Rsi);
            Logger::Log("{RED}  Regs: RCX=0x%llx RDX=0x%llx R8=0x%llx R9=0x%llx RSP=0x%llx RBX=0x%llx RDI=0x%llx RSI=0x%llx{RESET}\n",
                Rcx, Rdx, R8, R9, Rsp, Rbx, Rdi, Rsi);
        }
    } else {
        RaxErrorStreak = 0;
    }

    RipRingIdx++;
    RipRingTotal++;
}

void UnicornEmu::Hooks::OnDivWatch(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    uint8_t Code[16] = {};
    uc_mem_read(Uc, Addr, Code, (Size < 16) ? Size : 16);

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands))) {
        if (Instr.mnemonic == ZYDIS_MNEMONIC_DIV || Instr.mnemonic == ZYDIS_MNEMONIC_IDIV) {
            uint64_t Rax = 0, Rdx = 0, Rcx = 0, Rbx = 0, Rsi = 0, Rdi = 0, R8 = 0;
            uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
            uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
            uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
            uc_reg_read(Uc, UC_X86_REG_RBX, &Rbx);
            uc_reg_read(Uc, UC_X86_REG_RSI, &Rsi);
            uc_reg_read(Uc, UC_X86_REG_RDI, &Rdi);
            uc_reg_read(Uc, UC_X86_REG_R8, &R8);

            uint64_t DriverRva = Addr - DRIVER_BASE_UC;
            const char* MnStr = (Instr.mnemonic == ZYDIS_MNEMONIC_DIV) ? "DIV" : "IDIV";

            uint64_t Divisor = 0;
            const char* DivisorReg = "???";
            if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                ZydisRegister Reg = Operands[0].reg.value;
                switch (Reg) {
                case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_RCX: Divisor = Rcx; DivisorReg = "RCX"; break;
                case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_RBX: Divisor = Rbx; DivisorReg = "RBX"; break;
                case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI: Divisor = Rsi; DivisorReg = "RSI"; break;
                case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI: Divisor = Rdi; DivisorReg = "RDI"; break;
                case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_RDX: Divisor = Rdx; DivisorReg = "RDX"; break;
                case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_RAX: Divisor = Rax; DivisorReg = "RAX"; break;
                case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8: Divisor = R8; DivisorReg = "R8"; break;
                default: DivisorReg = "other"; break;
                }
            } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                DivisorReg = "[mem]";
                void* HostPtr = UnicornMem::UcToHost(Operands[0].mem.disp.value);
                if (HostPtr && Instr.operand_width == 32) {
                    Divisor = *(uint32_t*)HostPtr;
                }
            }

            std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);

            Logger::Log("{RED}[DIV WATCH] %s at RIP=0x%llx (drv+0x%llx): %s{RESET}\n",
                MnStr, Addr, DriverRva, Disasm.c_str());
            Logger::Log("{RED}  RAX=0x%llx RDX=0x%llx divisor(%s)=0x%llx%s{RESET}\n",
                Rax, Rdx, DivisorReg, Divisor, (Divisor == 0) ? " *** DIVIDE BY ZERO ***" : "");
        }
    }
}

void UnicornEmu::InstallDivWatch(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize) {
    uc_hook Hh;
    uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnDivWatch, nullptr,
        DriverBase, DriverBase + DriverSize - 1);
    Logger::Log("{CYN}DIV watch installed: 0x%llx - 0x%llx{RESET}\n",
        DriverBase, DriverBase + DriverSize - 1);
}

static int ZydisRegToUc(ZydisRegister Reg) {
    switch (Reg) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: return UC_X86_REG_RAX;
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: return UC_X86_REG_RCX;
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: return UC_X86_REG_RDX;
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: return UC_X86_REG_RBX;
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: return UC_X86_REG_RSP;
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: return UC_X86_REG_RBP;
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: return UC_X86_REG_RSI;
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: return UC_X86_REG_RDI;
    case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  return UC_X86_REG_R8;
    case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  return UC_X86_REG_R9;
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: return UC_X86_REG_R10;
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: return UC_X86_REG_R11;
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: return UC_X86_REG_R12;
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: return UC_X86_REG_R13;
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: return UC_X86_REG_R14;
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: return UC_X86_REG_R15;
    default: return 0;
    }
}

static uint64_t ComputeEffectiveAddress(uc_engine* Uc, ZydisDecodedOperand* Op, ZydisDecodedInstruction* Instr, uint64_t InstrAddr) {
    if (Op->type != ZYDIS_OPERAND_TYPE_MEMORY) return 0;

    uint64_t BaseVal = 0;
    uint64_t IndexVal = 0;

    if (Op->mem.base != ZYDIS_REGISTER_NONE) {
        if (Op->mem.base == ZYDIS_REGISTER_RIP) {
            BaseVal = InstrAddr + Instr->length;
        } else {
            int UcReg = ZydisRegToUc(Op->mem.base);
            if (UcReg) uc_reg_read(Uc, UcReg, &BaseVal);
        }
    }

    if (Op->mem.index != ZYDIS_REGISTER_NONE) {
        int UcReg = ZydisRegToUc(Op->mem.index);
        if (UcReg) uc_reg_read(Uc, UcReg, &IndexVal);
    }

    int64_t Disp = Op->mem.disp.has_displacement ? Op->mem.disp.value : 0;

    return BaseVal + IndexVal * Op->mem.scale + (uint64_t)Disp;
}

static std::unordered_map<uint32_t, uint64_t> MsrStore;
static std::mutex MsrStoreLock;

void UnicornEmu::InitMsrStore() {
    std::lock_guard<std::mutex> Guard(MsrStoreLock);
    MsrStore = {
        { 0x3A,        0x1 },
        { 0x1D9,       0 },
        { 0x122,       0 },
        { 0x1DB,       0 },
        { 0x1DC,       0 },
        { 0x1DD,       0 },
        { 0x1DE,       0 },
        { 0xC0000082,  SYSMOD_BASE_UC + 0x411a00 },
        { 0xC0000080,  0xD01 },
        { 0xC0000081,  0x0023001000000000ULL },
        { 0xC0000083,  0 },
        { 0xC0000084,  0x4700 },
        { 0xC0000103,  0 },
        { 0x1B,        0xFEE00D00 },
        { 0x1A0,       0x850089 },
        { 0x48,        0 },
        { 0x10A,       0x1 },
        { 0x480,       0 },
        { 0x481,       0 },
        { 0x482,       0 },
        { 0x483,       0 },
        { 0x484,       0 },
        { 0x485,       0 },
        { 0x486,       0 },
        { 0x487,       0 },
        { 0x488,       0 },
        { 0x489,       0 },
        { 0x48A,       0 },
        { 0x48B,       0 },
        { 0x48C,       0 },
        { 0x48D,       0 },
        { 0xC0010114,  0 },
        { 0x570,       0 },
        { 0x571,       0 },
        { 0x572,       0 },
        { 0x560,       0 },
        { 0x561,       0 },
        { 0x580,       0 },
        { 0x581,       0 },
        { 0x582,       0 },
        { 0x583,       0 },
        { 0xCE,        0x00050A2200000000ULL },
        { 0xE7,        0 },
        { 0xE8,        0 },
        { 0x38D,       0 },
        { 0x38E,       0 },
        { 0x38F,       0 },
        { 0x309,       0 },
        { 0x30A,       0 },
        { 0x30B,       0 },
    };
}

static const char* GetMsrName(uint32_t Id) {
    switch (Id) {
    case 0x10: return "IA32_TIME_STAMP_COUNTER";
    case 0x1B: return "IA32_APIC_BASE";
    case 0x3A: return "IA32_FEATURE_CONTROL";
    case 0x48: return "IA32_SPEC_CTRL";
    case 0xCE: return "IA32_PLATFORM_INFO";
    case 0xE7: return "IA32_MPERF";
    case 0xE8: return "IA32_APERF";
    case 0x122: return "IA32_SGX_SVN_STATUS";
    case 0x174: return "IA32_SYSENTER_CS";
    case 0x175: return "IA32_SYSENTER_ESP";
    case 0x176: return "IA32_SYSENTER_EIP";
    case 0x1A0: return "IA32_MISC_ENABLE";
    case 0x1D9: return "IA32_DEBUGCTL";
    case 0x1DB: return "IA32_LASTBRANCH_FROMIP";
    case 0x1DC: return "IA32_LASTBRANCH_TOIP";
    case 0x1DD: return "IA32_LASTINT_FROMIP";
    case 0x1DE: return "IA32_LASTINT_TOIP";
    case 0x186: return "IA32_PERFEVTSEL0";
    case 0x187: return "IA32_PERFEVTSEL1";
    case 0x188: return "IA32_PERFEVTSEL2";
    case 0x189: return "IA32_PERFEVTSEL3";
    case 0xC1: return "IA32_PERFEVTCTR0";
    case 0xC2: return "IA32_PERFEVTCTR1";
    case 0x277: return "IA32_PAT";
    case 0x480: return "IA32_VMX_BASIC";
    case 0x481: return "IA32_VMX_PINBASED_CTLS";
    case 0x482: return "IA32_VMX_PROCBASED_CTLS";
    case 0x483: return "IA32_VMX_EXIT_CTLS";
    case 0x484: return "IA32_VMX_ENTRY_CTLS";
    case 0x485: return "IA32_VMX_MISC";
    case 0x486: return "IA32_VMX_CR0_FIXED0";
    case 0x487: return "IA32_VMX_CR0_FIXED1";
    case 0x488: return "IA32_VMX_CR4_FIXED0";
    case 0x489: return "IA32_VMX_CR4_FIXED1";
    case 0x48A: return "IA32_VMX_VMCS_ENUM";
    case 0x48B: return "IA32_VMX_PROCBASED_CTLS2";
    case 0x48C: return "IA32_VMX_EPT_VPID_CAP";
    case 0x48D: return "IA32_VMX_TRUE_PINBASED";
    case 0x10A: return "IA32_ARCH_CAPABILITIES";
    case 0x570: return "IA32_RTIT_CTL";
    case 0x571: return "IA32_RTIT_STATUS";
    case 0x572: return "IA32_RTIT_CR3_MATCH";
    case 0x560: return "IA32_RTIT_OUTPUT_BASE";
    case 0x561: return "IA32_RTIT_OUTPUT_MASK_PTRS";
    case 0x580: return "IA32_RTIT_ADDR0_A";
    case 0x581: return "IA32_RTIT_ADDR0_B";
    case 0x582: return "IA32_RTIT_ADDR1_A";
    case 0x583: return "IA32_RTIT_ADDR1_B";
    case 0x58F: return "IA32_RTIT_ADDR3_B";
    case 0x38D: return "IA32_FIXED_CTR_CTRL";
    case 0x38E: return "IA32_FIXED_CTR1";
    case 0x38F: return "IA32_PERF_GLOBAL_CTRL";
    case 0x309: return "IA32_FIXED_CTR0";
    case 0x30A: return "IA32_FIXED_CTR1";
    case 0x30B: return "IA32_FIXED_CTR2";
    case 0xC0000080: return "IA32_EFER";
    case 0xC0000081: return "IA32_STAR";
    case 0xC0000082: return "IA32_LSTAR";
    case 0xC0000083: return "IA32_CSTAR";
    case 0xC0000084: return "IA32_FMASK";
    case 0xC0000100: return "IA32_FS_BASE";
    case 0xC0000101: return "IA32_GS_BASE";
    case 0xC0000102: return "IA32_KERNEL_GS_BASE";
    case 0xC0000103: return "IA32_TSC_AUX";
    case 0xC0010114: return "VM_CR";
    default: return nullptr;
    }
}

static uint64_t SafeDriverRva(uint64_t Rip) {
	if (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL)
		return Rip - DRIVER_BASE_UC;
	return 0;
}

static void DetectionRecordRdmsr(uint32_t MsrId, uint64_t Value, uint64_t Rip) {
}
static void DetectionRecordWrmsr(uint32_t MsrId, uint64_t Value, uint64_t Rip) {
}

static bool DecodeMsrInstructionAt(uc_engine* Uc, uint64_t Addr, bool& IsRead, uint32_t& InstructionLen) {
    uint8_t Bytes[16] = {};
    if (uc_mem_read(Uc, Addr, Bytes, sizeof(Bytes)) != UC_ERR_OK)
        return false;

    size_t PrefixLen = 0;
    while (PrefixLen < sizeof(Bytes)) {
        uint8_t B = Bytes[PrefixLen];
        bool IsLegacyPrefix =
            B == 0xF0 || B == 0xF2 || B == 0xF3 ||
            B == 0x66 || B == 0x67 ||
            B == 0x2E || B == 0x36 || B == 0x3E || B == 0x26 || B == 0x64 || B == 0x65;
        bool IsRexPrefix = (B >= 0x40 && B <= 0x4F);
        if (!IsLegacyPrefix && !IsRexPrefix)
            break;
        PrefixLen++;
    }

    if (PrefixLen + 1 >= sizeof(Bytes))
        return false;

    if (Bytes[PrefixLen] != 0x0F)
        return false;

    uint8_t Op2 = Bytes[PrefixLen + 1];
    if (Op2 == 0x32) {
        IsRead = true;
        InstructionLen = (uint32_t)(PrefixLen + 2);
        return true;
    }
    if (Op2 == 0x30) {
        IsRead = false;
        InstructionLen = (uint32_t)(PrefixLen + 2);
        return true;
    }
    return false;
}

void UnicornEmu::Hooks::OnRdmsr(uc_engine* Uc, void* UserData) {
    uint64_t Rcx = 0, Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    uint32_t MsrId = (uint32_t)Rcx;
    uint64_t Value = 0;
    bool FoundInStore = false;

    {
        std::lock_guard<std::mutex> Guard(MsrStoreLock);
        auto It = MsrStore.find(MsrId);
        if (It != MsrStore.end()) {
            Value = It->second;
            FoundInStore = true;
        }
    }

    if (!FoundInStore) {
        uc_x86_msr MsrVal;
        MsrVal.rid = MsrId;
        uc_err Err = uc_reg_read(Uc, UC_X86_REG_MSR, &MsrVal);
        if (Err == UC_ERR_OK) {
            Value = MsrVal.value;
        }
    }

    if (MsrId == 0x10) {
        LARGE_INTEGER CurrentQpc;
        QueryPerformanceCounter(&CurrentQpc);
        int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
        int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
        if (EmulatedElapsed < 0) EmulatedElapsed = 0;
        Value = UnicornEmu::VirtualTsc + (uint64_t)((double)EmulatedElapsed * UnicornEmu::TscPerQpcTick);
    }

    if (MsrId == 0x3A) {
        Value = 0x1;
    }

    if (MsrId >= 0x480 && MsrId <= 0x48D) {
        Value = 0;
    }

    if (MsrId == 0xC0010114) {
        Value = 0;
    }

    if (MsrId == 0x570 || MsrId == 0x571 || MsrId == 0x572 ||
        MsrId == 0x560 || MsrId == 0x561 ||
        (MsrId >= 0x580 && MsrId <= 0x58F)) {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{RED}[RDMSR] {WHT}0x%x{RED} (%s) = 0x%llx @ RIP=0x%llx (drv+0x%llx) *** INTEL PT ***{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip, Rip - DRIVER_BASE_UC);
    } else if (MsrId >= 0x300 && MsrId <= 0x400) {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{YEL}[RDMSR] 0x%x (%s) = 0x%llx @ drv+0x%llx *** PERF COUNTERS ***{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip - DRIVER_BASE_UC);
    } else {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{GRY}[RDMSR] 0x%x (%s) = 0x%llx @ drv+0x%llx{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip - DRIVER_BASE_UC);
    }

    uint64_t Eax = Value & 0xFFFFFFFF;
    uint64_t Edx = (Value >> 32) & 0xFFFFFFFF;
    uc_reg_write(Uc, UC_X86_REG_RAX, &Eax);
    uc_reg_write(Uc, UC_X86_REG_RDX, &Edx);

    DetectionRecordRdmsr(MsrId, Value, Rip);
}

void UnicornEmu::Hooks::OnWrmsr(uc_engine* Uc, void* UserData) {
    uint64_t Rcx = 0, Rax = 0, Rdx = 0, Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    uint32_t MsrId = (uint32_t)Rcx;
    uint64_t Value = (Rax & 0xFFFFFFFF) | ((Rdx & 0xFFFFFFFF) << 32);

    {
        std::lock_guard<std::mutex> Guard(MsrStoreLock);
        if (MsrId == 0x3A) {
            Value = (Value & ~0x4ULL) | 0x1;
            MsrStore[MsrId] = Value;
        } else if (MsrId >= 0x480 && MsrId <= 0x48D) {
            MsrStore[MsrId] = 0;
        } else if (MsrId == 0xC0010114) {
            MsrStore[MsrId] = 0;
        } else {
            MsrStore[MsrId] = Value;
        }
    }

    if (MsrId == 0x570 || MsrId == 0x571 || MsrId == 0x572 ||
        MsrId == 0x560 || MsrId == 0x561 ||
        (MsrId >= 0x580 && MsrId <= 0x58F)) {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{RED}[WRMSR] {WHT}0x%x{RED} (%s) = 0x%llx @ RIP=0x%llx (drv+0x%llx) *** INTEL PT WRITE ***{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip, Rip - DRIVER_BASE_UC);
    } else if (MsrId >= 0x300 && MsrId <= 0x400) {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{YEL}[WRMSR] 0x%x (%s) = 0x%llx @ drv+0x%llx *** PERF COUNTER WRITE ***{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip - DRIVER_BASE_UC);
    } else {
        const char* Name = GetMsrName(MsrId);
        Logger::Log("{GRY}[WRMSR] 0x%x (%s) = 0x%llx @ drv+0x%llx{RESET}\n",
            MsrId, Name ? Name : "???", Value, Rip - DRIVER_BASE_UC);
    }

    {
        uint64_t StoreVal;
        {
            std::lock_guard<std::mutex> Guard(MsrStoreLock);
            StoreVal = MsrStore[MsrId];
        }
        uc_x86_msr MsrVal;
        MsrVal.rid = MsrId;
        MsrVal.value = StoreVal;
        uc_reg_write(Uc, UC_X86_REG_MSR, &MsrVal);
    }

    DetectionRecordWrmsr(MsrId, Value, Rip);
}

void UnicornEmu::Hooks::OnMsrFallback(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    bool IsRead = false;
    uint32_t InstructionLen = 0;
    if (!DecodeMsrInstructionAt(Uc, Addr, IsRead, InstructionLen))
        return;

    if (IsRead && UnicornEmu::RdmsrInsnHookSupported)
        return;
    if (!IsRead && UnicornEmu::WrmsrInsnHookSupported)
        return;

    if (IsRead)
        Hooks::OnRdmsr(Uc, UserData);
    else
        Hooks::OnWrmsr(Uc, UserData);

    uint64_t NextRip = Addr + InstructionLen;
    uc_reg_write(Uc, UC_X86_REG_RIP, &NextRip);

    static uint64_t FallbackHitCount = 0;
    FallbackHitCount++;
    if (FallbackHitCount <= 40 || (FallbackHitCount % 2000 == 0)) {
        uint64_t DriverRva = (Addr >= DRIVER_BASE_UC) ? (Addr - DRIVER_BASE_UC) : Addr;
        Logger::Log("{MAG}[MSR FALLBACK] %s at drv+0x%llx len=%u hits=%llu{RESET}\n",
            IsRead ? "RDMSR" : "WRMSR", DriverRva, InstructionLen, FallbackHitCount);
    }
}

void UnicornEmu::Hooks::OnHypervisorSharedPageRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    HypervisorSharedPageReadCount++;
    uint64_t Offset = Addr - HYPERVISOR_SHARED_PAGE_BASE_UC;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    uint64_t DriverRva = (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL) ? Rip - DRIVER_BASE_UC : Rip;

    uint64_t ReadVal = 0;
    if (Size <= 8) {
        void* HostPtr = UnicornMem::UcToHost(Addr);
        if (HostPtr) memcpy(&ReadVal, HostPtr, Size);
    }

    auto& Entry = HypervisorSharedPageLog[HypervisorSharedPageLogIdx % 256];
    Entry.Rip = DriverRva;
    Entry.ReadOffset = Offset;
    Entry.Size = Size;
    Entry.Value = ReadVal;
    HypervisorSharedPageLogIdx++;

    if (DIAG_IS_ENABLED()) {
        HvspReadEvent Ev = {};
        Ev.Base.Sequence = DIAG_SEQ;
        Ev.Base.Rip = Rip;
        Ev.Base.AccessType = ACCESS_READ;
        DiagCenter::Instance().ResolveVaToModule(Rip, Ev.Base.ModuleBase, Ev.Base.ModuleRva, Ev.ModuleName, sizeof(Ev.ModuleName));
        {
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.ModuleName, sizeof(Ev.ModuleName));
            Ev.Base.ModuleBase = TmpBase;
            Ev.Base.ModuleRva = TmpRva;
        }
        Ev.Address = Addr;
        Ev.Offset = (uint32_t)Offset;
        Ev.Size = (uint32_t)Size;
        Ev.Value = ReadVal;
        const char* FieldName = "???";
        if (Offset == 0x00) FieldName = "TimeUpdateLock";
        else if (Offset == 0x04) FieldName = "Reserved0";
        else if (Offset == 0x08) FieldName = "QpcMultiplier";
        else if (Offset == 0x10) FieldName = "QpcBias";
        strncpy(Ev.FieldName, FieldName, sizeof(Ev.FieldName) - 1);
        Ev.DynamicUpdate = (Offset == 0x08) ? 1 : 0;
        DIAG_HVSP_READ(Ev);
    }

    if (HypervisorSharedPageReadCount <= 100) {
        const char* FieldName = "???";
        if (Offset == 0x00) FieldName = "TimeUpdateLock";
        else if (Offset == 0x04) FieldName = "Reserved0";
        else if (Offset == 0x08) FieldName = "QpcMultiplier";
        else if (Offset == 0x10) FieldName = "QpcBias";
        Logger::Log("{GRY}[HV_SHARED_PAGE_READ] offset=0x%03llx (%s) size=%d val=0x%llx RIP=drv+0x%llx{RESET}\n",
            Offset, FieldName, Size, ReadVal, DriverRva);
    }

    if (Offset >= 0x08 && Offset < 0x18) {
        LARGE_INTEGER PerfCount;
        QueryPerformanceCounter(&PerfCount);
        uint64_t QpcFreq;
        QueryPerformanceFrequency((LARGE_INTEGER*)&QpcFreq);
        uint64_t QpcMultiplier = (10000000ULL << 32) / QpcFreq;
        void* HostPtr = UnicornMem::UcToHost(HYPERVISOR_SHARED_PAGE_BASE_UC + 0x08);
        if (HostPtr) *(volatile uint64_t*)HostPtr = QpcMultiplier;
    }
}

void UnicornEmu::Hooks::OnBootEnvRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    BootEnvReadCount++;
    uint64_t Offset = Addr - 0xFFFFF80200050000ULL;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    uint64_t DriverRva = (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL) ? Rip - DRIVER_BASE_UC : Rip;

    uint64_t ReadVal = 0;
    if (Size <= 8) {
        void* HostPtr = UnicornMem::UcToHost(Addr);
        if (HostPtr) memcpy(&ReadVal, HostPtr, Size);
    }

    auto& Entry = BootEnvLog[BootEnvLogIdx % 128];
    Entry.Rip = DriverRva;
    Entry.ReadOffset = Offset;
    Entry.Size = Size;
    Entry.Value = ReadVal;
    BootEnvLogIdx++;

    if (BootEnvReadCount <= 100) {
        const char* FieldName = "???";
        if (Offset < 0x10) FieldName = "BootIdentifier";
        else if (Offset == 0x10) FieldName = "FirmwareType";
        else if (Offset == 0x18) FieldName = "BootFlags";
        Logger::Log("{GRY}[BOOT_ENV_READ] offset=0x%03llx (%s) size=%d val=0x%llx RIP=drv+0x%llx{RESET}\n",
            Offset, FieldName, Size, ReadVal, DriverRva);
    }
}

void UnicornEmu::Hooks::OnCodeIntegrityRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    CodeIntegrityReadCount++;
    uint64_t Offset = Addr - 0xFFFFF80200050000ULL;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    uint64_t DriverRva = (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL) ? Rip - DRIVER_BASE_UC : Rip;

    uint64_t ReadVal = 0;
    if (Size <= 8) {
        void* HostPtr = UnicornMem::UcToHost(Addr);
        if (HostPtr) memcpy(&ReadVal, HostPtr, Size);
    }

    auto& Entry = CodeIntegrityLog[CodeIntegrityLogIdx % 128];
    Entry.Rip = DriverRva;
    Entry.ReadOffset = Offset;
    Entry.Size = Size;
    Entry.Value = ReadVal;
    CodeIntegrityLogIdx++;

    if (CodeIntegrityReadCount <= 100) {
        const char* FieldName = "???";
        if (Offset == 0x00) FieldName = "Options";
        else if (Offset == 0x04) FieldName = "HVCIOptions";
        else if (Offset == 0x08) FieldName = "Version";
        else if (Offset == 0x10) FieldName = "PolicyGuid";
        Logger::Log("{GRY}[CODE_INTEGRITY_READ] offset=0x%03llx (%s) size=%d val=0x%llx RIP=drv+0x%llx{RESET}\n",
            Offset, FieldName, Size, ReadVal, DriverRva);
    }
}
