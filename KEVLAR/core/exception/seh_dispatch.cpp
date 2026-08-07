#include "core/exception/seh_dispatch.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/diagnostics/diag_center.h"
#include <Logger/Logger.h>
#include <windows.h>
#include <vector>

static std::vector<SehDispatch::ModuleRange> RegisteredModules;

struct PendingFilterState {
    bool Active;
    uint64_t OriginalRsp;
    uint64_t FaultRip;
    uint64_t JumpTarget;
    uint64_t ContextUcAddr;
    uint32_t ExceptionCode;
    uint64_t EstablishedFrame;
};

static thread_local PendingFilterState PendingFilter = {};

bool SehDispatch::Initialize() {
    RegisteredModules.clear();
    PendingFilter.Active = false;
    return true;
}

uint32_t SehDispatch::IntNoToExceptionCode(uint32_t IntNo) {
    switch (IntNo) {
    case 0x00: return STATUS_INTEGER_DIVIDE_BY_ZERO;
    case 0x01: return STATUS_SINGLE_STEP_EX;
    case 0x03: return STATUS_BREAKPOINT_EX;
    case 0x04: return STATUS_INTEGER_OVERFLOW_EX;
    case 0x06: return STATUS_ILLEGAL_INSTRUCTION_EX;
    case 0x0D: return STATUS_PRIVILEGED_INSTRUCTION;
    case 0x0E: return STATUS_ACCESS_VIOLATION_EX;
    case 0x11: return STATUS_DATATYPE_MISALIGNMENT;
    case 0x2C: return STATUS_ASSERTION_FAILURE;
    default:   return 0xC0000005;
    }
}

static bool FindModuleForAddress(uint64_t UcAddr, uint64_t& OutUcBase, uint64_t& OutSize, uint8_t** OutHostBase) {
    std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
    for (auto& Region : UnicornEmu::MappedRegions) {
        if (UcAddr >= Region.UcBase && UcAddr < Region.UcBase + Region.Size && Region.HostPtr) {
            *OutHostBase = (uint8_t*)Region.HostPtr;
            OutUcBase = Region.UcBase;
            OutSize = Region.Size;
            return true;
        }
    }

    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (UcAddr >= Mod.UcBase && UcAddr < Mod.UcBase + Mod.Size) {
            void* HostAddr = UnicornMem::UcToHost(Mod.UcBase);
            if (HostAddr) {
                *OutHostBase = (uint8_t*)HostAddr;
                OutUcBase = Mod.UcBase;
                OutSize = Mod.Size;
                return true;
            }
        }
    }

    return false;
}

static bool GetExceptionDirectory(uint8_t* HostImageBase, uint32_t& OutRva, uint32_t& OutSize) {
    auto Dos = (PIMAGE_DOS_HEADER)HostImageBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto Nt = (PIMAGE_NT_HEADERS)(HostImageBase + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& ExDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!ExDir.VirtualAddress || !ExDir.Size) return false;

    OutRva = ExDir.VirtualAddress;
    OutSize = ExDir.Size;
    return true;
}

RUNTIME_FUNCTION_ENTRY* SehDispatch::FindRuntimeFunction(uint8_t* HostImageBase, uint64_t ImageSize, uint32_t FaultRva) {
    uint32_t PdataRva = 0, PdataSize = 0;
    if (!GetExceptionDirectory(HostImageBase, PdataRva, PdataSize)) return nullptr;

    auto Entries = (RUNTIME_FUNCTION_ENTRY*)(HostImageBase + PdataRva);
    uint32_t Count = PdataSize / sizeof(RUNTIME_FUNCTION_ENTRY);

    if (Count == 0) return nullptr;

    uint32_t Lo = 0, Hi = Count - 1;
    while (Lo <= Hi) {
        uint32_t Mid = Lo + (Hi - Lo) / 2;
        if (FaultRva < Entries[Mid].BeginAddress) {
            if (Mid == 0) break;
            Hi = Mid - 1;
        } else if (FaultRva >= Entries[Mid].EndAddress) {
            Lo = Mid + 1;
        } else {
            return &Entries[Mid];
        }
    }

    return nullptr;
}

static DiagRejectReason ClassifyRejectReason(uint64_t Addr) {
    if (Addr == 0) return REJECT_SMALL_INT;
    if (Addr == SENTINEL_RET_ADDR) return REJECT_SENTINEL;
    if (Addr < 0xFFFFF00000000000ULL) {
        if (Addr < 0x1000) return REJECT_SMALL_INT;
        if (Addr >= KUSD_BASE_UC && Addr < KUSD_BASE_UC + 0x1000) return REJECT_KUSER_SHARED_DATA;
        if (Addr >= HYPERVISOR_SHARED_PAGE_BASE_UC && Addr < HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000) return REJECT_HYPERVISOR_SHARED_PAGE;
        if (Addr >= POOL_BASE_UC && Addr < POOL_BASE_UC + 0x200000000ULL) return REJECT_POOL;
        if (Addr >= STACK_BASE_UC && Addr < STACK_BASE_UC + STACK_SIZE_UC) return REJECT_STACK;
        if (Addr >= SENTINEL_BASE_UC && Addr < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE) return REJECT_SENTINEL;
        if (DiagCenter::Instance().IsStringLikeData(Addr)) return REJECT_STRING_LIKE;
        if (Addr >= 0xFFFF800000000000ULL) return REJECT_UNMAPPED;
        return REJECT_NON_CANONICAL;
    }
    if (!DiagCenter::Instance().IsCanonicalKernelVa(Addr)) return REJECT_NON_CANONICAL;
    uint64_t UcBase = 0, ModSize = 0;
    uint8_t* HostBase = nullptr;
    if (!FindModuleForAddress(Addr, UcBase, ModSize, &HostBase)) {
        uint64_t NearestDist = 0xFFFFFFFFFFFFFFFFULL;
        for (auto& Region : UnicornEmu::MappedRegions) {
            uint64_t Dist = (Addr > Region.UcBase) ? (Addr - Region.UcBase - Region.Size) : (Region.UcBase - Addr);
            if (Dist < NearestDist) NearestDist = Dist;
        }
        if (NearestDist > 0x10000000) return REJECT_FAR_FROM_MODULES;
        return REJECT_NO_MODULE;
    }
    return REJECT_OK;
}

static bool IsValidCodeAddress(uint64_t Addr) {
    if (Addr == 0 || Addr == SENTINEL_RET_ADDR) return false;
    if (Addr < 0xFFFFF00000000000ULL) return false;

    uint64_t UcBase = 0, ModSize = 0;
    uint8_t* HostBase = nullptr;
    return FindModuleForAddress(Addr, UcBase, ModSize, &HostBase);
}

static bool IsCallInstructionBefore(uint8_t* HostBase, uint64_t ModSize, uint32_t CandidateRva) {
    if (CandidateRva < 2) return false;

    uint8_t* Code = HostBase;

    if (CandidateRva >= 5) {
        uint8_t Op = Code[CandidateRva - 5];
        if (Op == 0xE8)
            return true;
    }

    for (int Back = 2; Back <= 7 && Back <= (int)CandidateRva; Back++) {
        uint32_t Pos = CandidateRva - Back;
        uint8_t* P = Code + Pos;

        int Idx = 0;
        int Len = Back;

        while (Idx < Len - 1 && (P[Idx] & 0xF0) == 0x40)
            Idx++;

        if (Idx < Len && P[Idx] == 0xFF) {
            if (Idx + 1 < Len) {
                uint8_t ModRm = P[Idx + 1];
                uint8_t RegField = (ModRm >> 3) & 7;
                if (RegField == 2 || RegField == 3)
                    return true;
            }
        }
    }

    return false;
}

static bool ScanStackForReturnAddress(uc_engine* Uc, uint64_t StartRsp, uint64_t* OutAddr, uint64_t* OutNewRsp) {
    uint64_t FallbackAddr = 0;
    uint64_t FallbackRsp = 0;
    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    for (uint64_t Offset = 0; Offset < 0x20000; Offset += 8) {
        uint64_t Candidate = 0;
        if (uc_mem_read(Uc, StartRsp + Offset, &Candidate, 8) != UC_ERR_OK)
            break;

        if (!IsValidCodeAddress(Candidate)) {
            if (DIAG_IS_ENABLED() && Candidate != 0) {
                DiagRejectReason Reason = ClassifyRejectReason(Candidate);
                if (Reason != REJECT_SMALL_INT || (Candidate & ~0xFFFULL) != 0) {
                    StackRejectEvent Ev = {};
                    Ev.Sequence = DIAG_SEQ;
                    Ev.Value = Candidate;
                    Ev.StackSlot = StartRsp + Offset;
                    Ev.Reason = Reason;
                    Ev.Rip = Rip;
                    uint64_t TmpBase = 0;
                    uint32_t TmpRva = 0;
                    DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.ModuleName, sizeof(Ev.ModuleName));
                    Ev.ModuleRva = TmpRva;
                    DiagCenter::Instance().EmitRejectReason(Reason, Ev.ReasonStr, sizeof(Ev.ReasonStr));
                    DIAG_STACK_REJECT(Ev);
                }
            }
            continue;
        }

        uint64_t UcBase = 0, ModSize = 0;
        uint8_t* HostBase = nullptr;
        if (!FindModuleForAddress(Candidate, UcBase, ModSize, &HostBase))
            continue;

        uint32_t CandidateRva = (uint32_t)(Candidate - UcBase);
        RUNTIME_FUNCTION_ENTRY* RtFunc = SehDispatch::FindRuntimeFunction(HostBase, ModSize, CandidateRva);
        if (!RtFunc)
            continue;

        if (CandidateRva == RtFunc->BeginAddress)
            continue;

        if (!FallbackAddr) {
            FallbackAddr = Candidate;
            FallbackRsp = StartRsp + Offset + 8;
        }

        if (!IsCallInstructionBefore(HostBase, ModSize, CandidateRva))
            continue;

        if (DIAG_IS_ENABLED()) {
            StackAcceptEvent Ev = {};
            Ev.Sequence = DIAG_SEQ;
            Ev.Value = Candidate;
            Ev.StackSlot = StartRsp + Offset;
            Ev.Rip = Rip;
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.ModuleName, sizeof(Ev.ModuleName));
            Ev.ModuleRva = TmpRva;
            DiagCenter::Instance().ResolveVaToPeSection(Candidate, Ev.Section, sizeof(Ev.Section));
            Ev.Confidence = IsCallInstructionBefore(HostBase, ModSize, CandidateRva) ? 100 : 50;
            DIAG_STACK_ACCEPT(Ev);
        }

        *OutAddr = Candidate;
        *OutNewRsp = StartRsp + Offset + 8;
        return true;
    }

    if (FallbackAddr) {
        *OutAddr = FallbackAddr;
        *OutNewRsp = FallbackRsp;
        return true;
    }

    return false;
}

static uint64_t SumUnwindStackAdjust(UNWIND_INFO_HEADER* UnwindInfo, UNWIND_CODE* Codes) {
    uint64_t StackAdjust = 0;
    for (int I = 0; I < UnwindInfo->CountOfCodes; I++) {
        switch (Codes[I].UnwindOp) {
        case UWOP_PUSH_NONVOL:
            StackAdjust += 8;
            break;
        case UWOP_ALLOC_LARGE:
            if (Codes[I].OpInfo == 0) {
                I++;
                if (I < UnwindInfo->CountOfCodes)
                    StackAdjust += *(uint16_t*)&Codes[I] * 8;
            } else {
                I += 2;
                if (I < UnwindInfo->CountOfCodes)
                    StackAdjust += *(uint32_t*)&Codes[I - 1];
            }
            break;
        case UWOP_ALLOC_SMALL:
            StackAdjust += (uint64_t)(Codes[I].OpInfo * 8 + 8);
            break;
        case UWOP_SET_FPREG:
            break;
        case UWOP_SAVE_NONVOL:
            I++;
            break;
        case UWOP_SAVE_NONVOL_FAR:
            I += 2;
            break;
        case UWOP_SAVE_XMM128:
            I++;
            break;
        case UWOP_SAVE_XMM128_FAR:
            I += 2;
            break;
        case UWOP_PUSH_MACHFRAME:
            StackAdjust += (Codes[I].OpInfo ? 48 : 40);
            break;
        }
    }
    return StackAdjust;
}

static uint64_t CalculateEstablishedFrameAt(
    uc_engine* Uc, uint64_t Rsp, bool CanUseRegisterState,
    UNWIND_INFO_HEADER* UnwindInfo, UNWIND_CODE* Codes) {

    uint8_t FrameReg = UnwindInfo->FrameRegisterOffset & 0x0F;
    uint8_t FrameOff = (UnwindInfo->FrameRegisterOffset >> 4) & 0x0F;

    if (FrameReg != 0 && CanUseRegisterState) {
        static const int RegMap[] = {
            UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
            UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
            UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        };

        uint64_t RegVal = 0;
        uc_reg_read(Uc, RegMap[FrameReg], &RegVal);
        return RegVal - (uint64_t)FrameOff * 16;
    }

    return Rsp + SumUnwindStackAdjust(UnwindInfo, Codes);
}

uint64_t SehDispatch::CalculateEstablishedFrame(uc_engine* Uc, uint8_t* HostImageBase, UNWIND_INFO_HEADER* UnwindInfo, UNWIND_CODE* Codes) {
    uint64_t Rsp = 0;
    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
    return CalculateEstablishedFrameAt(Uc, Rsp, true, UnwindInfo, Codes);
}

static bool UnwindFrameRsp(
    uc_engine* Uc, UNWIND_INFO_HEADER* UnwindInfo, UNWIND_CODE* Codes,
    uint64_t FrameRsp, uint64_t* OutReturnAddr, uint64_t* OutCallerRsp) {

    uint64_t StackAdjust = SumUnwindStackAdjust(UnwindInfo, Codes);
    uint64_t RetAddrLocation = FrameRsp + StackAdjust;

    uint64_t RetAddr = 0;
    if (uc_mem_read(Uc, RetAddrLocation, &RetAddr, 8) != UC_ERR_OK) {
        Logger::Log("{RED}SEH walk: failed to read return address at 0x%llx{RESET}\n", RetAddrLocation);
        return false;
    }

    *OutReturnAddr = RetAddr;
    *OutCallerRsp = RetAddrLocation + 8;
    return true;
}

static bool BuildExceptionContext(uc_engine* Uc, uint32_t ExceptionCode, uint64_t FaultRip,
                                   uint64_t FaultAddress, uint64_t& OutExPtrsAddr, uint64_t& OutNewRsp) {
    uint64_t OrigRsp = 0;
    uc_reg_read(Uc, UC_X86_REG_RSP, &OrigRsp);

    uint64_t ContextAddr = (OrigRsp - sizeof(CONTEXT)) & ~0xFULL;
    uint64_t ExRecAddr = ContextAddr - 0xA0;
    uint64_t ExPtrsAddr = ExRecAddr - 0x10;

    CONTEXT Ctx;
    memset(&Ctx, 0, sizeof(Ctx));
    Ctx.ContextFlags = 0x10001F;

    uc_reg_read(Uc, UC_X86_REG_RAX, &Ctx.Rax);
    uc_reg_read(Uc, UC_X86_REG_RCX, &Ctx.Rcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Ctx.Rdx);
    uc_reg_read(Uc, UC_X86_REG_RBX, &Ctx.Rbx);
    uc_reg_read(Uc, UC_X86_REG_RSP, &Ctx.Rsp);
    uc_reg_read(Uc, UC_X86_REG_RBP, &Ctx.Rbp);
    uc_reg_read(Uc, UC_X86_REG_RSI, &Ctx.Rsi);
    uc_reg_read(Uc, UC_X86_REG_RDI, &Ctx.Rdi);
    uc_reg_read(Uc, UC_X86_REG_R8, &Ctx.R8);
    uc_reg_read(Uc, UC_X86_REG_R9, &Ctx.R9);
    uc_reg_read(Uc, UC_X86_REG_R10, &Ctx.R10);
    uc_reg_read(Uc, UC_X86_REG_R11, &Ctx.R11);
    uc_reg_read(Uc, UC_X86_REG_R12, &Ctx.R12);
    uc_reg_read(Uc, UC_X86_REG_R13, &Ctx.R13);
    uc_reg_read(Uc, UC_X86_REG_R14, &Ctx.R14);
    uc_reg_read(Uc, UC_X86_REG_R15, &Ctx.R15);

    uint64_t Rflags = 0;
    uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Rflags);
    Ctx.EFlags = (DWORD)Rflags;

    Ctx.Rip = FaultRip;

    uint16_t SegVal = 0;
    uc_reg_read(Uc, UC_X86_REG_CS, &SegVal); Ctx.SegCs = SegVal;
    uc_reg_read(Uc, UC_X86_REG_DS, &SegVal); Ctx.SegDs = SegVal;
    uc_reg_read(Uc, UC_X86_REG_ES, &SegVal); Ctx.SegEs = SegVal;
    uc_reg_read(Uc, UC_X86_REG_FS, &SegVal); Ctx.SegFs = SegVal;
    uc_reg_read(Uc, UC_X86_REG_GS, &SegVal); Ctx.SegGs = SegVal;
    uc_reg_read(Uc, UC_X86_REG_SS, &SegVal); Ctx.SegSs = SegVal;

    uc_mem_write(Uc, ContextAddr, &Ctx, sizeof(CONTEXT));

    uint8_t ExRecBuf[0xA0];
    memset(ExRecBuf, 0, sizeof(ExRecBuf));
    *(uint32_t*)(ExRecBuf + 0x00) = ExceptionCode;
    *(uint32_t*)(ExRecBuf + 0x04) = 0;
    *(uint64_t*)(ExRecBuf + 0x08) = 0;
    *(uint64_t*)(ExRecBuf + 0x10) = FaultRip;

    if (ExceptionCode == STATUS_ACCESS_VIOLATION_EX && FaultAddress != 0) {
        *(uint32_t*)(ExRecBuf + 0x18) = 2;
        *(uint64_t*)(ExRecBuf + 0x20) = 0;
        *(uint64_t*)(ExRecBuf + 0x28) = FaultAddress;
    }

    uc_mem_write(Uc, ExRecAddr, ExRecBuf, 0xA0);

    uint64_t ExPtrsBuf[2];
    ExPtrsBuf[0] = ExRecAddr;
    ExPtrsBuf[1] = ContextAddr;
    uc_mem_write(Uc, ExPtrsAddr, ExPtrsBuf, 0x10);

    OutExPtrsAddr = ExPtrsAddr;
    OutNewRsp = (ExPtrsAddr - 0x28) & ~0xFULL;

    return true;
}

bool SehDispatch::ProcessScopeTable(uint8_t* HostImageBase, uint64_t UcImageBase, uint32_t ScopeTableRva, uint32_t FaultRva, uint64_t& OutJumpTarget) {
    auto ScopeCount = *(uint32_t*)(HostImageBase + ScopeTableRva);
    auto Entries = (SCOPE_TABLE_ENTRY*)(HostImageBase + ScopeTableRva + 4);

    Logger::Log("{MAG}  SEH ScopeTable: %u entries{RESET}\n", ScopeCount);

    if (ScopeCount > 256) {
        Logger::Log("{RED}  SEH: scope count too large (%u), likely corrupt{RESET}\n", ScopeCount);
        return false;
    }

    for (uint32_t I = 0; I < ScopeCount; I++) {
        Logger::Log("{GRY}    Scope[%u]: Begin=0x%x End=0x%x Handler=0x%x Jump=0x%x{RESET}\n",
            I, Entries[I].BeginAddress, Entries[I].EndAddress,
            Entries[I].HandlerAddress, Entries[I].JumpTarget);

        if (FaultRva >= Entries[I].BeginAddress && FaultRva < Entries[I].EndAddress) {
            if (Entries[I].JumpTarget != 0) {
                if (Entries[I].HandlerAddress == SEH_EXCEPTION_EXECUTE_HANDLER) {
                    Logger::Log("{GRN}  SEH: EXCEPTION_EXECUTE_HANDLER -> jumping to 0x%llx{RESET}\n",
                        UcImageBase + Entries[I].JumpTarget);
                    OutJumpTarget = UcImageBase + Entries[I].JumpTarget;
                    return true;
                }

                Logger::Log("{CYN}  SEH: filter at 0x%x, assuming EXCEPTION_EXECUTE_HANDLER{RESET}\n",
                    Entries[I].HandlerAddress);
                OutJumpTarget = UcImageBase + Entries[I].JumpTarget;
                return true;
            }

            if (Entries[I].HandlerAddress != 0 && Entries[I].JumpTarget == 0) {
                Logger::Log("{CYN}  SEH: __finally block at 0x%x{RESET}\n", Entries[I].HandlerAddress);
            }
        }
    }

    return false;
}

static bool FindScopeWithFilter(uint8_t* HostImageBase, uint64_t UcImageBase, uint32_t ScopeTableRva,
                                 uint32_t FaultRva, uint64_t& OutJumpTarget, uint32_t& OutFilterRva) {
    auto ScopeCount = *(uint32_t*)(HostImageBase + ScopeTableRva);
    auto Entries = (SCOPE_TABLE_ENTRY*)(HostImageBase + ScopeTableRva + 4);

    if (ScopeCount > 256) return false;

    for (uint32_t I = 0; I < ScopeCount; I++) {
        if (FaultRva >= Entries[I].BeginAddress && FaultRva < Entries[I].EndAddress) {
            if (Entries[I].JumpTarget != 0) {
                OutJumpTarget = UcImageBase + Entries[I].JumpTarget;
                if (Entries[I].HandlerAddress == SEH_EXCEPTION_EXECUTE_HANDLER) {
                    OutFilterRva = 0;
                } else {
                    OutFilterRva = Entries[I].HandlerAddress;
                }
                return true;
            }
        }
    }

    return false;
}

static RUNTIME_FUNCTION_ENTRY* ResolveChainedFunction(
    uint8_t* HostBase, RUNTIME_FUNCTION_ENTRY* RtFunc,
    UNWIND_INFO_HEADER** OutUnwindInfo, uint8_t* OutFlags) {

    auto UnwindInfo = (UNWIND_INFO_HEADER*)(HostBase + RtFunc->UnwindInfoAddress);
    uint8_t Flags = (UnwindInfo->VersionFlags >> 3) & 0x1F;

    while (Flags & UNW_FLAG_CHAININFO) {
        uint32_t CodesSize = UnwindInfo->CountOfCodes;
        if (CodesSize & 1) CodesSize++;
        auto ChainedFunc = (RUNTIME_FUNCTION_ENTRY*)(
            (uint8_t*)(UnwindInfo + 1) + CodesSize * sizeof(UNWIND_CODE));

        RtFunc = ChainedFunc;
        UnwindInfo = (UNWIND_INFO_HEADER*)(HostBase + ChainedFunc->UnwindInfoAddress);
        Flags = (UnwindInfo->VersionFlags >> 3) & 0x1F;
    }

    *OutUnwindInfo = UnwindInfo;
    *OutFlags = Flags;
    return RtFunc;
}

static bool DispatchToHandler(
    uc_engine* Uc, uint32_t ExceptionCode, uint64_t FaultAddress,
    uint64_t OriginalFaultRip, uint64_t HandlerFrameRsp,
    uint64_t UcBase, uint8_t* HostBase,
    uint64_t EstablishedFrame, uint64_t JumpTarget, uint32_t FilterRva) {

    if (FilterRva != 0) {
        uint64_t FilterAddr = UcBase + FilterRva;
        Logger::Log("{CYN}SEH: executing filter at 0x%llx (frame=0x%llx){RESET}\n", FilterAddr, EstablishedFrame);

        uint64_t ExPtrsAddr = 0, NewRsp = 0;
        if (!BuildExceptionContext(Uc, ExceptionCode, OriginalFaultRip, FaultAddress, ExPtrsAddr, NewRsp))
            return false;

        uint64_t OrigRsp = 0;
        uc_reg_read(Uc, UC_X86_REG_RSP, &OrigRsp);

        PendingFilter.Active = true;
        PendingFilter.OriginalRsp = HandlerFrameRsp;
        PendingFilter.FaultRip = OriginalFaultRip;
        PendingFilter.JumpTarget = JumpTarget;
        PendingFilter.ContextUcAddr = ((OrigRsp - sizeof(CONTEXT)) & ~0xFULL);
        PendingFilter.ExceptionCode = ExceptionCode;
        PendingFilter.EstablishedFrame = EstablishedFrame;

        uc_reg_write(Uc, UC_X86_REG_RSP, &NewRsp);
        uc_reg_write(Uc, UC_X86_REG_RCX, &ExPtrsAddr);
        uc_reg_write(Uc, UC_X86_REG_RDX, &EstablishedFrame);
        uc_reg_write(Uc, UC_X86_REG_RAX, &FilterAddr);

        uint64_t TrampolineAddr = EXCEPTION_TRAMPOLINE_UC;
        uc_reg_write(Uc, UC_X86_REG_RIP, &TrampolineAddr);

        Logger::Log("{CYN}SEH: filter trampoline at 0x%llx, ExPtrs=0x%llx, RSP=0x%llx{RESET}\n",
            TrampolineAddr, ExPtrsAddr, NewRsp);
        return true;
    }

    Logger::Log("{GRN}SEH: dispatching to __except at 0x%llx (frame=0x%llx){RESET}\n",
        JumpTarget, EstablishedFrame);

    uc_reg_write(Uc, UC_X86_REG_RIP, &JumpTarget);
    uc_reg_write(Uc, UC_X86_REG_RSP, &HandlerFrameRsp);

    uint64_t ExCode64 = (uint64_t)ExceptionCode;
    uc_reg_write(Uc, UC_X86_REG_RAX, &ExCode64);

    return true;
}

bool SehDispatch::DispatchException(uc_engine* Uc, uint32_t ExceptionCode, uint64_t FaultAddress) {
    if (!UnicornEmu::SehDispatchEnabled) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{YEL}SEH DISABLED: code=0x%08x at RIP=0x%llx — falling through{RESET}\n", ExceptionCode, Rip);
        return false;
    }
    uint64_t OriginalRip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &OriginalRip);

    uint64_t OriginalRsp = 0;
    uc_reg_read(Uc, UC_X86_REG_RSP, &OriginalRsp);

    Logger::Log("{MAG}SEH Dispatch: code=0x%08x at RIP=0x%llx fault=0x%llx{RESET}\n",
        ExceptionCode, OriginalRip, FaultAddress);

    if (DIAG_IS_ENABLED()) {
        SehEvent Ev = {};
        Ev.Base.Sequence = DIAG_SEQ;
        Ev.Base.Rip = OriginalRip;
        Ev.ExceptionCode = ExceptionCode;
        Ev.FaultAddress = FaultAddress;
        Ev.FirstChance = 1;
        DiagCenter::Instance().ResolveVaToModule(OriginalRip, Ev.Base.ModuleBase, Ev.Base.ModuleRva, Ev.ModuleName, sizeof(Ev.ModuleName));
        {
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(OriginalRip, TmpBase, TmpRva, Ev.ModuleName, sizeof(Ev.ModuleName));
            Ev.Base.ModuleBase = TmpBase;
            Ev.Base.ModuleRva = TmpRva;
        }
        uc_reg_read(Uc, UC_X86_REG_RAX, &Ev.GprAX);
        uc_reg_read(Uc, UC_X86_REG_RBX, &Ev.GprBX);
        uc_reg_read(Uc, UC_X86_REG_RCX, &Ev.GprCX);
        uc_reg_read(Uc, UC_X86_REG_RDX, &Ev.GprDX);
        uc_reg_read(Uc, UC_X86_REG_RSI, &Ev.GprSI);
        uc_reg_read(Uc, UC_X86_REG_RDI, &Ev.GprDI);
        uc_reg_read(Uc, UC_X86_REG_RSP, &Ev.GprSP);
        uc_reg_read(Uc, UC_X86_REG_RBP, &Ev.GprBP);
        uc_reg_read(Uc, UC_X86_REG_R8, &Ev.GprR8);
        uc_reg_read(Uc, UC_X86_REG_R9, &Ev.GprR9);
        uc_reg_read(Uc, UC_X86_REG_R10, &Ev.GprR10);
        uc_reg_read(Uc, UC_X86_REG_R11, &Ev.GprR11);
        uc_reg_read(Uc, UC_X86_REG_R12, &Ev.GprR12);
        uc_reg_read(Uc, UC_X86_REG_R13, &Ev.GprR13);
        uc_reg_read(Uc, UC_X86_REG_R14, &Ev.GprR14);
        uc_reg_read(Uc, UC_X86_REG_R15, &Ev.GprR15);
        uint64_t Eflags = 0;
        uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Eflags);
        Ev.Eflags = (uint32_t)Eflags;
        Ev.Hints = (uint8_t)DiagCenter::Instance().ComputePeProbeHint(FaultAddress);
        snprintf(Ev.Reason, sizeof(Ev.Reason), "code=0x%08x", ExceptionCode);
        DIAG_SEH(Ev);
    }

    uint64_t WalkRip = OriginalRip;
    uint64_t WalkRsp = OriginalRsp;

    for (int Depth = 0; Depth < 16; Depth++) {
        uint64_t UcBase = 0, ModSize = 0;
        uint8_t* HostBase = nullptr;
        if (!FindModuleForAddress(WalkRip, UcBase, ModSize, &HostBase)) {
            Logger::Log("{RED}SEH walk[%d]: RIP 0x%llx not in any mapped module{RESET}\n", Depth, WalkRip);
            return false;
        }

        uint32_t FrameRva = (uint32_t)(WalkRip - UcBase);
        Logger::Log("{GRY}  SEH walk[%d]: RIP=0x%llx RVA=0x%x RSP=0x%llx{RESET}\n",
            Depth, WalkRip, FrameRva, WalkRsp);

        RUNTIME_FUNCTION_ENTRY* RtFunc = FindRuntimeFunction(HostBase, ModSize, FrameRva);
        if (!RtFunc) {
            Logger::Log("{YEL}  SEH walk[%d]: no RUNTIME_FUNCTION for RVA 0x%x (leaf frame){RESET}\n",
                Depth, FrameRva);

            uint64_t RetAddr = 0;
            if (uc_mem_read(Uc, WalkRsp, &RetAddr, 8) != UC_ERR_OK) {
                Logger::Log("{RED}  SEH walk[%d]: failed to read [RSP]{RESET}\n", Depth);
                return false;
            }

            if (IsValidCodeAddress(RetAddr)) {
                Logger::Log("{GRY}  SEH walk[%d]: leaf -> return addr 0x%llx{RESET}\n", Depth, RetAddr);
                WalkRip = RetAddr;
                WalkRsp += 8;
                continue;
            }

            Logger::Log("{YEL}  SEH walk[%d]: [RSP]=0x%llx invalid, scanning stack for return address{RESET}\n",
                Depth, RetAddr);

            uint64_t ScannedAddr = 0, ScannedRsp = 0;
            if (ScanStackForReturnAddress(Uc, WalkRsp, &ScannedAddr, &ScannedRsp)) {
                Logger::Log("{GRN}  SEH walk[%d]: stack scan found 0x%llx at RSP+0x%llx{RESET}\n",
                    Depth, ScannedAddr, (ScannedRsp - 8) - WalkRsp);
                WalkRip = ScannedAddr;
                WalkRsp = ScannedRsp;
                continue;
            }

            Logger::Log("{RED}  SEH walk[%d]: stack scan found no valid return address{RESET}\n", Depth);
            return false;
        }

        auto RawUnwindInfo = (UNWIND_INFO_HEADER*)(HostBase + RtFunc->UnwindInfoAddress);
        uint8_t RawVersionFlags = RawUnwindInfo->VersionFlags;
        uint8_t RawFlags = (RawVersionFlags >> 3) & 0x1F;
        Logger::Log("{GRY}  SEH walk[%d]: raw RT Begin=0x%x End=0x%x UnwindRVA=0x%x VersionFlags=0x%02x rawFlags=0x%x codes=%d{RESET}\n",
            Depth, RtFunc->BeginAddress, RtFunc->EndAddress, RtFunc->UnwindInfoAddress,
            RawVersionFlags, RawFlags, RawUnwindInfo->CountOfCodes);

        UNWIND_INFO_HEADER* UnwindInfo = nullptr;
        uint8_t Flags = 0;
        RtFunc = ResolveChainedFunction(HostBase, RtFunc, &UnwindInfo, &Flags);

        auto Codes = (UNWIND_CODE*)(UnwindInfo + 1);

        if (RtFunc->BeginAddress != (uint32_t)(WalkRip - UcBase)) {
            Logger::Log("{GRY}  SEH walk[%d]: resolved RUNTIME_FUNCTION Begin=0x%x End=0x%x flags=0x%x{RESET}\n",
                Depth, RtFunc->BeginAddress, RtFunc->EndAddress, Flags);
        }

        if (Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
            uint32_t AlignedCodesSize = UnwindInfo->CountOfCodes;
            if (AlignedCodesSize & 1) AlignedCodesSize++;

            auto HandlerRvaPtr = (uint32_t*)((uint8_t*)(UnwindInfo + 1) + AlignedCodesSize * sizeof(UNWIND_CODE));
            uint32_t HandlerRva = *HandlerRvaPtr;
            uint32_t ScopeTableRva = (uint32_t)((uint8_t*)(HandlerRvaPtr + 1) - HostBase);

            uint64_t EstablishedFrame = CalculateEstablishedFrameAt(
                Uc, WalkRsp, (Depth == 0), UnwindInfo, Codes);

            uint32_t ScopeCheckRva = (Depth == 0) ? FrameRva : (FrameRva - 1);

            Logger::Log("{MAG}  SEH walk[%d]: handler RVA=0x%x scope RVA=0x%x check RVA=0x%x frame=0x%llx{RESET}\n",
                Depth, HandlerRva, ScopeTableRva, ScopeCheckRva, EstablishedFrame);

            uint64_t JumpTarget = 0;
            uint32_t FilterRva = 0;
            if (FindScopeWithFilter(HostBase, UcBase, ScopeTableRva, ScopeCheckRva, JumpTarget, FilterRva)) {
                Logger::Log("{GRN}  SEH walk[%d]: found handler! jump=0x%llx filter=0x%x{RESET}\n",
                    Depth, JumpTarget, FilterRva);
                return DispatchToHandler(Uc, ExceptionCode, FaultAddress,
                    OriginalRip, WalkRsp, UcBase, HostBase,
                    EstablishedFrame, JumpTarget, FilterRva);
            }

            Logger::Log("{GRY}  SEH walk[%d]: no matching scope, continuing walk{RESET}\n", Depth);
        }

        uint64_t RetAddr = 0, CallerRsp = 0;
        if (!UnwindFrameRsp(Uc, UnwindInfo, Codes, WalkRsp, &RetAddr, &CallerRsp)) {
            Logger::Log("{RED}  SEH walk[%d]: failed to unwind frame{RESET}\n", Depth);
            return false;
        }

        if (IsValidCodeAddress(RetAddr)) {
            Logger::Log("{GRY}  SEH walk[%d]: unwound -> return addr 0x%llx caller RSP=0x%llx{RESET}\n",
                Depth, RetAddr, CallerRsp);
            WalkRip = RetAddr;
            WalkRsp = CallerRsp;
        } else {
            Logger::Log("{YEL}  SEH walk[%d]: unwound return addr 0x%llx invalid, scanning stack{RESET}\n",
                Depth, RetAddr);

            uint64_t ScannedAddr = 0, ScannedRsp = 0;
            if (ScanStackForReturnAddress(Uc, CallerRsp, &ScannedAddr, &ScannedRsp)) {
                Logger::Log("{GRN}  SEH walk[%d]: stack scan found 0x%llx{RESET}\n", Depth, ScannedAddr);
                WalkRip = ScannedAddr;
                WalkRsp = ScannedRsp;
            } else {
                Logger::Log("{RED}  SEH walk[%d]: stack scan found no valid return address{RESET}\n", Depth);
                return false;
            }
        }
    }

    Logger::Log("{RED}SEH: exhausted %d frames without finding handler{RESET}\n", 16);
    return false;
}

bool SehDispatch::CompleteFilterDispatch(uc_engine* Uc) {
    if (!PendingFilter.Active) return false;

    uint64_t FilterResult = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &FilterResult);
    int32_t Result = (int32_t)FilterResult;

    Logger::Log("{CYN}SEH: filter returned %d{RESET}\n", Result);

    PendingFilter.Active = false;

    if (Result == 1) {
        Logger::Log("{GRN}SEH: EXCEPTION_EXECUTE_HANDLER -> jumping to 0x%llx{RESET}\n", PendingFilter.JumpTarget);

        uc_reg_write(Uc, UC_X86_REG_RSP, &PendingFilter.OriginalRsp);
        uc_reg_write(Uc, UC_X86_REG_RIP, &PendingFilter.JumpTarget);

        uint64_t ExCode64 = (uint64_t)PendingFilter.ExceptionCode;
        uc_reg_write(Uc, UC_X86_REG_RAX, &ExCode64);

        return true;
    }

    if (Result == -1) {
        Logger::Log("{GRN}SEH: EXCEPTION_CONTINUE_EXECUTION -> returning to 0x%llx{RESET}\n", PendingFilter.FaultRip);

        CONTEXT RestoredCtx;
        uc_mem_read(Uc, PendingFilter.ContextUcAddr, &RestoredCtx, sizeof(CONTEXT));

        uc_reg_write(Uc, UC_X86_REG_RAX, &RestoredCtx.Rax);
        uc_reg_write(Uc, UC_X86_REG_RCX, &RestoredCtx.Rcx);
        uc_reg_write(Uc, UC_X86_REG_RDX, &RestoredCtx.Rdx);
        uc_reg_write(Uc, UC_X86_REG_RBX, &RestoredCtx.Rbx);
        uc_reg_write(Uc, UC_X86_REG_RSP, &RestoredCtx.Rsp);
        uc_reg_write(Uc, UC_X86_REG_RBP, &RestoredCtx.Rbp);
        uc_reg_write(Uc, UC_X86_REG_RSI, &RestoredCtx.Rsi);
        uc_reg_write(Uc, UC_X86_REG_RDI, &RestoredCtx.Rdi);
        uc_reg_write(Uc, UC_X86_REG_R8, &RestoredCtx.R8);
        uc_reg_write(Uc, UC_X86_REG_R9, &RestoredCtx.R9);
        uc_reg_write(Uc, UC_X86_REG_R10, &RestoredCtx.R10);
        uc_reg_write(Uc, UC_X86_REG_R11, &RestoredCtx.R11);
        uc_reg_write(Uc, UC_X86_REG_R12, &RestoredCtx.R12);
        uc_reg_write(Uc, UC_X86_REG_R13, &RestoredCtx.R13);
        uc_reg_write(Uc, UC_X86_REG_R14, &RestoredCtx.R14);
        uc_reg_write(Uc, UC_X86_REG_R15, &RestoredCtx.R15);

        uint64_t RestoredRflags = (uint64_t)RestoredCtx.EFlags;
        uc_reg_write(Uc, UC_X86_REG_RFLAGS, &RestoredRflags);

        uint64_t RestoredRip = RestoredCtx.Rip;
        uc_reg_write(Uc, UC_X86_REG_RIP, &RestoredRip);

        return true;
    }

    Logger::Log("{RED}SEH: EXCEPTION_CONTINUE_SEARCH - no further handlers available{RESET}\n");
    uc_reg_write(Uc, UC_X86_REG_RSP, &PendingFilter.OriginalRsp);
    return false;
}

bool SehDispatch::IsPendingFilterDispatch() {
    return PendingFilter.Active;
}
