#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"

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

void UnicornEmu::Hooks::OnSseAlignCheck(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    if (SseFault.Active) return;

    uint8_t Code[16] = {};
    uc_mem_read(Uc, Addr, Code, (Size < 16) ? Size : 16);

    bool MaybeSse = false;
    if (Code[0] == 0x0F && (Code[1] == 0x28 || Code[1] == 0x29 || Code[1] == 0x2B)) MaybeSse = true;
    if (Code[0] == 0x66 && Code[1] == 0x0F) MaybeSse = true;
    if (Code[0] >= 0x40 && Code[0] <= 0x4F) {
        if (Code[1] == 0x0F && (Code[2] == 0x28 || Code[2] == 0x29 || Code[2] == 0x2B)) MaybeSse = true;
        if (Code[1] == 0x66 && Code[2] == 0x0F) MaybeSse = true;
    }

    if (!MaybeSse) return;

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands)))
        return;

    bool RequiresAlignment = false;
    switch (Instr.mnemonic) {
    case ZYDIS_MNEMONIC_MOVAPS:
    case ZYDIS_MNEMONIC_MOVAPD:
    case ZYDIS_MNEMONIC_MOVDQA:
    case ZYDIS_MNEMONIC_MOVNTPS:
    case ZYDIS_MNEMONIC_MOVNTPD:
    case ZYDIS_MNEMONIC_MOVNTDQ:
        RequiresAlignment = true;
        break;
    default:
        break;
    }

    if (!RequiresAlignment) return;

    for (int I = 0; I < Instr.operand_count; I++) {
        if (Operands[I].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t EffAddr = ComputeEffectiveAddress(Uc, &Operands[I], &Instr, Addr);

            if (EffAddr & 0xF) {
                Logger::Log("{RED}SSE alignment fault: %s at RIP=0x%llx addr=0x%llx (misaligned by %llu){RESET}\n",
                    (Instr.mnemonic == ZYDIS_MNEMONIC_MOVAPS) ? "MOVAPS" :
                    (Instr.mnemonic == ZYDIS_MNEMONIC_MOVAPD) ? "MOVAPD" :
                    (Instr.mnemonic == ZYDIS_MNEMONIC_MOVDQA) ? "MOVDQA" : "SSE_ALIGN",
                    Addr, EffAddr, EffAddr & 0xF);

                SseFault.Active = true;
                SseFault.FaultRip = Addr;
                SseFault.MemAddr = EffAddr;
                SseFault.ExceptionCode = STATUS_ACCESS_VIOLATION_EX;

                uc_emu_stop(Uc);
                return;
            }
        }
    }
}

void UnicornEmu::Hooks::OnVmEnter(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    uint8_t Code[16] = {};
    uc_mem_read(Uc, Addr, Code, (Size < 16) ? Size : 16);

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands)))
        return;

    if (Instr.mnemonic != ZYDIS_MNEMONIC_VMLAUNCH &&
        Instr.mnemonic != ZYDIS_MNEMONIC_VMRESUME) {
        return;
    }

    uint64_t Rip = 0;
    uint64_t Rsp = 0;
    uint64_t Rax = 0;
    uint64_t Rcx = 0;
    uint64_t Rdx = 0;

    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);

    const char* Name =
        (Instr.mnemonic == ZYDIS_MNEMONIC_VMLAUNCH) ? "VMLAUNCH" : "VMRESUME";

    Logger::Log("{MAG}[VMENTER] %s at RIP=0x%llx size=%u RSP=0x%llx RAX=0x%llx RCX=0x%llx RDX=0x%llx{RESET}\n",
        Name, Rip, Size, Rsp, Rax, Rcx, Rdx);
}

void UnicornEmu::Hooks::OnVmExit(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    uint8_t Code[16] = {};
    uc_mem_read(Uc, Addr, Code, (Size < 16) ? Size : 16);

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands)))
        return;

    bool IsExitLike = false;

    switch (Instr.mnemonic) {
    case ZYDIS_MNEMONIC_VMCALL:
    case ZYDIS_MNEMONIC_CPUID:
    case ZYDIS_MNEMONIC_HLT:
    case ZYDIS_MNEMONIC_IN:
    case ZYDIS_MNEMONIC_OUT:
    case ZYDIS_MNEMONIC_RDMSR:
    case ZYDIS_MNEMONIC_WRMSR:
    case ZYDIS_MNEMONIC_VMREAD:
    case ZYDIS_MNEMONIC_VMWRITE:
    case ZYDIS_MNEMONIC_VMXOFF:
        IsExitLike = true;
        break;
    default:
        break;
    }

    if (!IsExitLike)
        return;

    uint64_t Rip = 0;
    uint64_t Rsp = 0;
    uint64_t Rax = 0;
    uint64_t Rcx = 0;
    uint64_t Rdx = 0;

    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);

    std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);

    Logger::Log("{YEL}[VMEXIT] exit-like instruction at RIP=0x%llx size=%u: %s{RESET}\n",
        Rip, Size, Disasm.c_str());
    Logger::Log("{YEL}         RSP=0x%llx RAX=0x%llx RCX=0x%llx RDX=0x%llx{RESET}\n",
        Rsp, Rax, Rcx, Rdx);
}

void UnicornEmu::InstallSseAlignCheck(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize) {
    uc_hook Hh;
    uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnSseAlignCheck, nullptr,
        DriverBase, DriverBase + DriverSize - 1);
    Logger::Log("{GRN}SSE alignment check installed: 0x%llx - 0x%llx{RESET}\n",
        DriverBase, DriverBase + DriverSize - 1);
}

static int FocusedTraceCount = 0;
static const int FocusedTraceMax = 30000;

void UnicornEmu::Hooks::OnFocusedTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    FocusedTraceCount++;
    if (FocusedTraceCount > FocusedTraceMax)
        return;

    std::string Disasm = UnicornEmu::DisassembleAt(Uc, Addr);

    uint64_t Rax = 0, Rcx = 0, Rdx = 0, Rbx = 0, Rsi = 0, Rdi = 0, Rsp = 0, Rbp = 0;
    uint64_t R8 = 0, R9 = 0, R10 = 0, R11 = 0, R12 = 0, R13 = 0, R14 = 0, R15 = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
    uc_reg_read(Uc, UC_X86_REG_RBX, &Rbx);
    uc_reg_read(Uc, UC_X86_REG_RSI, &Rsi);
    uc_reg_read(Uc, UC_X86_REG_RDI, &Rdi);
    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
    uc_reg_read(Uc, UC_X86_REG_RBP, &Rbp);
    uc_reg_read(Uc, UC_X86_REG_R8, &R8);
    uc_reg_read(Uc, UC_X86_REG_R9, &R9);
    uc_reg_read(Uc, UC_X86_REG_R10, &R10);
    uc_reg_read(Uc, UC_X86_REG_R11, &R11);
    uc_reg_read(Uc, UC_X86_REG_R12, &R12);
    uc_reg_read(Uc, UC_X86_REG_R13, &R13);
    uc_reg_read(Uc, UC_X86_REG_R14, &R14);
    uc_reg_read(Uc, UC_X86_REG_R15, &R15);

    Logger::Log("{GRY}[FOCUS %d] 0x%llx: %s{RESET}\n", FocusedTraceCount, Addr, Disasm.c_str());
    Logger::Log("{GRY}  RAX=%016llx RCX=%016llx RDX=%016llx RBX=%016llx RSI=%016llx RDI=%016llx{RESET}\n",
        Rax, Rcx, Rdx, Rbx, Rsi, Rdi);
    Logger::Log("{GRY}  RSP=%016llx RBP=%016llx R8=%016llx R9=%016llx R10=%016llx R11=%016llx{RESET}\n",
        Rsp, Rbp, R8, R9, R10, R11);

    if (Addr == DRIVER_BASE_UC + 0x11c93) {
        Logger::Log("{RED}  *** FAULT POINT REACHED *** RSI=0x%llx (reading [RSI+0xE0]=0x%llx){RESET}\n", Rsi, Rsi + 0xE0);
        Logger::Log("{GRY}  R12=%016llx R13=%016llx R14=%016llx R15=%016llx{RESET}\n", R12, R13, R14, R15);

        uint64_t CtxPtr = 0;
        uc_mem_read(Uc, R12 + 0x18, &CtxPtr, 8);
        Logger::Log("{GRY}  [R12+0x18] (ctx ptr) = 0x%016llx{RESET}\n", CtxPtr);
        if (CtxPtr) {
            Logger::Log("{GRY}  Structure at 0x%016llx:{RESET}\n", CtxPtr);
            for (int I = 0; I < 32; I++) {
                uint64_t V = 0;
                uc_mem_read(Uc, CtxPtr + I * 8, &V, 8);
                Logger::Log("{GRY}    [ctx+0x%03x] = 0x%016llx{RESET}\n", I * 8, V);
            }
        }

        Logger::Log("{GRY}  Full R12 context dump (non-zero):{RESET}\n");
        for (int I = 0; I < 80; I++) {
            uint64_t V = 0;
            uc_mem_read(Uc, R12 + I * 8, &V, 8);
            if (V != 0)
                Logger::Log("{GRY}    [R12+0x%03x] = 0x%016llx{RESET}\n", I * 8, V);
        }
    }
}

void UnicornEmu::InstallFocusedTrace(uc_engine* Uc, uint64_t Start, uint64_t End) {
    FocusedTraceCount = 0;
    uc_hook Hh;
    uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnFocusedTrace, nullptr, Start, End);
    Logger::Log("{CYN}Focused trace installed: 0x%llx - 0x%llx{RESET}\n", Start, End);
}

static uint64_t StackWatchBase = 0;
static uint64_t StackWatchSize = 0;
static int StackWriteCount = 0;

void UnicornEmu::Hooks::OnStackWrite(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    if (Addr < StackWatchBase || Addr >= StackWatchBase + StackWatchSize)
        return;

    StackWriteCount++;
    if (StackWriteCount > 10000)
        return;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    uint64_t Offset = Addr - StackWatchBase;
    std::string Disasm = UnicornEmu::DisassembleAt(Uc, Rip);
    Logger::Log("{GRY}[STACK WRITE] addr=0x%llx (watch+0x%llx) size=%d val=0x%llx RIP=0x%llx: %s{RESET}\n",
        Addr, Offset, Size, (uint64_t)Value, Rip, Disasm.c_str());
}

void UnicornEmu::InstallStackWriteWatch(uc_engine* Uc, uint64_t WatchAddr, uint64_t WatchSize) {
    StackWatchBase = WatchAddr;
    StackWatchSize = WatchSize;
    StackWriteCount = 0;

    uint64_t PageStart = WatchAddr & ~0xFFFULL;
    uint64_t PageEnd = ((WatchAddr + WatchSize) + 0xFFF) & ~0xFFFULL;

    uc_hook Hh;
    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_WRITE, (void*)Hooks::OnStackWrite, nullptr,
        PageStart, PageEnd - 1);
    if (Err == UC_ERR_OK) {
        Logger::Log("{CYN}Stack write watchpoint: 0x%llx - 0x%llx (page range 0x%llx - 0x%llx){RESET}\n",
            WatchAddr, WatchAddr + WatchSize - 1, PageStart, PageEnd - 1);
    } else {
        Logger::Log("{RED}Stack write watchpoint failed: %s{RESET}\n", uc_strerror(Err));
    }
}

void UnicornEmu::Hooks::OnDrvObjRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    DrvObjReadCount++;

    if (DrvObjReadCount > 200)
        return;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    uint64_t Offset = Addr - DRIVER_OBJ_BASE_UC;

    if (Offset == 0x28) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverSection read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x18) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverStart read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x08) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DeviceObject read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x20) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverSize read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x30) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverExtension read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x10) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.Flags read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x58) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverInit read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset == 0x68) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.DriverUnload read at RIP=0x%llx{RESET}\n", Rip);
    } else if (Offset >= 0x70 && Offset < 0x70 + 28 * 8) {
        int MjIdx = (int)((Offset - 0x70) / 8);
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT.MajorFunction[%d] read at RIP=0x%llx{RESET}\n", MjIdx, Rip);
    } else if (DrvObjReadCount <= 50) {
        Logger::Log("{GRY}[WATCH] DRIVER_OBJECT+0x%llx read (size=%d) at RIP=0x%llx{RESET}\n", Offset, Size, Rip);
    }
}

void UnicornEmu::Hooks::OnModuleListRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    ModListReadCount++;

    if (ModListReadCount > 50000)
        return;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    for (auto& Entry : UnicornMem::UcToHostMap) {
        uint64_t Base = Entry.first;
        auto SizeIt = UnicornMem::PoolSizes.find(Base);
        if (SizeIt == UnicornMem::PoolSizes.end())
            continue;
        if (Addr >= Base && Addr < Base + SizeIt->second) {
            auto NameIt = UnicornMem::PoolNames.find(Base);
            std::string AllocName = (NameIt != UnicornMem::PoolNames.end()) ? NameIt->second : "unknown";

            if (AllocName.find("KldrEntry") != std::string::npos) {

                uint64_t EntryOffset = Addr - Base;
                const char* FieldName = "unknown";
                if (EntryOffset >= 0x00 && EntryOffset < 0x08) FieldName = "InLoadOrderLinks.Flink";
                else if (EntryOffset >= 0x08 && EntryOffset < 0x10) FieldName = "InLoadOrderLinks.Blink";
                else if (EntryOffset >= 0x10 && EntryOffset < 0x18) FieldName = "ExceptionTable";
                else if (EntryOffset >= 0x18 && EntryOffset < 0x20) FieldName = "ExceptionTableSize";
                else if (EntryOffset >= 0x20 && EntryOffset < 0x28) FieldName = "GpValue";
                else if (EntryOffset >= 0x28 && EntryOffset < 0x30) FieldName = "NonPagedDebugInfo";
                else if (EntryOffset >= 0x30 && EntryOffset < 0x38) FieldName = "DllBase";
                else if (EntryOffset >= 0x38 && EntryOffset < 0x40) FieldName = "EntryPoint";
                else if (EntryOffset >= 0x40 && EntryOffset < 0x48) FieldName = "SizeOfImage";
                else if (EntryOffset >= 0x48 && EntryOffset < 0x58) FieldName = "FullDllName";
                else if (EntryOffset >= 0x58 && EntryOffset < 0x68) FieldName = "BaseDllName";
                else if (EntryOffset >= 0x68 && EntryOffset < 0x6C) FieldName = "Flags";
                else if (EntryOffset >= 0x6C && EntryOffset < 0x6E) FieldName = "LoadCount";
                else if (EntryOffset >= 0x6E && EntryOffset < 0x70) FieldName = "u1(SignatureLevel/Type)";
                else if (EntryOffset >= 0x70 && EntryOffset < 0x78) FieldName = "SectionPointer";
                else if (EntryOffset >= 0x78 && EntryOffset < 0x7C) FieldName = "CheckSum";
                else if (EntryOffset >= 0x7C && EntryOffset < 0x80) FieldName = "CoverageSectionSize";
                else if (EntryOffset >= 0x80 && EntryOffset < 0x88) FieldName = "CoverageSection";
                else if (EntryOffset >= 0x88 && EntryOffset < 0x90) FieldName = "LoadedImports";
                else if (EntryOffset >= 0x90 && EntryOffset < 0x98) FieldName = "Spare";
                else if (EntryOffset >= 0x98 && EntryOffset < 0x9C) FieldName = "SizeOfImageNotRounded";
                else if (EntryOffset >= 0x9C && EntryOffset < 0xA0) FieldName = "TimeDateStamp";

                if (ModListReadCount <= 10000) {
                    Logger::Log("{GRY}[WATCH] LDR walk: %s+0x%llx (%s) read at RIP=0x%llx{RESET}\n",
                        AllocName.c_str(), EntryOffset, FieldName, Rip);
                }
                return;
            }
            break;
        }
    }

    if (ModListReadCount <= 10000) {
        Logger::Log("{GRY}[WATCH] Pool read: 0x%llx (size=%d) at RIP=0x%llx{RESET}\n", Addr, Size, Rip);
    }
}
