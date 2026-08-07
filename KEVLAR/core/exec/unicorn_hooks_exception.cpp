#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"
#include "core/exec/instruction_emulator.h"
#include "core/diagnostics/diag_center.h"

int TotalInterruptCount = 0;
int InterruptCounts[256] = {};

bool UnicornEmu::Hooks::OnMemReadUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    uint64_t PageAddr = Addr & ~0xFFFULL;

    static uint64_t UnmappedReadCount = 0;
    static uint64_t SysModRangeReadCount = 0;
    UnmappedReadCount++;
    if (Addr >= SYSMOD_BASE_UC && Addr < SYSMOD_BASE_UC + 0x100000000ULL) {
        SysModRangeReadCount++;
        if (SysModRangeReadCount <= 20) {
            uint64_t Rip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
            uint64_t DrvRva = (Rip >= DRIVER_BASE_UC) ? Rip - DRIVER_BASE_UC : Rip;
            Logger::Log("{YEL}[UNMAPPED READ] sysmod-range addr=0x%llx size=%d caller=drv+0x%llx{RESET}\n", Addr, Size, DrvRva);
        }
    }
    if (UnmappedReadCount % 50000 == 0) {
        Logger::Log("{CYN}[UNMAPPED READS] total=%llu sysmod_range=%llu{RESET}\n", UnmappedReadCount, SysModRangeReadCount);
    }

    uint64_t AllocBase = 0;
    void* AllocHost = nullptr;
    uint64_t AllocSize = 0;
    if (UnicornMem::FindAllocation(Addr, AllocBase, AllocHost, AllocSize)) {
        uint64_t PageOffset = PageAddr - AllocBase;
        void* HostPage = (uint8_t*)AllocHost + PageOffset;
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, PageAddr, 0x1000, UC_PROT_ALL, HostPage);
        if (Err == UC_ERR_OK) {
            return true;
        }
    }

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    if (PageAddr >= KUSD_BASE_UC && PageAddr < KUSD_BASE_UC + 0x1000) {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        if (KusdBlock) {
            uc_mem_map_ptr(Uc, KUSD_BASE_UC, 0x1000, UC_PROT_READ, KusdBlock);
        } else {
            uc_mem_map(Uc, PageAddr, 0x1000, UC_PROT_READ);
            uc_mem_write(Uc, KUSD_BASE_UC, (void*)0x7FFE0000, 0x1000);
        }
        Logger::Log("{BLU}READ UNMAPPED: lazily mapped KUSER_SHARED_DATA at {WHT}0x%llx {GRY}(RIP=0x%llx){RESET}\n", Addr, Rip);
        return true;
    }

    if (PageAddr >= HYPERSPACE_BASE_UC && PageAddr < HYPERSPACE_BASE_UC + HYPERSPACE_SIZE_UC && HyperspaceBlock) {
        uint64_t PageOffset = PageAddr - HYPERSPACE_BASE_UC;
        void* HostPage = (uint8_t*)HyperspaceBlock + PageOffset;
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, PageAddr, 0x1000, UC_PROT_ALL, HostPage);
        if (Err == UC_ERR_OK) {
            if (DiagnosticHooksEnabled)
                Logger::Log("{BLU}READ UNMAPPED: {WHT}0x%llx {GRY}(RIP=0x%llx) {BLU}-> hyperspace page map{RESET}\n", Addr, Rip);
            return true;
        }
    }

    if (Addr < 0x10000) {
        Logger::Log("{RED}READ UNMAPPED LOW: {WHT}0x%llx {GRY}(size=%d RIP=0x%llx) {RED}possible null deref{RESET}\n", Addr, Size, Rip);
        std::string Disasm = UnicornEmu::DisassembleAt(Uc, Rip);
        Logger::Log("  {GRY}Instruction: %s{RESET}\n", Disasm.c_str());

        uint64_t Rax = 0, Rcx = 0, Rdx = 0, Rbx = 0, Rsi = 0, Rdi = 0, Rsp = 0, Rbp = 0, R8 = 0, R9 = 0, R10 = 0, R11 = 0, R12 = 0, R13 = 0, R14 = 0, R15 = 0;
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
        Logger::Log("{GRY}  RAX=%016llx RCX=%016llx RDX=%016llx RBX=%016llx{RESET}\n", Rax, Rcx, Rdx, Rbx);
        Logger::Log("{GRY}  RSI=%016llx RDI=%016llx RSP=%016llx RBP=%016llx{RESET}\n", Rsi, Rdi, Rsp, Rbp);
        Logger::Log("{GRY}  R8 =%016llx R9 =%016llx R10=%016llx R11=%016llx{RESET}\n", R8, R9, R10, R11);
        Logger::Log("{GRY}  R12=%016llx R13=%016llx R14=%016llx R15=%016llx{RESET}\n", R12, R13, R14, R15);

        Logger::Log("{GRY}  Stack walk:{RESET}\n");
        for (int I = 0; I < 16; I++) {
            uint64_t StackVal = 0;
            uc_mem_read(Uc, Rsp + I * 8, &StackVal, 8);
            const char* Tag = "";
            if (StackVal >= DRIVER_BASE_UC && StackVal < DRIVER_BASE_UC + 0x10000000ULL)
                Tag = " [DRIVER]";
            else if (StackVal >= SYSMOD_BASE_UC && StackVal < SYSMOD_BASE_UC + 0x100000000ULL)
                Tag = " [SYSMOD]";
            else if (StackVal == SENTINEL_RET_ADDR)
                Tag = " [SENTINEL_RET]";
            Logger::Log("{GRY}  [RSP+0x%02x] = {WHT}0x%016llx%s{RESET}\n", I * 8, StackVal, Tag);
        }

        if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Addr)) {
            Logger::Log("{CYN}READ UNMAPPED LOW: SEH accepted fault 0x%llx and resumed control flow{RESET}\n", Addr);
            return true;
        }

        Logger::Log("{RED}READ UNMAPPED LOW: no SEH handler for 0x%llx{RESET}\n", Addr);
        return false;
    }

    if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Addr)) {
        if (DiagnosticHooksEnabled)
            Logger::Log("{CYN}READ UNMAPPED: SEH accepted fault at 0x%llx{RESET}\n", Addr);
        return true;
    }

    if (DiagnosticHooksEnabled)
        Logger::Log("{BLU}READ UNMAPPED: {WHT}0x%llx {GRY}(size=%d RIP=0x%llx) {BLU}-> lazy mapping zero page{RESET}\n", Addr, Size, Rip);
    {
        if (DIAG_IS_ENABLED()) {
            UnmappedReadEvent Ev = {};
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
            Ev.FaultAddress = Addr;
            Ev.Size = (uint32_t)Size;
            Ev.CandidateBase4k = Addr & ~0xFFFULL;
            Ev.CandidateBase64k = Addr & ~0xFFFFULL;
            Ev.Offset4k = (uint32_t)(Addr & 0xFFF);
            Ev.Offset64k = (uint32_t)(Addr & 0xFFFF);
            Ev.Hint = (DiagProbeType)DiagCenter::Instance().ComputePeProbeHint(Addr);
            Ev.LazyMapped = 1;
            Ev.HasHandler = 0;
            DiagCenter::Instance().ResolveVaToRegionName(Addr, Ev.RegionName, sizeof(Ev.RegionName));
            DIAG_UNMAPPED_READ(Ev);
        }
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_mem_map(Uc, PageAddr, 0x1000, UC_PROT_ALL);
    }
    return true;
}

static void CorrectFaultRip(uc_engine* Uc, uint32_t IntNo) {
    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    if (IntNo == 0x00) {
        uint8_t Code[16] = {};
        uc_mem_read(Uc, Rip, Code, 16);

        ZydisDecodedInstruction Instr;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands))) {
            if (Instr.mnemonic == ZYDIS_MNEMONIC_DIV || Instr.mnemonic == ZYDIS_MNEMONIC_IDIV) {
                return;
            }
        }

        for (int Offset = 1; Offset <= 15; Offset++) {
            uint64_t TryAddr = Rip - Offset;
            uint8_t TryCode[16] = {};
            uc_mem_read(Uc, TryAddr, TryCode, 16);

            ZydisDecodedInstruction TryInstr;
            ZydisDecodedOperand TryOps[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, TryCode, 16, &TryInstr, TryOps))) {
                if ((TryInstr.mnemonic == ZYDIS_MNEMONIC_DIV || TryInstr.mnemonic == ZYDIS_MNEMONIC_IDIV) &&
                    TryAddr + TryInstr.length == Rip) {
                    Logger::Log("{CYN}  RIP corrected: 0x%llx -> 0x%llx (fault semantics for #DE){RESET}\n", Rip, TryAddr);
                    uc_reg_write(Uc, UC_X86_REG_RIP, &TryAddr);
                    return;
                }
            }
        }

        Logger::Log("{YEL}  #DE RIP correction: could not find DIV/IDIV before 0x%llx{RESET}\n", Rip);
    }

    if (IntNo == 0x06) {
        uint8_t Code[16] = {};
        uc_mem_read(Uc, Rip, Code, 16);

        ZydisDecodedInstruction Instr;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands))) {
            return;
        }

        for (int Offset = 1; Offset <= 15; Offset++) {
            uint64_t TryAddr = Rip - Offset;
            uint8_t TryCode[16] = {};
            uc_mem_read(Uc, TryAddr, TryCode, 16);

            ZydisDecodedInstruction TryInstr;
            ZydisDecodedOperand TryOps[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, TryCode, 16, &TryInstr, TryOps))) {
                if (TryAddr + 2 == Rip || TryAddr + 3 == Rip || TryAddr + 1 == Rip) {
                    Logger::Log("{CYN}  RIP corrected: 0x%llx -> 0x%llx (fault semantics for #UD){RESET}\n", Rip, TryAddr);
                    uc_reg_write(Uc, UC_X86_REG_RIP, &TryAddr);
                    return;
                }
            }
        }
    }

    if (IntNo == 0x0D) {
        uint8_t Code[16] = {};
        uc_mem_read(Uc, Rip, Code, 16);

        ZydisDecodedInstruction Instr;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands))) {
            bool IsSseAlign = (Instr.mnemonic == ZYDIS_MNEMONIC_MOVAPS || Instr.mnemonic == ZYDIS_MNEMONIC_MOVAPD ||
                               Instr.mnemonic == ZYDIS_MNEMONIC_MOVDQA || Instr.mnemonic == ZYDIS_MNEMONIC_MOVNTPS ||
                               Instr.mnemonic == ZYDIS_MNEMONIC_MOVNTPD || Instr.mnemonic == ZYDIS_MNEMONIC_MOVNTDQ);
            if (IsSseAlign) return;
        }

        for (int Offset = 1; Offset <= 15; Offset++) {
            uint64_t TryAddr = Rip - Offset;
            uint8_t TryCode[16] = {};
            uc_mem_read(Uc, TryAddr, TryCode, 16);

            ZydisDecodedInstruction TryInstr;
            ZydisDecodedOperand TryOps[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, TryCode, 16, &TryInstr, TryOps))) {
                if (TryAddr + TryInstr.length == Rip) {
                    Logger::Log("{CYN}  RIP corrected: 0x%llx -> 0x%llx (fault semantics for #GP){RESET}\n", Rip, TryAddr);
                    uc_reg_write(Uc, UC_X86_REG_RIP, &TryAddr);
                    return;
                }
            }
        }
    }
}

void UnicornEmu::Hooks::OnInterrupt(uc_engine* Uc, uint32_t IntNo, void* UserData) {
    TotalInterruptCount++;
    if (IntNo < 256) InterruptCounts[IntNo]++;

    if (IntNo == 0x20) {
        return;
    }

    if (IntNo == 3) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

        if (SehDispatch::IsPendingFilterDispatch() &&
            Rip >= EXCEPTION_TRAMPOLINE_UC && Rip <= EXCEPTION_TRAMPOLINE_UC + 4) {
            if (SehDispatch::CompleteFilterDispatch(Uc)) return;
            Logger::Log("{RED}Filter dispatch failed - stopping{RESET}\n");
            uc_emu_stop(Uc);
            return;
        }

        uint64_t FaultRip = Rip - 1;
        uc_reg_write(Uc, UC_X86_REG_RIP, &FaultRip);

        static int Int3DispatchCount = 0;
        Int3DispatchCount++;
        if (Int3DispatchCount <= 20 || (Int3DispatchCount % 100000) == 0) {
            Logger::Log("{MAG}[INT 3] #%d breakpoint at RIP=0x%llx - SEH dispatch{RESET}\n", Int3DispatchCount, FaultRip);
        }

        if (SehDispatch::DispatchException(Uc, STATUS_BREAKPOINT_EX)) return;

        uc_reg_write(Uc, UC_X86_REG_RIP, &Rip);
        if (Int3DispatchCount <= 20) {
            Logger::Log("{YEL}INT3 unhandled at 0x%llx - skipping{RESET}\n", FaultRip);
        }
        return;
    }

    if (IntNo == 1) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

        static int Int1Count = 0;
        Int1Count++;
        if (Int1Count <= 20) {
            Logger::Log("{MAG}[INT 1] #%d single-step trap at RIP=0x%llx{RESET}\n", Int1Count, Rip);
        }

        uint64_t Rflags = 0;
        uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Rflags);

        if (SehDispatch::DispatchException(Uc, STATUS_SINGLE_STEP_EX)) {
            uint64_t NewRflags = 0;
            uc_reg_read(Uc, UC_X86_REG_RFLAGS, &NewRflags);
            NewRflags &= ~0x100ULL;
            uc_reg_write(Uc, UC_X86_REG_RFLAGS, &NewRflags);
            return;
        }

        Rflags &= ~0x100ULL;
        uc_reg_write(Uc, UC_X86_REG_RFLAGS, &Rflags);
        return;
    }

    if (IntNo == 0x29) {
        uint64_t Rcx = 0, Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{MAG}__fastfail (INT 29h) code=0x%llx RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rcx, Rip);
        if (SehDispatch::DispatchException(Uc, SehDispatch::IntNoToExceptionCode(IntNo))) return;
        Logger::Log("{YEL}__fastfail unhandled - skipping INT 29h (2 bytes){RESET}\n");
        Rip += 2;
        uc_reg_write(Uc, UC_X86_REG_RIP, &Rip);
        return;
    }

    if (IntNo == 0x2C) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{MAG}Assertion (INT 2Ch) at RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rip);
        if (SehDispatch::DispatchException(Uc, STATUS_ASSERTION_FAILURE)) return;
        Logger::Log("{RED}INT 2Ch unhandled - stopping{RESET}\n");
        uc_emu_stop(Uc);
        return;
    }

    if (IntNo == 0x00) {
        CorrectFaultRip(Uc, IntNo);
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{MAG}Divide by zero (INT 0) at RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rip);
        if (SehDispatch::DispatchException(Uc, STATUS_INTEGER_DIVIDE_BY_ZERO)) return;

        uint8_t DivCode[16] = {};
        uc_mem_read(Uc, Rip, DivCode, 16);
        ZydisDecodedInstruction DivInstr;
        ZydisDecodedOperand DivOps[ZYDIS_MAX_OPERAND_COUNT];
        uint8_t InstrLen = 2;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, DivCode, 16, &DivInstr, DivOps))) {
            InstrLen = DivInstr.length;
        }
        uint64_t SkipRip = Rip + InstrLen;
        uint64_t Zero = 0;
        uc_reg_write(Uc, UC_X86_REG_RAX, &Zero);
        uc_reg_write(Uc, UC_X86_REG_RDX, &Zero);
        uc_reg_write(Uc, UC_X86_REG_RIP, &SkipRip);
        Logger::Log("{YEL}Divide by zero unhandled - skipping DIV/IDIV (%u bytes) RIP=0x%llx{RESET}\n", InstrLen, SkipRip);
        return;
    }

    if (IntNo == 6) {
        CorrectFaultRip(Uc, IntNo);
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        if (InsnEmulator::TryEmulate(Uc, Rip)) return;
        Logger::Log("{MAG}Invalid opcode (INT 6) at RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rip);
        std::string Disasm = UnicornEmu::DisassembleAt(Uc, Rip);
        Logger::Log("{GRY}Instruction: %s{RESET}\n", Disasm.c_str());
        if (SehDispatch::DispatchException(Uc, STATUS_ILLEGAL_INSTRUCTION_EX)) return;
        Logger::Log("{RED}Invalid opcode unhandled - stopping{RESET}\n");
        uc_emu_stop(Uc);
        return;
    }

    if (IntNo == 0xD) {
        CorrectFaultRip(Uc, IntNo);
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{MAG}GPF (INT 0Dh) at RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rip);
        if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX)) return;
        Logger::Log("{RED}GPF unhandled - stopping{RESET}\n");
        uc_emu_stop(Uc);
        return;
    }

    if (IntNo == 0xE) {
        uint64_t Rip = 0;
        uint64_t Cr2 = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        uc_reg_read(Uc, UC_X86_REG_CR2, &Cr2);
        Logger::Log("{MAG}Page fault (INT 0Eh) at RIP=0x%llx CR2=0x%llx - attempting SEH dispatch{RESET}\n", Rip, Cr2);
        if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Cr2)) return;
        Logger::Log("{RED}Page fault unhandled - stopping{RESET}\n");
        uc_emu_stop(Uc);
        return;
    }

    if (IntNo == 0x11) {
        CorrectFaultRip(Uc, IntNo);
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{MAG}Alignment check (INT 11h) at RIP=0x%llx - attempting SEH dispatch{RESET}\n", Rip);
        if (SehDispatch::DispatchException(Uc, STATUS_DATATYPE_MISALIGNMENT)) return;
        Logger::Log("{RED}Alignment check unhandled - stopping{RESET}\n");
        uc_emu_stop(Uc);
        return;
    }

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
    Logger::Log("{MAG}Interrupt 0x%x at RIP=0x%llx - attempting SEH dispatch{RESET}\n", IntNo, Rip);
    uint32_t ExCode = SehDispatch::IntNoToExceptionCode(IntNo);
    if (SehDispatch::DispatchException(Uc, ExCode)) return;
    Logger::Log("{YEL}Unhandled interrupt: 0x%x at RIP=0x%llx{RESET}\n", IntNo, Rip);
}

void UnicornEmu::Hooks::OnSyscall(uc_engine* Uc, void* UserData) {
    uint64_t Rax = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    Logger::Log("{YEL}SYSCALL #%llu at RIP=0x%llx - returning STATUS_NOT_SUPPORTED{RESET}\n", Rax, Rip);

    Rax = 0xC00000BB;
    uc_reg_write(Uc, UC_X86_REG_RAX, &Rax);

    uint64_t R11 = 0;
    uc_reg_read(Uc, UC_X86_REG_RFLAGS, &R11);
    uc_reg_write(Uc, UC_X86_REG_R11, &R11);

    uint64_t Rcx = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rcx);
    Rcx += 2;
    uc_reg_write(Uc, UC_X86_REG_RCX, &Rcx);
}

uint32_t UnicornEmu::Hooks::OnIn(uc_engine* Uc, uint32_t Port, int Size, void* UserData) {
    Logger::Log("{GRY}IN port=0x%x size=%d{RESET}\n", Port, Size);

    if (Port == 0x5658 || Port == 0x5659) {
        return 0;
    }

    return 0;
}

void UnicornEmu::Hooks::OnOut(uc_engine* Uc, uint32_t Port, int Size, uint32_t Value, void* UserData) {
    Logger::Log("{GRY}OUT port=0x%x size=%d val=0x%x{RESET}\n", Port, Size, Value);
}
