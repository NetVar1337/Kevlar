#include "core/exec/instruction_emulator.h"
#include "core/exec/insn_emulator_internal.h"
#include "core/exec/unicorn_engine.h"
#include <random>
#include <immintrin.h>
#include <Logger/Logger.h>

static thread_local std::mt19937_64 RandGen{std::random_device{}()};

std::unordered_map<uint64_t, std::vector<uint8_t>> YmmPatchMap;

void InsnEmulator::Initialize() {
    InitCrc32cTable();
}

void InsnEmulator::PatchYmmInstructions(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize) {
    std::vector<uint8_t> Code(DriverSize);
    if (uc_mem_read(Uc, DriverBase, Code.data(), DriverSize) != UC_ERR_OK) return;

    uint64_t Offset = 0;
    int PatchCount = 0;
    while (Offset < DriverSize) {
        size_t Remaining = DriverSize - Offset;
        if (Remaining > 15) Remaining = 15;

        ZydisDecodedInstruction Instr;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus Status = ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code.data() + Offset, Remaining, &Instr, Operands);

        if (!ZYAN_SUCCESS(Status)) {
            Offset++;
            continue;
        }

        bool HasYmm = false;
        for (int I = 0; I < Instr.operand_count_visible; I++) {
            if (Operands[I].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                Operands[I].reg.value >= ZYDIS_REGISTER_YMM0 &&
                Operands[I].reg.value <= ZYDIS_REGISTER_YMM15) {
                HasYmm = true;
                break;
            }
        }

        if (HasYmm && Instr.length >= 2) {
            uint64_t Rip = DriverBase + Offset;
            YmmPatchMap[Rip] = std::vector<uint8_t>(Code.data() + Offset, Code.data() + Offset + Instr.length);
            uint8_t Patch[15] = {};
            Patch[0] = 0x0F;
            Patch[1] = 0x0B;
            for (int I = 2; I < (int)Instr.length; I++) Patch[I] = 0x90;
            uc_mem_write(Uc, Rip, Patch, Instr.length);
            PatchCount++;
        }

        Offset += Instr.length;
    }

    Logger::Log("{CYN}PatchYmmInstructions: patched %d YMM instructions in driver{RESET}\n", PatchCount);
}

bool InsnEmulator::TryEmulate(uc_engine* Uc, uint64_t Rip) {
    uint8_t Code[16] = {};
    auto YmmIt = YmmPatchMap.find(Rip);
    if (YmmIt != YmmPatchMap.end()) {
        size_t CopyLen = YmmIt->second.size();
        if (CopyLen > 16) CopyLen = 16;
        memcpy(Code, YmmIt->second.data(), CopyLen);
    } else {
        if (uc_mem_read(Uc, Rip, Code, 16) != UC_ERR_OK) return false;
    }

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&UnicornEmu::Decoder, Code, 16, &Instr, Operands)))
        return false;

    switch (Instr.mnemonic) {

    case ZYDIS_MNEMONIC_RDRAND: {
        int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
        if (!DstUc) return false;

        uint64_t Val = RandGen();
        int RegSize = Operands[0].size / 8;
        switch (RegSize) {
        case 2: Val &= 0xFFFF; break;
        case 4: Val &= 0xFFFFFFFF; break;
        }
        uc_reg_write(Uc, DstUc, &Val);

        uint64_t Rflags = 0;
        uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Rflags);
        Rflags &= ~((1ULL << 11) | (1ULL << 7) | (1ULL << 6) | (1ULL << 4) | (1ULL << 2));
        Rflags |= 1;
        uc_reg_write(Uc, UC_X86_REG_RFLAGS, &Rflags);
        break;
    }

    case ZYDIS_MNEMONIC_RDSEED: {
        int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
        if (!DstUc) return false;

        uint64_t Val = RandGen();
        int RegSize = Operands[0].size / 8;
        switch (RegSize) {
        case 2: Val &= 0xFFFF; break;
        case 4: Val &= 0xFFFFFFFF; break;
        }
        uc_reg_write(Uc, DstUc, &Val);

        uint64_t Rflags = 0;
        uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Rflags);
        Rflags &= ~((1ULL << 11) | (1ULL << 7) | (1ULL << 6) | (1ULL << 4) | (1ULL << 2));
        Rflags |= 1;
        uc_reg_write(Uc, UC_X86_REG_RFLAGS, &Rflags);
        break;
    }

    case ZYDIS_MNEMONIC_XGETBV: {
        uint64_t Ecx = 0;
        uc_reg_read(Uc, UC_X86_REG_ECX, &Ecx);
        uint64_t Result = 0;
        if ((unsigned int)Ecx == 0) {
            Result = _xgetbv(0);
            Result &= ~0x4ULL;
        }
        uint64_t Eax = Result & 0xFFFFFFFF;
        uint64_t Edx = (Result >> 32) & 0xFFFFFFFF;
        uc_reg_write(Uc, UC_X86_REG_RAX, &Eax);
        uc_reg_write(Uc, UC_X86_REG_RDX, &Edx);
        break;
    }

    case ZYDIS_MNEMONIC_PINSRB: {
        XMM128 Dst;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[1], Instr, Rip, Val, 1)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0xF;
        ((uint8_t*)Dst.L)[Idx] = (uint8_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_PINSRW: {
        XMM128 Dst;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[1], Instr, Rip, Val, 2)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x7;
        ((uint16_t*)Dst.L)[Idx] = (uint16_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_PINSRD: {
        XMM128 Dst;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[1], Instr, Rip, Val, 4)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x3;
        Dst.L[Idx] = (uint32_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_PINSRQ: {
        XMM128 Dst;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[1], Instr, Rip, Val, 8)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x1;
        Dst.L[Idx * 2]     = (uint32_t)Val;
        Dst.L[Idx * 2 + 1] = (uint32_t)(Val >> 32);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_VPINSRB: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[2], Instr, Rip, Val, 1)) return false;
        uint8_t Idx = (uint8_t)Operands[3].imm.value.u & 0xF;
        ((uint8_t*)Src.L)[Idx] = (uint8_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Src);
        break;
    }

    case ZYDIS_MNEMONIC_VPINSRW: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[2], Instr, Rip, Val, 2)) return false;
        uint8_t Idx = (uint8_t)Operands[3].imm.value.u & 0x7;
        ((uint16_t*)Src.L)[Idx] = (uint16_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Src);
        break;
    }

    case ZYDIS_MNEMONIC_VPINSRD: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[2], Instr, Rip, Val, 4)) return false;
        uint8_t Idx = (uint8_t)Operands[3].imm.value.u & 0x3;
        Src.L[Idx] = (uint32_t)Val;
        WriteXmm(Uc, Operands[0].reg.value, Src);
        break;
    }

    case ZYDIS_MNEMONIC_VPINSRQ: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint64_t Val = 0;
        if (!ReadGprOperand(Uc, Operands[2], Instr, Rip, Val, 8)) return false;
        uint8_t Idx = (uint8_t)Operands[3].imm.value.u & 0x1;
        Src.L[Idx * 2]     = (uint32_t)Val;
        Src.L[Idx * 2 + 1] = (uint32_t)(Val >> 32);
        WriteXmm(Uc, Operands[0].reg.value, Src);
        break;
    }

    case ZYDIS_MNEMONIC_PEXTRB: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0xF;
        uint8_t ByteVal = ((uint8_t*)Src.L)[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = ByteVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &ByteVal, 1);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_PEXTRW: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x7;
        uint16_t WordVal = ((uint16_t*)Src.L)[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = WordVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &WordVal, 2);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_PEXTRD: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x3;
        uint32_t DwordVal = Src.L[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = DwordVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &DwordVal, 4);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_PEXTRQ: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x1;
        uint64_t QwordVal = ((uint64_t)Src.L[Idx * 2 + 1] << 32) | Src.L[Idx * 2];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uc_reg_write(Uc, DstUc, &QwordVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &QwordVal, 8);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPEXTRB: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0xF;
        uint8_t ByteVal = ((uint8_t*)Src.L)[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = ByteVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &ByteVal, 1);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPEXTRW: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x7;
        uint16_t WordVal = ((uint16_t*)Src.L)[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = WordVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &WordVal, 2);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPEXTRD: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x3;
        uint32_t DwordVal = Src.L[Idx];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uint64_t WriteVal = DwordVal;
            uc_reg_write(Uc, DstUc, &WriteVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &DwordVal, 4);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPEXTRQ: {
        XMM128 Src;
        if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Idx = (uint8_t)Operands[2].imm.value.u & 0x1;
        uint64_t QwordVal = ((uint64_t)Src.L[Idx * 2 + 1] << 32) | Src.L[Idx * 2];
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
            if (!DstUc) return false;
            uc_reg_write(Uc, DstUc, &QwordVal);
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &QwordVal, 8);
        } else return false;
        break;
    }

    default:
        if (TryEmulateCrypto(Uc, Instr, Operands, Rip))
            break;
        if (TryEmulateAvx(Uc, Instr, Operands, Rip))
            break;
        if (TryEmulateAvxExt(Uc, Instr, Operands, Rip))
            break;
        return false;
    }

    uint64_t NewRip = Rip + Instr.length;
    uc_reg_write(Uc, UC_X86_REG_RIP, &NewRip);
    return true;
}
