#include "core/exec/insn_emulator_internal.h"

bool TryEmulateAvxExt(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip) {
    switch (Instr.mnemonic) {

    case ZYDIS_MNEMONIC_VPSRLDQ: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int H = 0; H < 2; H++) {
            if (Count >= 16) memset(Dst.B + H * 16, 0, 16);
            else {
                memmove(Dst.B + H * 16, Src.B + H * 16 + Count, 16 - Count);
                memset(Dst.B + H * 16 + 16 - Count, 0, Count);
            }
        }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSLLDQ: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int H = 0; H < 2; H++) {
            if (Count >= 16) memset(Dst.B + H * 16, 0, 16);
            else {
                memmove(Dst.B + H * 16 + Count, Src.B + H * 16, 16 - Count);
                memset(Dst.B + H * 16, 0, Count);
            }
        }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSRLW: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = Count >= 16 ? 0 : (((uint16_t*)Src.B)[I] >> Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSLLW: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = Count >= 16 ? 0 : (((uint16_t*)Src.B)[I] << Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSRAW: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        if (Count > 15) Count = 15;
        for (int I = 0; I < 16; I++)
            ((int16_t*)Dst.B)[I] = ((int16_t*)Src.B)[I] >> Count;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSRLD: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = Count >= 32 ? 0 : (((uint32_t*)Src.B)[I] >> Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSLLD: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = Count >= 32 ? 0 : (((uint32_t*)Src.B)[I] << Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSRLQ: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 4; I++)
            ((uint64_t*)Dst.B)[I] = Count >= 64 ? 0 : (((uint64_t*)Src.B)[I] >> Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSLLQ: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Count = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 4; I++)
            ((uint64_t*)Dst.B)[I] = Count >= 64 ? 0 : (((uint64_t*)Src.B)[I] << Count);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VINSERTI128:
    case ZYDIS_MNEMONIC_VINSERTF128: {
        YMM256 Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Dst)) return false;
        XMM128 Src;
        if (!ReadXmmOperand(Uc, Operands[2], Instr, Rip, Src)) return false;
        uint8_t Imm = (uint8_t)Operands[3].imm.value.u & 1;
        memcpy(Dst.B + Imm * 16, &Src, 16);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VEXTRACTI128:
    case ZYDIS_MNEMONIC_VEXTRACTF128: {
        YMM256 Src;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Imm = (uint8_t)Operands[2].imm.value.u & 1;
        XMM128 Half;
        memcpy(&Half, Src.B + Imm * 16, 16);
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (!WriteXmm(Uc, Operands[0].reg.value, Half)) return false;
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            uc_mem_write(Uc, Addr, &Half, 16);
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPBROADCASTB: {
        uint8_t Val = 0;
        if (Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (Operands[1].reg.value >= ZYDIS_REGISTER_XMM0 && Operands[1].reg.value <= ZYDIS_REGISTER_XMM15) {
                XMM128 Src;
                if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
                Val = ((uint8_t*)&Src)[0];
            } else {
                uint64_t Gpr = 0;
                int UcReg = ZydisRegToUcGpr(Operands[1].reg.value);
                if (!UcReg) return false;
                uc_reg_read(Uc, UcReg, &Gpr);
                Val = (uint8_t)Gpr;
            }
        } else if (Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[1], Instr, Rip);
            uc_mem_read(Uc, Addr, &Val, 1);
        } else return false;
        YMM256 Dst;
        memset(Dst.B, Val, 32);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPBROADCASTW: {
        uint16_t Val = 0;
        if (Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            XMM128 Src;
            if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
            Val = ((uint16_t*)&Src)[0];
        } else if (Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[1], Instr, Rip);
            uc_mem_read(Uc, Addr, &Val, 2);
        } else return false;
        YMM256 Dst;
        for (int I = 0; I < 16; I++) ((uint16_t*)Dst.B)[I] = Val;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPBROADCASTD: {
        uint32_t Val = 0;
        if (Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            XMM128 Src;
            if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
            Val = ((uint32_t*)&Src)[0];
        } else if (Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[1], Instr, Rip);
            uc_mem_read(Uc, Addr, &Val, 4);
        } else return false;
        YMM256 Dst;
        for (int I = 0; I < 8; I++) ((uint32_t*)Dst.B)[I] = Val;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPBROADCASTQ: {
        uint64_t Val = 0;
        if (Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            XMM128 Src;
            if (!ReadXmm(Uc, Operands[1].reg.value, Src)) return false;
            Val = ((uint64_t*)&Src)[0];
        } else if (Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            uint64_t Addr = ComputeAddr(Uc, Operands[1], Instr, Rip);
            uc_mem_read(Uc, Addr, &Val, 8);
        } else return false;
        YMM256 Dst;
        for (int I = 0; I < 4; I++) ((uint64_t*)Dst.B)[I] = Val;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPERM2I128:
    case ZYDIS_MNEMONIC_VPERM2F128: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        uint8_t Ctrl = (uint8_t)Operands[3].imm.value.u;
        auto SelectHalf = [&](uint8_t Sel, uint8_t* Out) {
            if ((Sel >> 3) & 1) { memset(Out, 0, 16); return; }
            uint8_t Idx = Sel & 3;
            if (Idx == 0) memcpy(Out, Src1.B, 16);
            else if (Idx == 1) memcpy(Out, Src1.B + 16, 16);
            else if (Idx == 2) memcpy(Out, Src2.B, 16);
            else memcpy(Out, Src2.B + 16, 16);
        };
        SelectHalf(Ctrl & 0x0F, Dst.B);
        SelectHalf((Ctrl >> 4) & 0x0F, Dst.B + 16);
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPERMD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = ((uint32_t*)Src2.B)[((uint32_t*)Src1.B)[I] & 7];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPERMQ: {
        YMM256 Src, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint8_t Ctrl = (uint8_t)Operands[2].imm.value.u;
        for (int I = 0; I < 4; I++)
            ((uint64_t*)Dst.B)[I] = ((uint64_t*)Src.B)[(Ctrl >> (I * 2)) & 3];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    default:
        return false;
    }

    return true;
}
