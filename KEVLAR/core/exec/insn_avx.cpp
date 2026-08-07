#include "core/exec/insn_emulator_internal.h"

bool TryEmulateAvx(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip) {
    switch (Instr.mnemonic) {

    case ZYDIS_MNEMONIC_VMOVDQU:
    case ZYDIS_MNEMONIC_VMOVDQA:
    case ZYDIS_MNEMONIC_VMOVAPS:
    case ZYDIS_MNEMONIC_VMOVUPS: {
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            Operands[0].reg.value >= ZYDIS_REGISTER_YMM0 && Operands[0].reg.value <= ZYDIS_REGISTER_YMM15) {
            YMM256 Src;
            if (!ReadYmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
            if (!WriteYmm(Uc, Operands[0].reg.value, Src)) return false;
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            YMM256 Src;
            if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
            uint64_t Addr = ComputeAddr(Uc, Operands[0], Instr, Rip);
            if (uc_mem_write(Uc, Addr, &Src, 32) != UC_ERR_OK) return false;
        } else return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPXOR: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] ^ Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPAND: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] & Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPOR: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] | Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPANDN: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = (~Src1.B[I]) & Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPEQB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = (Src1.B[I] == Src2.B[I]) ? 0xFF : 0x00;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPEQW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = (((uint16_t*)Src1.B)[I] == ((uint16_t*)Src2.B)[I]) ? 0xFFFF : 0;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPEQD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = (((uint32_t*)Src1.B)[I] == ((uint32_t*)Src2.B)[I]) ? 0xFFFFFFFF : 0;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPGTB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = ((int8_t)Src1.B[I] > (int8_t)Src2.B[I]) ? 0xFF : 0;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPGTW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = (((int16_t*)Src1.B)[I] > ((int16_t*)Src2.B)[I]) ? 0xFFFF : 0;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPCMPGTD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = (((int32_t*)Src1.B)[I] > ((int32_t*)Src2.B)[I]) ? 0xFFFFFFFF : 0;
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPMOVMSKB: {
        YMM256 Src;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src)) return false;
        uint32_t Mask = 0;
        for (int I = 0; I < 32; I++)
            if (Src.B[I] & 0x80) Mask |= (1u << I);
        int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
        if (!DstUc) return false;
        uint64_t Val = Mask;
        uc_reg_write(Uc, DstUc, &Val);
        break;
    }

    case ZYDIS_MNEMONIC_VPMINUB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] < Src2.B[I] ? Src1.B[I] : Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPMAXUB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] > Src2.B[I] ? Src1.B[I] : Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPALIGNR: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        uint8_t Imm = (uint8_t)Operands[3].imm.value.u;
        for (int H = 0; H < 2; H++) {
            uint8_t Concat[32];
            memcpy(Concat, Src2.B + H * 16, 16);
            memcpy(Concat + 16, Src1.B + H * 16, 16);
            if (Imm >= 16) memset(Dst.B + H * 16, 0, 16);
            else memcpy(Dst.B + H * 16, Concat + Imm, 16);
        }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSHUFB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int H = 0; H < 2; H++)
            for (int I = 0; I < 16; I++) {
                uint8_t Ctrl = Src2.B[H * 16 + I];
                Dst.B[H * 16 + I] = (Ctrl & 0x80) ? 0 : Src1.B[H * 16 + (Ctrl & 0x0F)];
            }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPUNPCKLBW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int H = 0; H < 2; H++)
            for (int I = 0; I < 8; I++) {
                Dst.B[H * 16 + I * 2]     = Src2.B[H * 16 + I];
                Dst.B[H * 16 + I * 2 + 1] = Src1.B[H * 16 + I];
            }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPUNPCKHBW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int H = 0; H < 2; H++)
            for (int I = 0; I < 8; I++) {
                Dst.B[H * 16 + I * 2]     = Src2.B[H * 16 + 8 + I];
                Dst.B[H * 16 + I * 2 + 1] = Src1.B[H * 16 + 8 + I];
            }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPUNPCKLWD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int H = 0; H < 2; H++)
            for (int I = 0; I < 4; I++) {
                ((uint16_t*)Dst.B)[H * 8 + I * 2]     = ((uint16_t*)Src2.B)[H * 8 + I];
                ((uint16_t*)Dst.B)[H * 8 + I * 2 + 1] = ((uint16_t*)Src1.B)[H * 8 + I];
            }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPUNPCKHWD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int H = 0; H < 2; H++)
            for (int I = 0; I < 4; I++) {
                ((uint16_t*)Dst.B)[H * 8 + I * 2]     = ((uint16_t*)Src2.B)[H * 8 + 4 + I];
                ((uint16_t*)Dst.B)[H * 8 + I * 2 + 1] = ((uint16_t*)Src1.B)[H * 8 + 4 + I];
            }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPADDB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] + Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSUBB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) Dst.B[I] = Src1.B[I] - Src2.B[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPADDUSB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) {
            uint16_t Sum = (uint16_t)Src1.B[I] + (uint16_t)Src2.B[I];
            Dst.B[I] = Sum > 255 ? 255 : (uint8_t)Sum;
        }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSUBSB: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 32; I++) {
            int16_t Diff = (int16_t)(int8_t)Src1.B[I] - (int16_t)(int8_t)Src2.B[I];
            Dst.B[I] = (uint8_t)(Diff < -128 ? -128 : (Diff > 127 ? 127 : Diff));
        }
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPADDW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = ((uint16_t*)Src1.B)[I] + ((uint16_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSUBW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = ((uint16_t*)Src1.B)[I] - ((uint16_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPADDD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = ((uint32_t*)Src1.B)[I] + ((uint32_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSUBD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = ((uint32_t*)Src1.B)[I] - ((uint32_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPADDQ: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 4; I++)
            ((uint64_t*)Dst.B)[I] = ((uint64_t*)Src1.B)[I] + ((uint64_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPSUBQ: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 4; I++)
            ((uint64_t*)Dst.B)[I] = ((uint64_t*)Src1.B)[I] - ((uint64_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPMULLD: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 8; I++)
            ((uint32_t*)Dst.B)[I] = ((uint32_t*)Src1.B)[I] * ((uint32_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    case ZYDIS_MNEMONIC_VPMULLW: {
        YMM256 Src1, Src2, Dst;
        if (!ReadYmm(Uc, Operands[1].reg.value, Src1)) return false;
        if (!ReadYmmOperand(Uc, Operands[2], Instr, Rip, Src2)) return false;
        for (int I = 0; I < 16; I++)
            ((uint16_t*)Dst.B)[I] = ((uint16_t*)Src1.B)[I] * ((uint16_t*)Src2.B)[I];
        if (!WriteYmm(Uc, Operands[0].reg.value, Dst)) return false;
        break;
    }

    default:
        return false;
    }

    return true;
}
