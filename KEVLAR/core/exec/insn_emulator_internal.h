#pragma once

#include <unicorn/unicorn.h>
#include <Zydis/Zydis.h>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

struct XMM128 {
    uint32_t L[4];
};

struct YMM256 {
    uint8_t B[32];
};

inline int ZydisRegToUcGpr(ZydisRegister Reg) {
    switch (Reg) {
    case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_RAX: return UC_X86_REG_RAX;
    case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_RCX: return UC_X86_REG_RCX;
    case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_RDX: return UC_X86_REG_RDX;
    case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_RBX: return UC_X86_REG_RBX;
    case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_RSP: return UC_X86_REG_RSP;
    case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_RBP: return UC_X86_REG_RBP;
    case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI: return UC_X86_REG_RSI;
    case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI: return UC_X86_REG_RDI;
    case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8: return UC_X86_REG_R8;
    case ZYDIS_REGISTER_R9B: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9: return UC_X86_REG_R9;
    case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10: return UC_X86_REG_R10;
    case ZYDIS_REGISTER_R11B: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11: return UC_X86_REG_R11;
    case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12: return UC_X86_REG_R12;
    case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13: return UC_X86_REG_R13;
    case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14: return UC_X86_REG_R14;
    case ZYDIS_REGISTER_R15B: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15: return UC_X86_REG_R15;
    default: return 0;
    }
}

inline int ZydisRegToUcXmm(ZydisRegister Reg) {
    if (Reg >= ZYDIS_REGISTER_XMM0 && Reg <= ZYDIS_REGISTER_XMM15)
        return UC_X86_REG_XMM0 + (Reg - ZYDIS_REGISTER_XMM0);
    return 0;
}

inline int ZydisRegToUcYmm(ZydisRegister Reg) {
    if (Reg >= ZYDIS_REGISTER_YMM0 && Reg <= ZYDIS_REGISTER_YMM15)
        return UC_X86_REG_YMM0 + (Reg - ZYDIS_REGISTER_YMM0);
    return 0;
}

inline bool ReadXmm(uc_engine* Uc, ZydisRegister Reg, XMM128& Out) {
    int UcReg = ZydisRegToUcXmm(Reg);
    if (!UcReg) return false;
    return uc_reg_read(Uc, UcReg, &Out) == UC_ERR_OK;
}

inline bool WriteXmm(uc_engine* Uc, ZydisRegister Reg, const XMM128& Val) {
    int UcReg = ZydisRegToUcXmm(Reg);
    if (!UcReg) return false;
    return uc_reg_write(Uc, UcReg, &Val) == UC_ERR_OK;
}

inline bool ReadYmm(uc_engine* Uc, ZydisRegister Reg, YMM256& Out) {
    int UcReg = ZydisRegToUcYmm(Reg);
    if (!UcReg) return false;
    return uc_reg_read(Uc, UcReg, &Out) == UC_ERR_OK;
}

inline bool WriteYmm(uc_engine* Uc, ZydisRegister Reg, const YMM256& Val) {
    int UcReg = ZydisRegToUcYmm(Reg);
    if (!UcReg) return false;
    return uc_reg_write(Uc, UcReg, &Val) == UC_ERR_OK;
}

inline uint64_t ComputeAddr(uc_engine* Uc, const ZydisDecodedOperand& Op, const ZydisDecodedInstruction& Instr, uint64_t InstrAddr) {
    uint64_t BaseVal = 0;
    uint64_t IndexVal = 0;

    if (Op.mem.base != ZYDIS_REGISTER_NONE) {
        if (Op.mem.base == ZYDIS_REGISTER_RIP) {
            BaseVal = InstrAddr + Instr.length;
        } else {
            int UcReg = ZydisRegToUcGpr(Op.mem.base);
            if (UcReg) uc_reg_read(Uc, UcReg, &BaseVal);
        }
    }

    if (Op.mem.index != ZYDIS_REGISTER_NONE) {
        int UcReg = ZydisRegToUcGpr(Op.mem.index);
        if (UcReg) uc_reg_read(Uc, UcReg, &IndexVal);
    }

    int64_t Disp = Op.mem.disp.has_displacement ? Op.mem.disp.value : 0;
    return BaseVal + IndexVal * Op.mem.scale + (uint64_t)Disp;
}

inline bool ReadXmmOperand(uc_engine* Uc, const ZydisDecodedOperand& Op, const ZydisDecodedInstruction& Instr, uint64_t InstrAddr, XMM128& Out) {
    if (Op.type == ZYDIS_OPERAND_TYPE_REGISTER)
        return ReadXmm(Uc, Op.reg.value, Out);
    if (Op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t Addr = ComputeAddr(Uc, Op, Instr, InstrAddr);
        return uc_mem_read(Uc, Addr, &Out, 16) == UC_ERR_OK;
    }
    return false;
}

inline bool ReadGprOperand(uc_engine* Uc, const ZydisDecodedOperand& Op, const ZydisDecodedInstruction& Instr, uint64_t InstrAddr, uint64_t& Out, int Size) {
    if (Op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int UcReg = ZydisRegToUcGpr(Op.reg.value);
        if (!UcReg) return false;
        Out = 0;
        uc_reg_read(Uc, UcReg, &Out);
        switch (Size) {
        case 1: Out &= 0xFF; break;
        case 2: Out &= 0xFFFF; break;
        case 4: Out &= 0xFFFFFFFF; break;
        }
        return true;
    }
    if (Op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t Addr = ComputeAddr(Uc, Op, Instr, InstrAddr);
        Out = 0;
        return uc_mem_read(Uc, Addr, &Out, Size) == UC_ERR_OK;
    }
    return false;
}

inline bool ReadYmmOperand(uc_engine* Uc, const ZydisDecodedOperand& Op, const ZydisDecodedInstruction& Instr, uint64_t InstrAddr, YMM256& Out) {
    if (Op.type == ZYDIS_OPERAND_TYPE_REGISTER)
        return ReadYmm(Uc, Op.reg.value, Out);
    if (Op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t Addr = ComputeAddr(Uc, Op, Instr, InstrAddr);
        return uc_mem_read(Uc, Addr, &Out, 32) == UC_ERR_OK;
    }
    return false;
}

void InitCrc32cTable();

extern std::unordered_map<uint64_t, std::vector<uint8_t>> YmmPatchMap;

bool TryEmulateCrypto(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip);
bool TryEmulateAvx(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip);
bool TryEmulateAvxExt(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip);
