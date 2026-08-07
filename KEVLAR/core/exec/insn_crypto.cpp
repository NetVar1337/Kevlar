#include "core/exec/insn_emulator_internal.h"

static uint32_t Rol32(uint32_t X, int N) { return (X << N) | (X >> (32 - N)); }
static uint32_t Ror32(uint32_t X, int N) { return (X >> N) | (X << (32 - N)); }

static uint32_t Sha1Ch(uint32_t B, uint32_t C, uint32_t D) { return (B & C) ^ (~B & D); }
static uint32_t Sha1Parity(uint32_t B, uint32_t C, uint32_t D) { return B ^ C ^ D; }
static uint32_t Sha1Maj(uint32_t B, uint32_t C, uint32_t D) { return (B & C) ^ (B & D) ^ (C & D); }

static uint32_t Sha256Ch(uint32_t E, uint32_t F, uint32_t G) { return (E & F) ^ (~E & G); }
static uint32_t Sha256Maj(uint32_t A, uint32_t B, uint32_t C) { return (A & B) ^ (A & C) ^ (B & C); }
static uint32_t Sha256Sigma0(uint32_t A) { return Ror32(A, 2) ^ Ror32(A, 13) ^ Ror32(A, 22); }
static uint32_t Sha256Sigma1(uint32_t E) { return Ror32(E, 6) ^ Ror32(E, 11) ^ Ror32(E, 25); }
static uint32_t Sha256SmSigma0(uint32_t X) { return Ror32(X, 7) ^ Ror32(X, 18) ^ (X >> 3); }
static uint32_t Sha256SmSigma1(uint32_t X) { return Ror32(X, 17) ^ Ror32(X, 19) ^ (X >> 10); }

static uint8_t AesXtime(uint8_t X) { return (uint8_t)((X << 1) ^ ((X & 0x80) ? 0x1B : 0)); }

static uint8_t AesMul(uint8_t A, uint8_t B) {
    uint8_t R = 0;
    uint8_t T = A;
    for (int I = 0; I < 8; I++) {
        if (B & (1 << I)) R ^= T;
        T = AesXtime(T);
    }
    return R;
}

static const uint8_t AesSbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
};

static const uint8_t AesInvSbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D,
};

static uint32_t Crc32cTable[256];

void InitCrc32cTable() {
    for (uint32_t I = 0; I < 256; I++) {
        uint32_t Crc = I;
        for (int J = 0; J < 8; J++) {
            if (Crc & 1) Crc = (Crc >> 1) ^ 0x82F63B78;
            else Crc >>= 1;
        }
        Crc32cTable[I] = Crc;
    }
}

static void EmSha1Rnds4(XMM128& Dst, const XMM128& Src, uint8_t Fn) {
    uint32_t A = Dst.L[3], B = Dst.L[2], C = Dst.L[1], D = Dst.L[0];
    uint32_t E = 0;

    for (int I = 3; I >= 0; I--) {
        uint32_t F, K;
        switch (Fn & 3) {
        case 0: F = Sha1Ch(B, C, D);     K = 0x5A827999; break;
        case 1: F = Sha1Parity(B, C, D); K = 0x6ED9EBA1; break;
        case 2: F = Sha1Maj(B, C, D);    K = 0x8F1BBCDC; break;
        case 3: F = Sha1Parity(B, C, D); K = 0xCA62C1D6; break;
        }
        uint32_t T = Rol32(A, 5) + F + E + Src.L[I] + K;
        E = D;
        D = C;
        C = Rol32(B, 30);
        B = A;
        A = T;
    }

    Dst.L[3] = A;
    Dst.L[2] = B;
    Dst.L[1] = C;
    Dst.L[0] = D;
}

static void EmSha1Nexte(XMM128& Dst, const XMM128& Src) {
    Dst.L[3] = Src.L[3] + Rol32(Dst.L[3], 30);
    Dst.L[2] = Src.L[2];
    Dst.L[1] = Src.L[1];
    Dst.L[0] = Src.L[0];
}

static void EmSha1Msg1(XMM128& Dst, const XMM128& Src) {
    Dst.L[3] ^= Dst.L[1];
    Dst.L[2] ^= Dst.L[0];
    Dst.L[1] ^= Src.L[3];
    Dst.L[0] ^= Src.L[2];
}

static void EmSha1Msg2(XMM128& Dst, const XMM128& Src) {
    Dst.L[3] = Rol32(Dst.L[3] ^ Src.L[2], 1);
    Dst.L[2] = Rol32(Dst.L[2] ^ Src.L[1], 1);
    Dst.L[1] = Rol32(Dst.L[1] ^ Src.L[0], 1);
    Dst.L[0] = Rol32(Dst.L[0] ^ Dst.L[3], 1);
}

static void EmSha256Rnds2(XMM128& Dst, const XMM128& Src, const XMM128& Wk) {
    uint32_t A = Dst.L[3], B = Dst.L[2];
    uint32_t E = Dst.L[1], F = Dst.L[0];
    uint32_t C = Src.L[3], D = Src.L[2];
    uint32_t G = Src.L[1], H = Src.L[0];

    for (int I = 0; I < 2; I++) {
        uint32_t T1 = H + Sha256Sigma1(E) + Sha256Ch(E, F, G) + Wk.L[I];
        uint32_t T2 = Sha256Sigma0(A) + Sha256Maj(A, B, C);
        H = G; G = F; F = E; E = D + T1;
        D = C; C = B; B = A; A = T1 + T2;
    }

    Dst.L[3] = A;
    Dst.L[2] = B;
    Dst.L[1] = E;
    Dst.L[0] = F;
}

static void EmSha256Msg1(XMM128& Dst, const XMM128& Src) {
    Dst.L[0] += Sha256SmSigma0(Dst.L[1]);
    Dst.L[1] += Sha256SmSigma0(Dst.L[2]);
    Dst.L[2] += Sha256SmSigma0(Dst.L[3]);
    Dst.L[3] += Sha256SmSigma0(Src.L[0]);
}

static void EmSha256Msg2(XMM128& Dst, const XMM128& Src) {
    Dst.L[0] += Sha256SmSigma1(Src.L[2]);
    Dst.L[1] += Sha256SmSigma1(Src.L[3]);
    Dst.L[2] += Sha256SmSigma1(Dst.L[0]);
    Dst.L[3] += Sha256SmSigma1(Dst.L[1]);
}

static void AesSubBytes(uint8_t State[16]) {
    for (int I = 0; I < 16; I++) State[I] = AesSbox[State[I]];
}
static void AesInvSubBytes(uint8_t State[16]) {
    for (int I = 0; I < 16; I++) State[I] = AesInvSbox[State[I]];
}

static void AesShiftRows(uint8_t S[16]) {
    uint8_t T;
    T = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = T;
    T = S[2]; S[2] = S[10]; S[10] = T; T = S[6]; S[6] = S[14]; S[14] = T;
    T = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = T;
}
static void AesInvShiftRows(uint8_t S[16]) {
    uint8_t T;
    T = S[13]; S[13] = S[9]; S[9] = S[5]; S[5] = S[1]; S[1] = T;
    T = S[2]; S[2] = S[10]; S[10] = T; T = S[6]; S[6] = S[14]; S[14] = T;
    T = S[3]; S[3] = S[7]; S[7] = S[11]; S[11] = S[15]; S[15] = T;
}

static void AesMixColumns(uint8_t S[16]) {
    for (int C = 0; C < 4; C++) {
        int I = C * 4;
        uint8_t A0 = S[I], A1 = S[I+1], A2 = S[I+2], A3 = S[I+3];
        S[I]   = AesMul(A0, 2) ^ AesMul(A1, 3) ^ A2 ^ A3;
        S[I+1] = A0 ^ AesMul(A1, 2) ^ AesMul(A2, 3) ^ A3;
        S[I+2] = A0 ^ A1 ^ AesMul(A2, 2) ^ AesMul(A3, 3);
        S[I+3] = AesMul(A0, 3) ^ A1 ^ A2 ^ AesMul(A3, 2);
    }
}
static void AesInvMixColumns(uint8_t S[16]) {
    for (int C = 0; C < 4; C++) {
        int I = C * 4;
        uint8_t A0 = S[I], A1 = S[I+1], A2 = S[I+2], A3 = S[I+3];
        S[I]   = AesMul(A0, 14) ^ AesMul(A1, 11) ^ AesMul(A2, 13) ^ AesMul(A3, 9);
        S[I+1] = AesMul(A0, 9) ^ AesMul(A1, 14) ^ AesMul(A2, 11) ^ AesMul(A3, 13);
        S[I+2] = AesMul(A0, 13) ^ AesMul(A1, 9) ^ AesMul(A2, 14) ^ AesMul(A3, 11);
        S[I+3] = AesMul(A0, 11) ^ AesMul(A1, 13) ^ AesMul(A2, 9) ^ AesMul(A3, 14);
    }
}

static void EmAesEnc(XMM128& State, const XMM128& RoundKey) {
    uint8_t S[16];
    memcpy(S, &State, 16);
    AesShiftRows(S);
    AesSubBytes(S);
    AesMixColumns(S);
    for (int I = 0; I < 16; I++) S[I] ^= ((uint8_t*)&RoundKey)[I];
    memcpy(&State, S, 16);
}
static void EmAesEncLast(XMM128& State, const XMM128& RoundKey) {
    uint8_t S[16];
    memcpy(S, &State, 16);
    AesShiftRows(S);
    AesSubBytes(S);
    for (int I = 0; I < 16; I++) S[I] ^= ((uint8_t*)&RoundKey)[I];
    memcpy(&State, S, 16);
}

static void EmAesDec(XMM128& State, const XMM128& RoundKey) {
    uint8_t S[16];
    memcpy(S, &State, 16);
    AesInvShiftRows(S);
    AesInvSubBytes(S);
    AesInvMixColumns(S);
    for (int I = 0; I < 16; I++) S[I] ^= ((uint8_t*)&RoundKey)[I];
    memcpy(&State, S, 16);
}
static void EmAesDecLast(XMM128& State, const XMM128& RoundKey) {
    uint8_t S[16];
    memcpy(S, &State, 16);
    AesInvShiftRows(S);
    AesInvSubBytes(S);
    for (int I = 0; I < 16; I++) S[I] ^= ((uint8_t*)&RoundKey)[I];
    memcpy(&State, S, 16);
}

static void EmAesImc(XMM128& Dst, const XMM128& Src) {
    uint8_t S[16];
    memcpy(S, &Src, 16);
    AesInvMixColumns(S);
    memcpy(&Dst, S, 16);
}

static void EmAesKeygenAssist(XMM128& Dst, const XMM128& Src, uint8_t Rcon) {
    uint32_t X1 = Src.L[1];
    uint32_t X3 = Src.L[3];

    uint32_t SubX1 = (uint32_t)AesSbox[X1 & 0xFF] |
                     ((uint32_t)AesSbox[(X1 >> 8) & 0xFF] << 8) |
                     ((uint32_t)AesSbox[(X1 >> 16) & 0xFF] << 16) |
                     ((uint32_t)AesSbox[(X1 >> 24) & 0xFF] << 24);

    uint32_t SubX3 = (uint32_t)AesSbox[X3 & 0xFF] |
                     ((uint32_t)AesSbox[(X3 >> 8) & 0xFF] << 8) |
                     ((uint32_t)AesSbox[(X3 >> 16) & 0xFF] << 16) |
                     ((uint32_t)AesSbox[(X3 >> 24) & 0xFF] << 24);

    uint32_t RotSubX1 = Rol32(SubX1, 8);
    uint32_t RotSubX3 = Rol32(SubX3, 8);

    Dst.L[0] = SubX1;
    Dst.L[1] = RotSubX1 ^ (uint32_t)Rcon;
    Dst.L[2] = SubX3;
    Dst.L[3] = RotSubX3 ^ (uint32_t)Rcon;
}

static void EmPclmulqdq(XMM128& Dst, const XMM128& Src, uint8_t Imm) {
    uint64_t A, B;
    if (Imm & 0x01)
        A = ((uint64_t)Dst.L[3] << 32) | Dst.L[2];
    else
        A = ((uint64_t)Dst.L[1] << 32) | Dst.L[0];

    if (Imm & 0x10)
        B = ((uint64_t)Src.L[3] << 32) | Src.L[2];
    else
        B = ((uint64_t)Src.L[1] << 32) | Src.L[0];

    uint64_t Lo = 0, Hi = 0;
    for (int I = 0; I < 64; I++) {
        if (B & (1ULL << I)) {
            Lo ^= (A << I);
            if (I > 0) Hi ^= (A >> (64 - I));
        }
    }

    Dst.L[0] = (uint32_t)(Lo);
    Dst.L[1] = (uint32_t)(Lo >> 32);
    Dst.L[2] = (uint32_t)(Hi);
    Dst.L[3] = (uint32_t)(Hi >> 32);
}

static uint32_t EmCrc32cByte(uint32_t Crc, uint8_t Data) {
    return (Crc >> 8) ^ Crc32cTable[(Crc ^ Data) & 0xFF];
}

static uint32_t EmCrc32c(uint32_t Crc, const uint8_t* Data, int Size) {
    for (int I = 0; I < Size; I++)
        Crc = EmCrc32cByte(Crc, Data[I]);
    return Crc;
}

bool TryEmulateCrypto(uc_engine* Uc, const ZydisDecodedInstruction& Instr, ZydisDecodedOperand* Operands, uint64_t Rip) {
    switch (Instr.mnemonic) {

    case ZYDIS_MNEMONIC_SHA1RNDS4: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        uint8_t Fn = (uint8_t)Operands[2].imm.value.u;
        EmSha1Rnds4(Dst, Src, Fn);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA1NEXTE: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmSha1Nexte(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA1MSG1: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmSha1Msg1(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA1MSG2: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmSha1Msg2(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA256RNDS2: {
        XMM128 Dst, Src, Xmm0;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        if (!ReadXmm(Uc, ZYDIS_REGISTER_XMM0, Xmm0)) return false;
        EmSha256Rnds2(Dst, Src, Xmm0);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA256MSG1: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmSha256Msg1(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_SHA256MSG2: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmSha256Msg2(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_AESENC: {
        XMM128 State, Key;
        if (!ReadXmm(Uc, Operands[0].reg.value, State)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Key)) return false;
        EmAesEnc(State, Key);
        WriteXmm(Uc, Operands[0].reg.value, State);
        break;
    }

    case ZYDIS_MNEMONIC_AESENCLAST: {
        XMM128 State, Key;
        if (!ReadXmm(Uc, Operands[0].reg.value, State)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Key)) return false;
        EmAesEncLast(State, Key);
        WriteXmm(Uc, Operands[0].reg.value, State);
        break;
    }

    case ZYDIS_MNEMONIC_AESDEC: {
        XMM128 State, Key;
        if (!ReadXmm(Uc, Operands[0].reg.value, State)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Key)) return false;
        EmAesDec(State, Key);
        WriteXmm(Uc, Operands[0].reg.value, State);
        break;
    }

    case ZYDIS_MNEMONIC_AESDECLAST: {
        XMM128 State, Key;
        if (!ReadXmm(Uc, Operands[0].reg.value, State)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Key)) return false;
        EmAesDecLast(State, Key);
        WriteXmm(Uc, Operands[0].reg.value, State);
        break;
    }

    case ZYDIS_MNEMONIC_AESIMC: {
        XMM128 Dst, Src;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        EmAesImc(Dst, Src);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_AESKEYGENASSIST: {
        XMM128 Dst, Src;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        uint8_t Rcon = (uint8_t)Operands[2].imm.value.u;
        EmAesKeygenAssist(Dst, Src, Rcon);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_PCLMULQDQ: {
        XMM128 Dst, Src;
        if (!ReadXmm(Uc, Operands[0].reg.value, Dst)) return false;
        if (!ReadXmmOperand(Uc, Operands[1], Instr, Rip, Src)) return false;
        uint8_t Imm = (uint8_t)Operands[2].imm.value.u;
        EmPclmulqdq(Dst, Src, Imm);
        WriteXmm(Uc, Operands[0].reg.value, Dst);
        break;
    }

    case ZYDIS_MNEMONIC_CRC32: {
        uint64_t CrcVal = 0;
        int DstUc = ZydisRegToUcGpr(Operands[0].reg.value);
        if (!DstUc) return false;
        uc_reg_read(Uc, DstUc, &CrcVal);

        int SrcSize = Operands[1].size / 8;
        if (SrcSize < 1) SrcSize = 1;
        if (SrcSize > 8) SrcSize = 8;

        uint64_t SrcVal = 0;
        if (!ReadGprOperand(Uc, Operands[1], Instr, Rip, SrcVal, SrcSize)) return false;

        uint32_t Crc = (uint32_t)CrcVal;
        uint8_t SrcBytes[8];
        memcpy(SrcBytes, &SrcVal, SrcSize);
        Crc = EmCrc32c(Crc, SrcBytes, SrcSize);

        if (Operands[0].size == 64) {
            uint64_t Result = Crc;
            uc_reg_write(Uc, DstUc, &Result);
        } else {
            uint64_t Result = Crc;
            uc_reg_write(Uc, DstUc, &Result);
        }
        break;
    }

    default:
        return false;
    }

    return true;
}
