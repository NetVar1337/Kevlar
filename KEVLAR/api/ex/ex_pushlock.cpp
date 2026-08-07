#include "include/common.h"
#include "ex_pushlock.h"

_ETHREAD* h_KeGetCurrentThread();
void h_KeLeaveCriticalRegionThread(_KTHREAD* A1);

static __int64 h_ExTimedWaitForUnblockPushLock(volatile __int64* A1, char* A2, LARGE_INTEGER* A3) {
    auto HostA2 = (char*)UcPtr(A2);
    volatile long* V3 = (volatile long*)(HostA2 + 52);

    *reinterpret_cast<WORD*>(HostA2) = 0;
    *reinterpret_cast<DWORD*>(HostA2 + 4) = 0;
    *reinterpret_cast<uint64_t*>(HostA2 + 16) = (uint64_t)((uintptr_t)A2 + 8);
    *reinterpret_cast<uint64_t*>(HostA2 + 8) = (uint64_t)((uintptr_t)A2 + 8);
    HostA2[2] = 6;

    if (_interlockedbittestandreset(V3, 1u)) {
        unsigned int V9 = (unsigned int)h_KeWaitForSingleObject(A2, (void*)31, nullptr, 0, A3);
        if (V9)
            h_ExpUnblockPushLock(A1, A2, 1);
        return (NTSTATUS)V9;
    }
    return 0;
}

int h_ExpUnblockPushLock(volatile __int64* A1, void* A2, char A3) {
    char V3 = 0;
    __int64 V4;
    unsigned int CurrentPrcbLower = 2;
    unsigned __int8 CurrentIrql = 2;

    auto HostA1 = (volatile __int64*)UcPtr((volatile __int64*)A1);
    V4 = _InterlockedExchange64(HostA1, 0);

    if (V4) {
        char* HostV4 = (char*)UnicornMem::UcToHost((uint64_t)V4);
        if (HostV4 && *(__int64*)(HostV4 + 24)) {
            CurrentIrql = 0;
        }
        do {
            __int64 V10 = HostV4 ? *(__int64*)(HostV4 + 24) : 0;
            if ((void*)(uintptr_t)V4 == A2)
                V3 = 1;
            if (HostV4 && !_interlockedbittestandreset((volatile long*)(HostV4 + 52), 1u))
                CurrentPrcbLower = (unsigned int)h_KeSetEvent((_KEVENT*)(uintptr_t)V4, 1, 0);
            V4 = V10;
            HostV4 = V4 ? (char*)UnicornMem::UcToHost((uint64_t)V4) : nullptr;
        } while (V4);
    }

    if (A2 && !V3) {
        if (A3)
            CurrentPrcbLower = (unsigned int)h_KeWaitForSingleObject(A2, (void*)31, nullptr, 0, nullptr);
        else
            CurrentPrcbLower = (unsigned int)h_ExTimedWaitForUnblockPushLock(A1, (char*)A2, nullptr);
    }

    return (int)CurrentPrcbLower;
}

int h_ExfUnblockPushLock(volatile __int64* A1, void* A2) {
    return h_ExpUnblockPushLock(A1, A2, 0);
}

static __int64 h_ExpLookupHandleTableEntry(__int64 A1Uc, __int64 A2) {
    auto HostA1 = (uint8_t*)UnicornMem::UcToHost((uint64_t)A1Uc);
    if (!HostA1) return 0;

    unsigned __int64 V2 = (unsigned __int64)A2 & 0xFFFFFFFFFFFFFFFCULL;
    unsigned int Limit = *(unsigned int*)HostA1;
    if (V2 >= (unsigned __int64)Limit) return 0;

    uint64_t TableCode = *(uint64_t*)(HostA1 + 8);

    if ((TableCode & 3) == 1) {
        auto L1 = (uint64_t*)UnicornMem::UcToHost(TableCode + 8 * (V2 >> 10) - 1);
        if (!L1) return 0;
        return (__int64)(*L1 + 4 * (V2 & 0x3FF));
    }
    if ((TableCode & 3) != 0) {
        auto L2 = (uint64_t*)UnicornMem::UcToHost(TableCode + 8 * (V2 >> 19) - 2);
        if (!L2) return 0;
        auto L1 = (uint64_t*)UnicornMem::UcToHost(*L2 + 8 * ((V2 >> 10) & 0x1FF));
        if (!L1) return 0;
        return (__int64)(*L1 + 4 * (V2 & 0x3FF));
    }
    return (__int64)(TableCode + 4 * V2);
}

static __int64 h_ExpGetNextHandleTableEntry(__int64 A1Uc, __int64 A2Uc, __int64* A3Host) {
    __int64 V6 = 0, V4, V5;

    if (A2Uc) {
        V6 = *A3Host + 4;
        if ((unsigned __int64)(V6 ^ (unsigned __int64)*A3Host) < 0x400) {
            V5 = A2Uc + 16;
            *A3Host = V6;
            return V5;
        }
        V4 = *A3Host + 8;
    } else {
        V4 = 4;
    }
    V5 = h_ExpLookupHandleTableEntry(A1Uc, V4);
    *A3Host = V6;
    return V5;
}

static __int64 h_ExpBlockOnLockedHandleEntry(__int64 A1Uc, __int64 A2Uc, __int64 A3Val) {
    _mm_pause();
    return 0;
}

static unsigned char h_InvokeEnumCallback(
    uint64_t CbUcAddr, __int64 A1Uc, __int64 EntryUc, __int64 HandleVal, __int64 A3Uc)
{
    auto ThrCtx = UnicornThread::GetCurrent();
    uc_engine* Uc = ThrCtx ? ThrCtx->Engine : UnicornEmu::PrimaryEngine;
    if (!Uc || !CbUcAddr) return 0;

    uint64_t SaveRcx, SaveRdx, SaveR8, SaveR9, SaveRsp, SaveRax;
    uc_reg_read(Uc, UC_X86_REG_RCX, &SaveRcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &SaveRdx);
    uc_reg_read(Uc, UC_X86_REG_R8, &SaveR8);
    uc_reg_read(Uc, UC_X86_REG_R9, &SaveR9);
    uc_reg_read(Uc, UC_X86_REG_RSP, &SaveRsp);
    uc_reg_read(Uc, UC_X86_REG_RAX, &SaveRax);

    uint64_t Rcx = (uint64_t)A1Uc;
    uint64_t Rdx = (uint64_t)EntryUc;
    uint64_t R8  = (uint64_t)HandleVal;
    uint64_t R9  = (uint64_t)A3Uc;
    uc_reg_write(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_write(Uc, UC_X86_REG_RDX, &Rdx);
    uc_reg_write(Uc, UC_X86_REG_R8, &R8);
    uc_reg_write(Uc, UC_X86_REG_R9, &R9);

    uint64_t Rsp = SaveRsp - 8;
    uint64_t RetAddr = SENTINEL_RET_ADDR;
    uc_mem_write(Uc, Rsp, &RetAddr, 8);
    uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);

    uc_emu_start(Uc, CbUcAddr, SENTINEL_RET_ADDR, 0, 0);

    uint64_t Result = 0;
    uc_reg_read(Uc, UC_X86_REG_RAX, &Result);

    uc_reg_write(Uc, UC_X86_REG_RCX, &SaveRcx);
    uc_reg_write(Uc, UC_X86_REG_RDX, &SaveRdx);
    uc_reg_write(Uc, UC_X86_REG_R8, &SaveR8);
    uc_reg_write(Uc, UC_X86_REG_R9, &SaveR9);
    uc_reg_write(Uc, UC_X86_REG_RSP, &SaveRsp);
    uc_reg_write(Uc, UC_X86_REG_RAX, &SaveRax);

    return (unsigned char)Result;
}

__int64 h_ExEnumHandleTable(
    __int64 A1Uc,
    __int64 (__fastcall *A2CbUc)(__int64, signed __int64*, uint64_t, __int64),
    __int64 A3Uc,
    uint64_t* A4Uc)
{
    _ETHREAD* CurEThread = h_KeGetCurrentThread();
    unsigned char V5 = 0;
    __int64 V15[7] = {};
    __int64 NextEntryUc;
    volatile signed __int64* EntryHost;
    signed __int64 V11;
    __int64 V12, V13;

    --CurEThread->Tcb.KernelApcDisable;

    NextEntryUc = h_ExpGetNextHandleTableEntry(A1Uc, 0, V15);
    if (!NextEntryUc) goto LABEL_13;

EnumLoop:
LockRetry:
    EntryHost = (volatile signed __int64*)UnicornMem::UcToHost((uint64_t)NextEntryUc);
    if (!EntryHost) goto LABEL_13;

WaitValid:
    _m_prefetchw((void*)EntryHost);
    V11 = *EntryHost;

    if ((V11 & 1) == 0) {
        if (V11) {
            h_ExpBlockOnLockedHandleEntry(A1Uc, NextEntryUc, V11);
            goto WaitValid;
        }
        goto Advance;
    }

    if (V11 != _InterlockedCompareExchange64(EntryHost, V11 - 1, V11))
        goto LockRetry;

    V12 = V15[0];
    V5 = h_InvokeEnumCallback((uint64_t)A2CbUc, A1Uc, NextEntryUc, V12, A3Uc);
    if (!V5) goto Advance;

    if (A4Uc)
        *UcPtr(A4Uc) = (uint64_t)V12;
    goto LABEL_13;

Advance:
    V12 = V15[0];
    V13 = V12 + 4;
    if ((unsigned __int64)(V12 ^ (unsigned __int64)(V12 + 4)) >= 0x400)
        NextEntryUc = h_ExpLookupHandleTableEntry(A1Uc, V12 + 8);
    else
        NextEntryUc += 16;
    V15[0] = V13;
    if (!NextEntryUc) goto LABEL_13;
    goto EnumLoop;

LABEL_13:
    h_KeLeaveCriticalRegionThread(&CurEThread->Tcb);
    return V5;
}
