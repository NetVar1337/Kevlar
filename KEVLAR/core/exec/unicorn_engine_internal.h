#pragma once

#include <windows.h>
#include <Zydis/Zydis.h>
#include <cstdint>

extern ZydisFormatter GlobalFormatter;
extern void* SentinelMemory;
extern void* GdtMemory;
extern void* IdtMemory;
extern void* KpcrBlock;
extern void* EthreadBlock;
extern void* EprocessBlock;
extern void* DrvObjBlock;
extern void* RegPathBlock;
extern void* KusdBlock;
extern void* HyperspaceBlock;
extern void* HypervisorSharedPageBlock;
extern volatile bool KusdThreadRunning;
extern HANDLE KusdThread;

extern int DrvObjReadCount;
extern int ModListReadCount;
extern int NtoskrnlReadCount;
extern int NtoskrnlCodeReadCount;
extern int NtoskrnlEdataReadCount;
extern int NtoskrnlDataReadCount;
extern int NtoskrnlGapReadCount;
extern int NtoskrnlNoModCount;
extern int NtoskrnlHdrReadCount;
extern int NtoskrnlRdataReadCount;
extern int NtoskrnlPdataReadCount;
extern int NtoskrnlIdataReadCount;
extern int NtoskrnlGfidsReadCount;

struct HdrReadEntry { uint64_t Rva; int Size; uint64_t Val; uint64_t Rip; };
extern HdrReadEntry HdrRingBuf[64];
extern int HdrRingIdx;
extern int HdrFirstLogged;

extern int DrvSelfReadCount;
extern int DrvSelfHdrReadCount;
extern int DrvSelfIatReadCount;

struct EdataReadEntry { uint64_t Rva; int Size; uint64_t Val; uint64_t Rip; };
extern EdataReadEntry EdataRingBuf[32];
extern int EdataRingIdx;

struct OrdReadEntry { uint64_t NameRva; uint16_t Ordinal; uint32_t FuncRva; uint64_t Rip; };
extern OrdReadEntry OrdRingBuf[64];
extern int OrdRingIdx;
extern int OrdinalReadCount;
extern int FuncAddrReadCount;
extern int EdataFirstLogged;
extern int KusdReadCount;
extern int KusdTimingLogCount;
extern int SysModReadCount;

struct HypervisorSharedPageLogEntry {
    uint64_t Rip;
    uint64_t ReadOffset;
    int Size;
    uint64_t Value;
};
extern HypervisorSharedPageLogEntry HypervisorSharedPageLog[256];
extern int HypervisorSharedPageLogIdx;
extern int HypervisorSharedPageReadCount;

struct BootEnvLogEntry {
    uint64_t Rip;
    uint64_t ReadOffset;
    int Size;
    uint64_t Value;
};
extern BootEnvLogEntry BootEnvLog[128];
extern int BootEnvLogIdx;
extern int BootEnvReadCount;

struct CodeIntegrityLogEntry {
    uint64_t Rip;
    uint64_t ReadOffset;
    int Size;
    uint64_t Value;
};
extern CodeIntegrityLogEntry CodeIntegrityLog[128];
extern int CodeIntegrityLogIdx;
extern int CodeIntegrityReadCount;
extern int TotalInterruptCount;
extern int InterruptCounts[256];

static constexpr int RIP_RING_SIZE = 4096;
struct RipRaxEntry { uint64_t Rip; uint64_t Rax; };
extern RipRaxEntry RipRingBuf[RIP_RING_SIZE];
extern int RipRingIdx;
extern uint64_t RipRingTotal;

struct SysModCallEntry {
    uint64_t CallerRip;
    uint64_t FuncAddr;
    uint64_t RetVal;
    char FuncName[64];
};
static constexpr int SYSMOD_RING_SIZE = 64;
extern SysModCallEntry SysModRing[SYSMOD_RING_SIZE];
extern int SysModRingIdx;
