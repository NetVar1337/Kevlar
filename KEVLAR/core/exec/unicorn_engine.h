#pragma once

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <windows.h>
#include <Zydis/Zydis.h>

#define DRIVER_BASE_UC        0xFFFFF80100000000ULL
#define SENTINEL_BASE_UC      0xFFFF800000000000ULL
#define POOL_BASE_UC          0xFFFFB00000000000ULL
#define STACK_BASE_UC         0xFFFFA70000000000ULL
#define STACK_SIZE_UC         0x200000ULL
#define KPCR_BASE_UC          0xFFFFF80200000000ULL
#define KPRCB_BASE_UC         0xFFFFF80200010000ULL
#define ETHREAD_BASE_UC       0xFFFFF80200020000ULL
#define EPROCESS_BASE_UC      0xFFFFF80200030000ULL
#define DRIVER_OBJ_BASE_UC    0xFFFFF80200040000ULL
#define REGISTRY_PATH_BASE_UC 0xFFFFF80200050000ULL
#define LDR_ENTRIES_BASE_UC   0xFFFFF80200060000ULL
#define DATA_EXPORTS_BASE_UC  0xFFFFF80200100000ULL
#define KUSD_BASE_UC          0xFFFFF78000000000ULL
#define HYPERVISOR_SHARED_PAGE_BASE_UC 0xFFFFF78000001000ULL
#define HYPERSPACE_BASE_UC    0xFFFFF70000000000ULL
#define HYPERSPACE_SIZE_UC    0x200000ULL
#define GDT_BASE_UC           0xFFFFF70000100000ULL
#define IDT_BASE_UC           0xFFFFF70000101000ULL
#define SYSMOD_BASE_UC        0xFFFFF80300000000ULL
#define USERMODE_MAPPING_BASE 0x0000000010000000ULL
#define SENTINEL_RET_ADDR     0xDEADC0DE00000000ULL
#define SENTINEL_RANGE_SIZE   0x100000ULL
#define EXCEPTION_TRAMPOLINE_UC (SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE - 0x100)

class PEFile;

struct StubEntry {
    std::string Name;
    PVOID HostFunc;
    uint64_t SentinelAddr;
    bool IsPassthrough;
};

struct MemoryRegion {
    uint64_t UcBase;
    uint64_t Size;
    void* HostPtr;
    std::string Name;
    uint32_t Perms;
};

namespace UnicornEmu {

extern uc_engine* PrimaryEngine;
extern uint64_t NextSentinelAddr;
extern uint64_t NextSysModAddr;
extern std::unordered_map<uint64_t, StubEntry> SentinelMap;
extern std::vector<MemoryRegion> MappedRegions;

struct SysModInfo {
    uint64_t UcBase;
    uint64_t Size;
    std::string Name;
    PEFile* Pe;
};

extern std::vector<SysModInfo> MappedSysMods;

struct SysModFuncEntry {
    uint64_t UcBase;
    uint64_t Size;
    std::string ModName;
    std::string FuncName;
    PVOID HostFunc;
    bool IsPassthrough;
    bool IsKnown;
};

extern std::unordered_map<uint64_t, SysModFuncEntry> SysModFuncCache;
extern std::mutex SysModFuncCacheLock;

void BuildSysModFuncCache();
extern std::shared_mutex EngineLock;
extern std::shared_mutex RegionsLock;
extern uint64_t VirtualTsc;
extern uint64_t TscIncrement;
extern ZydisDecoder Decoder;

extern volatile int64_t HookTimeAccumulated;
extern int64_t EmulationStartQpc;
extern int64_t EmulationStartSystemTime;
extern int64_t QpcFrequency;
extern double TscPerQpcTick;
extern std::mutex UcMapLock;

void InitTimingSpoofing();

bool Initialize();
void Shutdown();
uc_engine* CreateEngine();
void SetupHooks(uc_engine* Uc);
void SetupGdt(uc_engine* Uc);
void SetupIdt(uc_engine* Uc);
void SetupSegmentRegisters(uc_engine* Uc);
void SetupControlRegisters(uc_engine* Uc);
void SetupMsrs(uc_engine* Uc);
uint64_t AllocateSentinel(const char* FuncName, PVOID HostFunc, bool IsPassthrough = false);
void BuildSentinelIat(PEFile* Module);
uint64_t MapRegion(uc_engine* Uc, uint64_t UcAddr, uint64_t Size, uint32_t Perms, const char* Name);
uint64_t MapRegionPtr(uc_engine* Uc, uint64_t UcAddr, uint64_t Size, uint32_t Perms, void* HostPtr, const char* Name);
uint64_t MapDriverImage(PEFile* Driver, uint64_t DesiredBase);
uint64_t MapSystemModule(PEFile* Module, const char* Name);
uint64_t MapStubModule(const char* Name, uint64_t ClaimedImageSize);
uint64_t MapKernelStructs();
uint64_t MapKuserSharedData();
uint64_t MapDataExports();
void PatchSystemModuleExports();
bool StartEmulation(uc_engine* Uc, uint64_t EntryPoint);
void StopEmulation(uc_engine* Uc);
std::string DisassembleAt(uc_engine* Uc, uint64_t Addr);

namespace Hooks {

void OnSentinelExec(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnSysModExec(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
bool OnMemFetchUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
bool OnMemReadUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
bool OnMemWriteUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnInterrupt(uc_engine* Uc, uint32_t IntNo, void* UserData);
void OnSyscall(uc_engine* Uc, void* UserData);
uint32_t OnIn(uc_engine* Uc, uint32_t Port, int Size, void* UserData);
void OnOut(uc_engine* Uc, uint32_t Port, int Size, uint32_t Value, void* UserData);
void OnCpuid(uc_engine* Uc, void* UserData);
void OnDriverTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnDrvObjRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnModuleListRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnNtoskrnlRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnKusdRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnSysModRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnRdtsc(uc_engine* Uc, void* UserData);
void OnRdmsr(uc_engine* Uc, void* UserData);
void OnWrmsr(uc_engine* Uc, void* UserData);
void OnMsrFallback(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnFocusedTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnStackWrite(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnDivWatch(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnSseAlignCheck(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnVmEnter(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnVmExit(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);
void OnHypervisorSharedPageRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnBootEnvRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);
void OnCodeIntegrityRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData);

}

struct PendingSseFault {
    bool Active;
    uint64_t FaultRip;
    uint64_t MemAddr;
    uint32_t ExceptionCode;
};

extern PendingSseFault SseFault;
extern bool DiagnosticHooksEnabled;
extern bool VgkErrorOverrideEnabled;
extern bool SehDispatchEnabled;
extern bool ModuleReadLoggingEnabled;
extern bool IntelCpuSpoofEnabled;
extern bool DevirtualizationTest;
extern bool RdmsrInsnHookSupported;
extern bool WrmsrInsnHookSupported;
extern bool MsrCodeInterceptEnabled;
extern bool StrictExportsEnabled;
extern bool ProvenanceEnabled;
extern std::string TraceRecordPath;
extern std::string TraceCheckPath;

void UpdateKusdTimeValues();

void InstallTraceCapture(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);
void TraceRecordApi(const char* FuncName, uint64_t RetVal, uint64_t CallerRip);
void TraceFlush();
void InstallDriverTrace(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);
void InstallDivWatch(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);
void InstallSseAlignCheck(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);
void InstallFocusedTrace(uc_engine* Uc, uint64_t Start, uint64_t End);
void InstallStackWriteWatch(uc_engine* Uc, uint64_t WatchAddr, uint64_t WatchSize);
void InitMsrStore();
void InstallWatchpoints(uc_engine* Uc);

}
