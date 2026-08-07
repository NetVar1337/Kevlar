#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include "host/providers/provider.h"
#include "host/providers/ntoskrnl_provider.h"
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"
#include <SymParser/symparser.hpp>
#include <intrin.h>

int DrvObjReadCount = 0;

static bool UcReadU64(uc_engine* Uc, uint64_t UcAddr, uint64_t& Out) {
    void* Host = UnicornMem::UcToHost(UcAddr);
    if (Host) {
        Out = *(uint64_t*)Host;
        return true;
    }
    uc_err Err = uc_mem_read(Uc, UcAddr, &Out, 8);
    return Err == UC_ERR_OK;
}
int ModListReadCount = 0;
int NtoskrnlReadCount = 0;
int NtoskrnlCodeReadCount = 0;
int NtoskrnlEdataReadCount = 0;
int NtoskrnlDataReadCount = 0;
int NtoskrnlGapReadCount = 0;
int NtoskrnlNoModCount = 0;
int NtoskrnlHdrReadCount = 0;
int NtoskrnlRdataReadCount = 0;
int NtoskrnlPdataReadCount = 0;
int NtoskrnlIdataReadCount = 0;
int NtoskrnlGfidsReadCount = 0;
HdrReadEntry HdrRingBuf[64];
int HdrRingIdx = 0;
int HdrFirstLogged = 0;
int DrvSelfReadCount = 0;
int DrvSelfHdrReadCount = 0;
int DrvSelfIatReadCount = 0;
EdataReadEntry EdataRingBuf[32];
int EdataRingIdx = 0;
OrdReadEntry OrdRingBuf[64];
int OrdRingIdx = 0;
int OrdinalReadCount = 0;
int FuncAddrReadCount = 0;
int EdataFirstLogged = 0;
RipRaxEntry RipRingBuf[RIP_RING_SIZE];
int RipRingIdx = 0;
uint64_t RipRingTotal = 0;
SysModCallEntry SysModRing[SYSMOD_RING_SIZE];
int SysModRingIdx = 0;

struct HookCallResult {
    uint64_t RetVal;
    DWORD ExceptionCode;
    bool Crashed;
};

static HookCallResult CallHookSafe(void* Func, uint64_t Rcx, uint64_t Rdx, uint64_t R8, uint64_t R9, uint64_t* StackArgs) {
    HookCallResult Result = { 0, 0, false };
    using FnCall = uint64_t(__fastcall*)(...);
    auto Fn = (FnCall)Func;
    __try {
        Result.RetVal = Fn(
            Rcx, Rdx, R8, R9,
            StackArgs[0], StackArgs[1], StackArgs[2], StackArgs[3],
            StackArgs[4], StackArgs[5], StackArgs[6], StackArgs[7],
            StackArgs[8], StackArgs[9], StackArgs[10], StackArgs[11]
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Result.Crashed = true;
        Result.ExceptionCode = GetExceptionCode();
    }
    return Result;
}

void UnicornEmu::Hooks::OnSysModExec(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    SysModFuncEntry* Entry = nullptr;
    SysModFuncEntry LocalEntry;
    {
        std::lock_guard<std::mutex> Guard(SysModFuncCacheLock);
        auto It = SysModFuncCache.find(Addr);
        if (It != SysModFuncCache.end()) {
            Entry = &It->second;
        }
    }

    if (!Entry) {
        for (auto& Mod : UnicornEmu::MappedSysMods) {
            if (Addr >= Mod.UcBase && Addr < Mod.UcBase + Mod.Size) {
                uint64_t Rva = Addr - Mod.UcBase;
                const char* ExportName = Mod.Pe->GetExport(Rva);
                if (!ExportName) {
                    auto AllExports = Mod.Pe->GetAllExports();
                    uint64_t BestRva = 0;
                    std::string BestName;
                    for (auto& [ExpRva, ExpName] : AllExports) {
                        if (ExpRva <= Rva && ExpRva > BestRva) {
                            BestRva = ExpRva;
                            BestName = ExpName;
                        }
                    }
                    if (BestRva && (Rva - BestRva) < 0x20) {
                        ExportName = BestName.c_str();
                        Logger::Log("{GRY}SysMod fuzzy: {WHT}%s!%s {GRY}(exact=0x%llx export=0x%llx delta=%lld){RESET}\n",
                            Mod.Name.c_str(), ExportName, Rva, BestRva, Rva - BestRva);
                    }
                }
                if (!ExportName) {
                    auto Sym = symparser::find_symbol(Mod.Pe->filename, Rva);
                    if (Sym && Sym->rva) {
                        static thread_local std::string SymNameBuf;
                        SymNameBuf = Sym->name;
                        ExportName = SymNameBuf.c_str();
                        Logger::Log("{GRY}SysMod symbol: {WHT}%s!%s {GRY}(RVA=0x%llx){RESET}\n",
                            Mod.Name.c_str(), ExportName, Rva);
                    }
                }
                if (!ExportName) {
                    uint64_t Rsp = 0;
                    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
                    uint64_t RetAddr = 0;
                    UcReadU64(Uc, Rsp, RetAddr);
                    bool CalledFromOutside = (RetAddr < Mod.UcBase || RetAddr >= Mod.UcBase + Mod.Size);
                    if (CalledFromOutside) {
                        Logger::Log("{YEL}SysMod exec: {WHT}%s!<unknown> {GRY}RVA=0x%llx caller=0x%llx {YEL}-> forcing RET 0{RESET}\n", Mod.Name.c_str(), Rva, RetAddr);
                        uint64_t Zero = 0;
                        uc_reg_write(Uc, UC_X86_REG_RAX, &Zero);
                        Rsp += 8;
                        uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);
                        uc_reg_write(Uc, UC_X86_REG_RIP, &RetAddr);
                    }
                    return;
                }
                LocalEntry.UcBase = Mod.UcBase;
                LocalEntry.Size = Mod.Size;
                LocalEntry.ModName = Mod.Name;
                LocalEntry.FuncName = ExportName;
                LocalEntry.HostFunc = nullptr;
                LocalEntry.IsPassthrough = false;
                LocalEntry.IsKnown = false;
                {
                    std::shared_lock<std::shared_mutex> Guard(Provider::ProviderLock);
                    if (Provider::function_providers.contains(LocalEntry.FuncName)) {
                        LocalEntry.HostFunc = Provider::function_providers[LocalEntry.FuncName];
                        LocalEntry.IsKnown = true;
                    } else if (Provider::passthrough_provider_cache.contains(LocalEntry.FuncName)) {
                        LocalEntry.HostFunc = Provider::passthrough_provider_cache[LocalEntry.FuncName];
                        LocalEntry.IsPassthrough = true;
                        LocalEntry.IsKnown = true;
                    }
                }
                if (!LocalEntry.HostFunc) {
                    auto NtdllAddr = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), ExportName);
                    if (NtdllAddr) {
                        LocalEntry.HostFunc = NtdllAddr;
                        LocalEntry.IsPassthrough = true;
                        LocalEntry.IsKnown = true;
                        {
                            std::unique_lock<std::shared_mutex> Guard(Provider::ProviderLock);
                            Provider::passthrough_provider_cache[LocalEntry.FuncName] = NtdllAddr;
                        }
                    }
                }
                {
                    std::lock_guard<std::mutex> Guard(SysModFuncCacheLock);
                    SysModFuncCache[Addr] = LocalEntry;
                }
                Entry = &LocalEntry;
                break;
            }
        }
    }

    if (!Entry) return;

    if (Entry->IsKnown && Entry->HostFunc) {
        if (Entry->IsPassthrough) {
            std::shared_lock<std::shared_mutex> PGuard(Provider::ProviderLock);
            if (Provider::function_providers.contains(Entry->FuncName)) {
                Entry->HostFunc = Provider::function_providers[Entry->FuncName];
                Entry->IsPassthrough = false;
            }
        }
        if (DiagnosticHooksEnabled || Entry->FuncName.find("NtQuerySystemInformation") != std::string::npos)
            Logger::Log("{YEL}SysMod: {WHT}%s!%s {GRY}(0x%llx)%s{RESET}\n", Entry->ModName.c_str(), Entry->FuncName.c_str(), Addr,
                Entry->IsPassthrough ? " [PASSTHROUGH]" : " [custom]");
        uint64_t Rcx = 0, Rdx = 0, R8 = 0, R9 = 0, Rsp = 0;
        uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
        uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
        uc_reg_read(Uc, UC_X86_REG_R8, &R8);
        uc_reg_read(Uc, UC_X86_REG_R9, &R9);
        uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
        uint64_t StackArgs[12] = { 0 };
        for (int I = 0; I < 12; I++) {
            UcReadU64(Uc, Rsp + 0x28 + I * 8, StackArgs[I]);
        }
        auto CallResult = CallHookSafe(Entry->HostFunc, Rcx, Rdx, R8, R9, StackArgs);
        uint64_t RetVal = CallResult.RetVal;
        if (CallResult.Crashed) {
            Logger::Log("{RED}SYSMOD HOOK CRASH in '%s!%s'! Exception 0x%08x RCX=%llx RDX=%llx R8=%llx R9=%llx{RESET}\n",
                Entry->ModName.c_str(), Entry->FuncName.c_str(), CallResult.ExceptionCode, Rcx, Rdx, R8, R9);
            RetVal = 0;
        }
        uint64_t SysModCallerRip = 0;
        UcReadU64(Uc, Rsp, SysModCallerRip);
        UnicornEmu::TraceRecordApi(Entry->FuncName.c_str(), RetVal, SysModCallerRip);
        uc_reg_write(Uc, UC_X86_REG_RAX, &RetVal);
        uint64_t CallerRip = 0;
        UcReadU64(Uc, Rsp, CallerRip);
        if (RetVal >= 0x80000000ULL && RetVal <= 0xFFFFFFFFULL) {
            bool IsExpectedError = false;
            switch ((uint32_t)RetVal) {
            case 0xC0000004:
            case 0xC0000023:
            case 0xC0000225:
            case 0xC0000034:
            case 0xC000007A:
                IsExpectedError = true;
                break;
            }
            uint64_t DrvOffset = 0;
            const char* CallerTag = "unknown";
            if (CallerRip >= DRIVER_BASE_UC && CallerRip < DRIVER_BASE_UC + 0x10000000ULL) {
                DrvOffset = CallerRip - DRIVER_BASE_UC;
                CallerTag = "drv";
            } else {
                for (auto& M : MappedSysMods) {
                    if (CallerRip >= M.UcBase && CallerRip < M.UcBase + M.Size) {
                        DrvOffset = CallerRip - M.UcBase;
                        CallerTag = M.Name.c_str();
                        break;
                    }
                }
            }
            if (!IsExpectedError) {
                Logger::Log("{RED}SysMod ERROR: {WHT}%s!%s {RED}-> 0x%08x {GRY}caller=%s+0x%llx{RESET}\n",
                    Entry->ModName.c_str(), Entry->FuncName.c_str(), (uint32_t)RetVal, CallerTag, DrvOffset);
            }
        }
        if (DiagnosticHooksEnabled)
            Logger::Log("{YEL}SysMod: {WHT}%s!%s {GRN}-> {WHT}0x%llx {GRY}caller=0x%llx{RESET}\n",
                Entry->ModName.c_str(), Entry->FuncName.c_str(), RetVal, CallerRip);
        auto& Rec = SysModRing[SysModRingIdx % SYSMOD_RING_SIZE];
        Rec.CallerRip = CallerRip;
        Rec.FuncAddr = Addr;
        Rec.RetVal = RetVal;
        strncpy(Rec.FuncName, Entry->FuncName.c_str(), sizeof(Rec.FuncName) - 1);
        Rec.FuncName[sizeof(Rec.FuncName) - 1] = 0;
        SysModRingIdx++;
        Rsp += 8;
        uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);
        uc_reg_write(Uc, UC_X86_REG_RIP, &CallerRip);
    } else {
        uint64_t Rsp = 0;
        uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
        uint64_t RetAddr = 0;
        UcReadU64(Uc, Rsp, RetAddr);
        bool CalledFromOutside = (RetAddr < Entry->UcBase || RetAddr >= Entry->UcBase + Entry->Size);
        if (CalledFromOutside) {
            if (StrictExportsEnabled) {
                Logger::Log("{RED}SysMod UNHANDLED: {WHT}%s!%s {GRY}(0x%llx) {RED}-> STATUS_NOT_IMPLEMENTED (strict){RESET}\n",
                    Entry->ModName.c_str(), Entry->FuncName.c_str(), Addr);
                uint64_t Status = 0xC0000002ULL; // STATUS_NOT_IMPLEMENTED
                uc_reg_write(Uc, UC_X86_REG_RAX, &Status);
            } else {
                Logger::Log("{RED}SysMod UNHANDLED: {WHT}%s!%s {GRY}(0x%llx) {RED}-> forcing RET 0{RESET}\n",
                    Entry->ModName.c_str(), Entry->FuncName.c_str(), Addr);
                uint64_t Zero = 0;
                uc_reg_write(Uc, UC_X86_REG_RAX, &Zero);
            }
            Rsp += 8;
            uc_reg_write(Uc, UC_X86_REG_RSP, &Rsp);
            uc_reg_write(Uc, UC_X86_REG_RIP, &RetAddr);
        } else {
            Logger::Log("{YEL}SysMod internal: {WHT}%s!%s {GRY}(0x%llx) {YEL}-> letting execute{RESET}\n",
                Entry->ModName.c_str(), Entry->FuncName.c_str(), Addr);
        }
    }
}

void UnicornEmu::Hooks::OnSentinelExec(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    StubEntry EntryCopy;
    {
        std::shared_lock<std::shared_mutex> Guard(UnicornEmu::EngineLock);
        auto It = UnicornEmu::SentinelMap.find(Addr);
        if (It == UnicornEmu::SentinelMap.end()) {
            uint64_t AlignedAddr = Addr & ~0xFULL;
            It = UnicornEmu::SentinelMap.find(AlignedAddr);
            if (It == UnicornEmu::SentinelMap.end()) {
                return;
            }
        }
        EntryCopy = It->second;
    }
    LARGE_INTEGER HookEntryQpc;
    QueryPerformanceCounter(&HookEntryQpc);
    uint64_t Rcx = 0, Rdx = 0, R8 = 0, R9 = 0, Rsp = 0;
    uint64_t Rax = 0;
    uc_reg_read(Uc, UC_X86_REG_RCX, &Rcx);
    uc_reg_read(Uc, UC_X86_REG_RDX, &Rdx);
    uc_reg_read(Uc, UC_X86_REG_R8, &R8);
    uc_reg_read(Uc, UC_X86_REG_R9, &R9);
    uc_reg_read(Uc, UC_X86_REG_RSP, &Rsp);
    uc_reg_read(Uc, UC_X86_REG_RAX, &Rax);
    uint64_t RetRip = 0;
    UcReadU64(Uc, Rsp, RetRip);
    static thread_local char HookRing[16][64] = {};
    static thread_local int HookRingIdx = 0;
    static thread_local const char* LastHookName = nullptr;
    bool IsChkstk = (_stricmp(EntryCopy.Name.c_str(), "__chkstk") == 0 || _stricmp(EntryCopy.Name.c_str(), "_chkstk") == 0);
    if (DiagnosticHooksEnabled)
        Logger::Log("{YEL}>> {WHT}%s {GRY}(RCX=%llx RDX=%llx R8=%llx R9=%llx) caller=0x%llx{RESET}\n",
            EntryCopy.Name.c_str(), Rcx, Rdx, R8, R9, RetRip);

    strncpy_s(HookRing[HookRingIdx % 16], 64, EntryCopy.Name.c_str(), _TRUNCATE);
    HookRingIdx++;
    LastHookName = EntryCopy.Name.c_str();

    if (IsChkstk) {
        uint64_t StackFloorUc = STACK_BASE_UC;
        uint64_t StackTopUc = STACK_BASE_UC + STACK_SIZE_UC;
        uint64_t DownwardSpace = (Rsp >= StackFloorUc) ? (Rsp - StackFloorUc) : 0;
        uint64_t FutureRsp = Rsp - Rax;
        std::string ReturnDisasm = UnicornEmu::DisassembleAt(Uc, RetRip);

        Logger::Log("{MAG}[CHKSTK] probeSize(RAX)=0x%llx currentRsp=0x%llx futureRsp=0x%llx stackBase=0x%llx stackTop=0x%llx downwardSpace=0x%llx return=0x%llx{RESET}\n",
            Rax, Rsp, FutureRsp, StackFloorUc, StackTopUc, DownwardSpace, RetRip);
        Logger::Log("{MAG}[CHKSTK] return instruction: %s{RESET}\n", ReturnDisasm.c_str());

        for (int I = 0; I < 6; I++) {
            uint64_t StackVal = 0;
            uc_mem_read(Uc, Rsp + I * 8, &StackVal, 8);
            Logger::Log("{MAG}[CHKSTK] [RSP+0x%02x] = 0x%016llx{RESET}\n", I * 8, StackVal);
        }

        if (FutureRsp < StackFloorUc) {
            Logger::Log("{RED}[CHKSTK] probe exceeds emulated stack reserve: futureRsp=0x%llx stackBase=0x%llx{RESET}\n",
                FutureRsp, StackFloorUc);
        }

        uc_reg_write(Uc, UC_X86_REG_RAX, &Rax);
        return;
    }
    if (EntryCopy.Name.find("RtlDeleteRegistryValue") != std::string::npos ||
        EntryCopy.Name.find("RtlWriteRegistryValue") != std::string::npos) {
        Logger::Log("{RED}[CALLSTACK @ %s] Walking stack from RSP=0x%llx:{RESET}\n", EntryCopy.Name.c_str(), Rsp);
        for (uint64_t Scan = Rsp; Scan < Rsp + 0x200 && Scan < STACK_BASE_UC + STACK_SIZE_UC; Scan += 8) {
            uint64_t Val = 0;
            UcReadU64(Uc, Scan, Val);
            if (Val == 0) continue;
            bool InDriver = (Val >= DRIVER_BASE_UC && Val < DRIVER_BASE_UC + 0x10000000ULL);
            if (InDriver) {
                uint64_t Rva = Val - DRIVER_BASE_UC;
                Logger::Log("{GRY}  [SP+0x%llx] 0x%llx (drv+0x%llx){RESET}\n", Scan - Rsp, Val, Rva);
            }
        }
    }
    uint64_t StackArgs[12] = { 0 };
    for (int I = 0; I < 12; I++) {
        UcReadU64(Uc, Rsp + 0x28 + I * 8, StackArgs[I]);
    }
    auto CallResult = CallHookSafe(EntryCopy.HostFunc, Rcx, Rdx, R8, R9, StackArgs);
    uint64_t RetVal = CallResult.RetVal;
    if ((RetVal & 0xFFFFFFFF) == 0xC0000034) {
        Logger::Log("{RED}[TRACE-0x34] %s returned STATUS_OBJECT_NAME_NOT_FOUND! caller=drv+0x%llx RCX=%llx RDX=%llx R8=%llx R9=%llx{RESET}\n",
            EntryCopy.Name.c_str(), RetRip - DRIVER_BASE_UC, Rcx, Rdx, R8, R9);
        for (uint64_t Scan = Rsp; Scan < Rsp + 0x100 && Scan < STACK_BASE_UC + STACK_SIZE_UC; Scan += 8) {
            uint64_t Val = 0;
            UcReadU64(Uc, Scan, Val);
            if (Val == 0) continue;
            bool InDriver = (Val >= DRIVER_BASE_UC && Val < DRIVER_BASE_UC + 0x10000000ULL);
            if (InDriver) {
                uint64_t Rva = Val - DRIVER_BASE_UC;
                Logger::Log("{RED}  [SP+0x%llx] drv+0x%llx{RESET}\n", Scan - Rsp, Rva);
            }
        }
    }
    if (CallResult.Crashed) {
        Logger::Log("{RED}HOOK CRASH in '%s'! Exception 0x%08x RCX=%llx RDX=%llx{RESET}\n",
            EntryCopy.Name.c_str(), CallResult.ExceptionCode, Rcx, Rdx);
        Logger::Log("{RED}Last 16 hooks:{RESET}\n");
        for (int I = (HookRingIdx > 16 ? HookRingIdx - 16 : 0); I < HookRingIdx; I++)
            Logger::Log("{RED}  [%d] %s{RESET}\n", I, HookRing[I % 16]);
        RetVal = 0;
        if (EntryCopy.Name.find("KeBugCheck") != std::string::npos) {
            Logger::Log("{RED}KeBugCheck hook crashed — stopping emulation to prevent loop{RESET}\n");
            uc_emu_stop(Uc);
        }
    }
    UnicornEmu::TraceRecordApi(EntryCopy.Name.c_str(), RetVal, RetRip);
    uc_reg_write(Uc, UC_X86_REG_RAX, &RetVal);
    if (DiagnosticHooksEnabled)
        Logger::Log("{GRY}<< %s -> 0x%llx{RESET}\n", EntryCopy.Name.c_str(), RetVal);
    LARGE_INTEGER HookExitQpc;
    QueryPerformanceCounter(&HookExitQpc);
    InterlockedAdd64(&UnicornEmu::HookTimeAccumulated, HookExitQpc.QuadPart - HookEntryQpc.QuadPart);
}

bool UnicornEmu::Hooks::OnMemFetchUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    if (Addr == SENTINEL_RET_ADDR) {
        Logger::Log("{CYN}Reached SENTINEL_RET_ADDR - stopping emulation{RESET}\n");
        uc_emu_stop(Uc);
        return false;
    }
    uint64_t AllocBase = 0;
    void* AllocHost = nullptr;
    uint64_t AllocSize = 0;
    if (UnicornMem::FindAllocation(Addr, AllocBase, AllocHost, AllocSize)) {
        uint64_t PageAddr = Addr & ~0xFFFULL;
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
    static thread_local uint64_t FetchUnmappedRunaway = 0;
    bool IsLowAddr = Addr < 0xFFFF000000000000ULL;
    bool IsRipLow = Rip < 0xFFFF000000000000ULL;
    if (IsLowAddr && IsRipLow) {
        FetchUnmappedRunaway++;
        if (FetchUnmappedRunaway >= 3) {
            if (FetchUnmappedRunaway == 3) {
                Logger::Log("{RED}FETCH UNMAPPED runaway detected (RIP=0x%llx addr=0x%llx) - stopping thread emulation{RESET}\n", Rip, Addr);
            }
            uc_emu_stop(Uc);
            return false;
        }
    } else {
        FetchUnmappedRunaway = 0;
    }
    Logger::Log("{RED}FETCH UNMAPPED at {WHT}0x%llx {GRY}(RIP=0x%llx size=%d){RESET}\n", Addr, Rip, Size);

    if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Addr)) {
        Logger::Log("{CYN}FETCH UNMAPPED: SEH accepted fault at 0x%llx{RESET}\n", Addr);
        return true;
    }

    uint64_t PageAddr = Addr & ~0xFFFULL;
    {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_mem_map(Uc, PageAddr, 0x1000, UC_PROT_ALL);
    }
    uint8_t RetOpcode = 0xC3;
    uc_mem_write(Uc, Addr, &RetOpcode, 1);
    return true;
}

bool UnicornEmu::Hooks::OnMemWriteUnmapped(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    uint64_t PageAddr = Addr & ~0xFFFULL;

    if (Addr < 0x10000) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Logger::Log("{RED}WRITE UNMAPPED LOW: {WHT}0x%llx {GRY}(size=%d val=0x%llx RIP=0x%llx){RESET}\n", Addr, Size, Value, Rip);
        if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Addr)) {
            Logger::Log("{CYN}WRITE UNMAPPED LOW: SEH accepted fault 0x%llx and resumed control flow{RESET}\n", Addr);
            return true;
        }
        Logger::Log("{RED}WRITE UNMAPPED LOW: no SEH handler for 0x%llx{RESET}\n", Addr);
        return false;
    }

    if (PageAddr >= HYPERSPACE_BASE_UC && PageAddr < HYPERSPACE_BASE_UC + HYPERSPACE_SIZE_UC && HyperspaceBlock) {
        uint64_t PageOffset = PageAddr - HYPERSPACE_BASE_UC;
        void* HostPage = (uint8_t*)HyperspaceBlock + PageOffset;
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, PageAddr, 0x1000, UC_PROT_ALL, HostPage);
        if (Err == UC_ERR_OK)
            return true;
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

    if (SehDispatch::DispatchException(Uc, STATUS_ACCESS_VIOLATION_EX, Addr)) {
        if (DiagnosticHooksEnabled)
            Logger::Log("{CYN}WRITE UNMAPPED: SEH accepted fault at 0x%llx{RESET}\n", Addr);
        return true;
    }

    if (DiagnosticHooksEnabled)
        Logger::Log("{BLU}WRITE UNMAPPED: {WHT}0x%llx {GRY}(size=%d val=0x%llx RIP=0x%llx) {BLU}-> lazy mapping{RESET}\n", Addr, Size, Value, Rip);
    {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_mem_map(Uc, PageAddr, 0x1000, UC_PROT_ALL);
    }
    return true;
}
