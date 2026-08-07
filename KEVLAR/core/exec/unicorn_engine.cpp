#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include "core/exec/instruction_emulator.h"
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"
#include "core/diagnostics/diag_center.h"
#include <intrin.h>
#include <malloc.h>

bool UnicornEmu::DiagnosticHooksEnabled = false;
bool UnicornEmu::VgkErrorOverrideEnabled = false;
bool UnicornEmu::SehDispatchEnabled = true;
bool UnicornEmu::ModuleReadLoggingEnabled = false;
bool UnicornEmu::IntelCpuSpoofEnabled = false;
bool UnicornEmu::DevirtualizationTest = false;
bool UnicornEmu::RdmsrInsnHookSupported = false;
bool UnicornEmu::WrmsrInsnHookSupported = false;
bool UnicornEmu::MsrCodeInterceptEnabled = false;

namespace UnicornEmu {
    uc_engine* PrimaryEngine = nullptr;
    uint64_t NextSentinelAddr = SENTINEL_BASE_UC;
    uint64_t NextSysModAddr = SYSMOD_BASE_UC;
    std::unordered_map<uint64_t, StubEntry> SentinelMap;
    std::vector<MemoryRegion> MappedRegions;
    std::vector<SysModInfo> MappedSysMods;
    std::unordered_map<uint64_t, SysModFuncEntry> SysModFuncCache;
    std::mutex SysModFuncCacheLock;
    std::shared_mutex EngineLock;
    std::shared_mutex RegionsLock;
    std::mutex UcMapLock;
    uint64_t VirtualTsc = 0;
    uint64_t TscIncrement = 50;
    ZydisDecoder Decoder;
    PendingSseFault SseFault = {};

    volatile int64_t HookTimeAccumulated = 0;
    int64_t EmulationStartQpc = 0;
    int64_t EmulationStartSystemTime = 0;
    int64_t QpcFrequency = 0;
    double TscPerQpcTick = 0.0;
}

ZydisFormatter GlobalFormatter;
void* SentinelMemory = nullptr;
void* GdtMemory = nullptr;
void* IdtMemory = nullptr;
void* KpcrBlock = nullptr;
void* EthreadBlock = nullptr;
void* EprocessBlock = nullptr;
void* DrvObjBlock = nullptr;
void* RegPathBlock = nullptr;
void* KusdBlock = nullptr;
void* HyperspaceBlock = nullptr;
void* HypervisorSharedPageBlock = nullptr;
volatile bool KusdThreadRunning = false;
HANDLE KusdThread = nullptr;

int KusdReadCount = 0;
int KusdTimingLogCount = 0;
int SysModReadCount = 0;

HypervisorSharedPageLogEntry HypervisorSharedPageLog[256] = {};
int HypervisorSharedPageLogIdx = 0;
int HypervisorSharedPageReadCount = 0;

BootEnvLogEntry BootEnvLog[128] = {};
int BootEnvLogIdx = 0;
int BootEnvReadCount = 0;

CodeIntegrityLogEntry CodeIntegrityLog[128] = {};
int CodeIntegrityLogIdx = 0;
int CodeIntegrityReadCount = 0;

bool UnicornEmu::Initialize() {
    uc_err Err = uc_open(UC_ARCH_X86, UC_MODE_64, &PrimaryEngine);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}uc_open failed: %s{RESET}\n", uc_strerror(Err));
        return false;
    }

    Err = (uc_err)uc_ctl_tlb_mode(PrimaryEngine, UC_TLB_VIRTUAL);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}uc_ctl_tlb_mode failed: %s{RESET}\n", uc_strerror(Err));
    }

    uint32_t OldTcgBufSize = 0;
    uc_ctl_get_tcg_buffer_size(PrimaryEngine, &OldTcgBufSize);
    uint32_t NewTcgBufSize = 128 * 1024 * 1024;
    Err = (uc_err)uc_ctl_set_tcg_buffer_size(PrimaryEngine, NewTcgBufSize);
    if (Err == UC_ERR_OK) {
        Logger::Log("{GRN}TCG buffer size: %u -> %u MB{RESET}\n", OldTcgBufSize / (1024*1024), NewTcgBufSize / (1024*1024));
    } else {
        Logger::Log("{YEL}TCG buffer size set failed: %s (using default %u){RESET}\n", uc_strerror(Err), OldTcgBufSize);
    }

    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&GlobalFormatter, ZYDIS_FORMATTER_STYLE_INTEL);

    InsnEmulator::Initialize();

    SentinelMemory = _aligned_malloc(SENTINEL_RANGE_SIZE, 0x1000);
    if (!SentinelMemory) {
        Logger::Log("{RED}Failed to allocate sentinel memory{RESET}\n");
        return false;
    }
    memset(SentinelMemory, 0xC3, SENTINEL_RANGE_SIZE);

    uint8_t* TrampolineHost = (uint8_t*)SentinelMemory + SENTINEL_RANGE_SIZE - 0x100;
    TrampolineHost[0] = 0xFF;
    TrampolineHost[1] = 0xD0;
    TrampolineHost[2] = 0xCC;

    Err = uc_mem_map_ptr(PrimaryEngine, SENTINEL_BASE_UC, SENTINEL_RANGE_SIZE, UC_PROT_ALL, SentinelMemory);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}Sentinel range mapping failed: %s{RESET}\n", uc_strerror(Err));
        return false;
    }

    MappedRegions.push_back({ SENTINEL_BASE_UC, SENTINEL_RANGE_SIZE, SentinelMemory, "SentinelRange", UC_PROT_ALL });

    SetupHooks(PrimaryEngine);
    SetupGdt(PrimaryEngine);
    SetupIdt(PrimaryEngine);
    SetupSegmentRegisters(PrimaryEngine);
    SetupControlRegisters(PrimaryEngine);
    SetupMsrs(PrimaryEngine);
    InitMsrStore();

    auto StackHost = (void*)_aligned_malloc((size_t)STACK_SIZE_UC, 0x1000);
    if (!StackHost) {
        Logger::Log("{RED}Stack allocation failed{RESET}\n");
        return false;
    }
    memset(StackHost, 0, (size_t)STACK_SIZE_UC);

    Err = uc_mem_map_ptr(PrimaryEngine, STACK_BASE_UC, STACK_SIZE_UC, UC_PROT_ALL, StackHost);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}Stack mapping failed: %s{RESET}\n", uc_strerror(Err));
        return false;
    }

    MappedRegions.push_back({ STACK_BASE_UC, STACK_SIZE_UC, StackHost, "Stack", UC_PROT_ALL });
    UnicornMem::TrackExisting(STACK_BASE_UC, StackHost, STACK_SIZE_UC, "PrimaryStack");

    VirtualTsc = __rdtsc();

    InitTimingSpoofing();
    SehDispatch::Initialize();

    if (DiagnosticHooksEnabled) {
        DiagCenter::Instance().Initialize();
    }

    Logger::Log("{GRN}Unicorn engine initialized{RESET}\n");
    return true;
}

void UnicornEmu::Shutdown() {
    if (PrimaryEngine) {
        uc_close(PrimaryEngine);
        PrimaryEngine = nullptr;
    }

    if (SentinelMemory) {
        _aligned_free(SentinelMemory);
        SentinelMemory = nullptr;
    }

    if (GdtMemory) {
        _aligned_free(GdtMemory);
        GdtMemory = nullptr;
    }

    if (KpcrBlock) {
        _aligned_free(KpcrBlock);
        KpcrBlock = nullptr;
    }

    if (EthreadBlock) {
        _aligned_free(EthreadBlock);
        EthreadBlock = nullptr;
    }

    if (EprocessBlock) {
        _aligned_free(EprocessBlock);
        EprocessBlock = nullptr;
    }

    if (DrvObjBlock) {
        _aligned_free(DrvObjBlock);
        DrvObjBlock = nullptr;
    }

    if (RegPathBlock) {
        _aligned_free(RegPathBlock);
        RegPathBlock = nullptr;
    }

    if (KusdBlock) {
        KusdThreadRunning = false;
        if (KusdThread) {
            WaitForSingleObject(KusdThread, 1000);
            CloseHandle(KusdThread);
            KusdThread = nullptr;
        }
        _aligned_free(KusdBlock);
        KusdBlock = nullptr;
    }

    if (HyperspaceBlock) {
        _aligned_free(HyperspaceBlock);
        HyperspaceBlock = nullptr;
    }

    if (DiagCenter::Instance().IsEnabled()) {
        DiagCenter::Instance().Shutdown();
    }

    SentinelMap.clear();
    MappedRegions.clear();
    NextSentinelAddr = SENTINEL_BASE_UC;

    Logger::Log("{CYN}Unicorn engine shut down{RESET}\n");
}

uc_engine* UnicornEmu::CreateEngine() {
    uc_engine* Uc = nullptr;
    uc_err Err = uc_open(UC_ARCH_X86, UC_MODE_64, &Uc);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}CreateEngine uc_open failed: %s{RESET}\n", uc_strerror(Err));
        return nullptr;
    }

    Err = (uc_err)uc_ctl_tlb_mode(Uc, UC_TLB_VIRTUAL);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}CreateEngine uc_ctl_tlb_mode failed: %s{RESET}\n", uc_strerror(Err));
    }

    uint32_t WorkerTcgBufSize = 128 * 1024 * 1024;
    Err = (uc_err)uc_ctl_set_tcg_buffer_size(Uc, WorkerTcgBufSize);
    if (Err != UC_ERR_OK) {
        Logger::Log("{YEL}CreateEngine TCG buffer size set failed: %s{RESET}\n", uc_strerror(Err));
    }

    {
        std::shared_lock<std::shared_mutex> Guard(RegionsLock);
        for (auto& Region : MappedRegions) {
            if (Region.HostPtr) {
                Err = uc_mem_map_ptr(Uc, Region.UcBase, Region.Size, Region.Perms, Region.HostPtr);
            } else {
                Err = uc_mem_map(Uc, Region.UcBase, Region.Size, Region.Perms);
                if (Err == UC_ERR_OK) {
                    uint8_t* TempBuf = (uint8_t*)malloc((size_t)Region.Size);
                    if (TempBuf) {
                        uc_mem_read(PrimaryEngine, Region.UcBase, TempBuf, (size_t)Region.Size);
                        uc_mem_write(Uc, Region.UcBase, TempBuf, (size_t)Region.Size);
                        free(TempBuf);
                    }
                }
            }
            if (Err != UC_ERR_OK) {
                Logger::Log("{RED}CreateEngine region '%s' mapping failed: %s{RESET}\n", Region.Name.c_str(), uc_strerror(Err));
            }
        }
    }

    SetupHooks(Uc);
    SetupGdt(Uc);
    SetupIdt(Uc);
    SetupSegmentRegisters(Uc);
    SetupControlRegisters(Uc);
    SetupMsrs(Uc);
    InitMsrStore();

    {
        uc_hook Hh;
        for (auto& Mod : MappedSysMods) {
            uc_err HookErr = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnSysModExec, nullptr,
                Mod.UcBase, Mod.UcBase + Mod.Size - 1);
            if (HookErr != UC_ERR_OK) {
                Logger::Log("{RED}CreateEngine: OnSysModExec hook for '%s' failed: %s{RESET}\n",
                    Mod.Name.c_str(), uc_strerror(HookErr));
            }
        }

        uc_err RdtscErr = uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSC);
        if (RdtscErr != UC_ERR_OK) {
            Logger::Log("{RED}CreateEngine: RDTSC hook failed: %s{RESET}\n", uc_strerror(RdtscErr));
        }

        RdtscErr = uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSCP);
        if (RdtscErr != UC_ERR_OK) {
            Logger::Log("{RED}CreateEngine: RDTSCP hook failed: %s{RESET}\n", uc_strerror(RdtscErr));
        }

        if (MsrCodeInterceptEnabled) {
            uc_err MsrHookErr = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnMsrFallback, nullptr,
                DRIVER_BASE_UC, DRIVER_BASE_UC + 0x10000000ULL - 1);
            if (MsrHookErr == UC_ERR_OK) {
                Logger::Log("{GRN}CreateEngine: MSR fallback hook active for driver range{RESET}\n");
            } else {
                Logger::Log("{RED}CreateEngine: MSR fallback hook failed: %s{RESET}\n", uc_strerror(MsrHookErr));
            }
        }

        if (!MappedSysMods.empty()) {
            Logger::Log("{GRN}CreateEngine: installed OnSysModExec for %llu system modules + RDTSC/RDTSCP{RESET}\n",
                (uint64_t)MappedSysMods.size());
        }
    }

    return Uc;
}

void UnicornEmu::SetupHooks(uc_engine* Uc) {
    uc_hook Hh;

    uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnSentinelExec, nullptr,
        SENTINEL_BASE_UC, SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE - 1);

    uc_hook_add(Uc, &Hh, UC_HOOK_MEM_FETCH_UNMAPPED, (void*)Hooks::OnMemFetchUnmapped, nullptr, 1, 0);
    uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ_UNMAPPED, (void*)Hooks::OnMemReadUnmapped, nullptr, 1, 0);
    uc_hook_add(Uc, &Hh, UC_HOOK_MEM_WRITE_UNMAPPED, (void*)Hooks::OnMemWriteUnmapped, nullptr, 1, 0);
    uc_hook_add(Uc, &Hh, UC_HOOK_INTR, (void*)Hooks::OnInterrupt, nullptr, 1, 0);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnSyscall, nullptr, 1, 0, UC_X86_INS_SYSCALL);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnIn, nullptr, 1, 0, UC_X86_INS_IN);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnOut, nullptr, 1, 0, UC_X86_INS_OUT);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnCpuid, nullptr, 1, 0, UC_X86_INS_CPUID);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnVmEnter, nullptr, 1, 0, UC_X86_INS_VMRESUME);
    uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnVmExit, nullptr, 1, 0, UC_X86_INS_VMXOFF);
}

void UnicornEmu::SetupGdt(uc_engine* Uc) {
    if (!GdtMemory) {
        GdtMemory = _aligned_malloc(0x1000, 0x1000);
        memset(GdtMemory, 0, 0x1000);

        uint64_t* GdtEntries = (uint64_t*)GdtMemory;
        GdtEntries[0] = 0x0000000000000000ULL;
        GdtEntries[1] = 0x0000000000000000ULL;
        GdtEntries[2] = 0x00209A0000000000ULL;
        GdtEntries[3] = 0x0000920000000000ULL;
        GdtEntries[4] = 0x00CFFA000000FFFFULL;
        GdtEntries[5] = 0x00CFF2000000FFFFULL;
        GdtEntries[6] = 0x0020FA0000000000ULL;
        GdtEntries[7] = 0x0000000000000000ULL;

        uint64_t TssBase = GDT_BASE_UC + 0x200;
        uint32_t TssLimit = 0x67;
        uint64_t TssDescLow =
            ((uint64_t)(TssLimit & 0xFFFF)) |
            ((uint64_t)(TssBase & 0xFFFF) << 16) |
            ((uint64_t)((TssBase >> 16) & 0xFF) << 32) |
            ((uint64_t)0x89 << 40) |
            ((uint64_t)((TssLimit >> 16) & 0xF) << 48) |
            ((uint64_t)((TssBase >> 24) & 0xFF) << 56);
        uint64_t TssDescHigh =
            ((uint64_t)((TssBase >> 32) & 0xFFFFFFFF)) |
            ((uint64_t)0 << 32);
        GdtEntries[8] = TssDescLow;
        GdtEntries[9] = TssDescHigh;

        uc_err Err = uc_mem_map_ptr(Uc, GDT_BASE_UC, 0x1000, UC_PROT_ALL, GdtMemory);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}GDT mapping failed: %s{RESET}\n", uc_strerror(Err));
            return;
        }

        MappedRegions.push_back({ GDT_BASE_UC, 0x1000, GdtMemory, "GDT", UC_PROT_ALL });
    }

    uc_x86_mmr Gdtr = { 0 };
    Gdtr.base = GDT_BASE_UC;
    Gdtr.limit = 10 * 8 - 1;
    uc_reg_write(Uc, UC_X86_REG_GDTR, &Gdtr);
}

void UnicornEmu::SetupIdt(uc_engine* Uc) {
    if (!IdtMemory) {
        IdtMemory = _aligned_malloc(0x1000, 0x1000);
        memset(IdtMemory, 0, 0x1000);

        struct IdtEntry {
            uint16_t OffsetLow;
            uint16_t Selector;
            uint8_t Ist;
            uint8_t TypeAttr;
            uint16_t OffsetMid;
            uint32_t OffsetHigh;
            uint32_t Reserved;
        };

        uint64_t NtosBase = SYSMOD_BASE_UC;
        struct { int Vector; uint64_t Rva; uint8_t Ist; uint8_t TypeAttr; } Handlers[] = {
            {  0, 0x40a600, 0, 0x8E },
            {  1, 0x40a940, 0, 0x8E },
            {  2, 0x40ae40, 3, 0x8E },
            {  3, 0x40b340, 0, 0x8E },
            {  4, 0x40b680, 0, 0x8E },
            {  5, 0x40b9c0, 0, 0x8E },
            {  6, 0x40c040, 0, 0x8E },
            {  7, 0x40c680, 0, 0x8E },
            {  8, 0x40c980, 1, 0x8E },
            {  9, 0x40cc80, 0, 0x8E },
            { 10, 0x40cf80, 0, 0x8E },
            { 11, 0x40d280, 0, 0x8E },
            { 12, 0x40d640, 0, 0x8E },
            { 13, 0x40d9c0, 0, 0x8E },
            { 14, 0x40dd00, 0, 0x8E },
            { 16, 0x40e4c0, 0, 0x8E },
            { 17, 0x40e880, 0, 0x8E },
            { 18, 0x40ebc0, 2, 0x8E },
            { 19, 0x40f840, 0, 0x8E },
            { 20, 0x40fC00, 0, 0x8E },
        };

        auto IdtEntries = (IdtEntry*)IdtMemory;
        for (auto& H : Handlers) {
            uint64_t Addr = NtosBase + H.Rva;
            IdtEntries[H.Vector].OffsetLow = (uint16_t)(Addr & 0xFFFF);
            IdtEntries[H.Vector].Selector = 0x10;
            IdtEntries[H.Vector].Ist = H.Ist;
            IdtEntries[H.Vector].TypeAttr = H.TypeAttr;
            IdtEntries[H.Vector].OffsetMid = (uint16_t)((Addr >> 16) & 0xFFFF);
            IdtEntries[H.Vector].OffsetHigh = (uint32_t)((Addr >> 32) & 0xFFFFFFFF);
            IdtEntries[H.Vector].Reserved = 0;
        }

        for (int I = 32; I < 256; I++) {
            uint64_t Addr = NtosBase + 0x40a600 + (I * 0x100);
            IdtEntries[I].OffsetLow = (uint16_t)(Addr & 0xFFFF);
            IdtEntries[I].Selector = 0x10;
            IdtEntries[I].Ist = 0;
            IdtEntries[I].TypeAttr = 0x8E;
            IdtEntries[I].OffsetMid = (uint16_t)((Addr >> 16) & 0xFFFF);
            IdtEntries[I].OffsetHigh = (uint32_t)((Addr >> 32) & 0xFFFFFFFF);
            IdtEntries[I].Reserved = 0;
        }

        uc_err Err = uc_mem_map_ptr(Uc, IDT_BASE_UC, 0x1000, UC_PROT_ALL, IdtMemory);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}IDT mapping failed: %s{RESET}\n", uc_strerror(Err));
            return;
        }

        MappedRegions.push_back({ IDT_BASE_UC, 0x1000, IdtMemory, "IDT", UC_PROT_ALL });
    }

    uc_x86_mmr Idtr = { 0 };
    Idtr.base = IDT_BASE_UC;
    Idtr.limit = 256 * 16 - 1;
    uc_reg_write(Uc, UC_X86_REG_IDTR, &Idtr);
}

void UnicornEmu::SetupSegmentRegisters(uc_engine* Uc) {
    uint16_t Cs = 0x10;
    uint16_t Ds = 0x2B;
    uint16_t Ss = 0x18;
    uint16_t Es = 0x2B;
    uint16_t Fs = 0x53;
    uint16_t Gs = 0x2B;

    uc_reg_write(Uc, UC_X86_REG_CS, &Cs);
    uc_reg_write(Uc, UC_X86_REG_DS, &Ds);
    uc_reg_write(Uc, UC_X86_REG_SS, &Ss);
    uc_reg_write(Uc, UC_X86_REG_ES, &Es);
    uc_reg_write(Uc, UC_X86_REG_FS, &Fs);
    uc_reg_write(Uc, UC_X86_REG_GS, &Gs);

    uint64_t GsBase = KPCR_BASE_UC;
    uc_reg_write(Uc, UC_X86_REG_GS_BASE, &GsBase);

    uint16_t Tr = 0x40;
    uc_reg_write(Uc, UC_X86_REG_TR, &Tr);

    uint16_t Ldtr = 0x00;
    uc_reg_write(Uc, UC_X86_REG_LDTR, &Ldtr);
}

void UnicornEmu::SetupControlRegisters(uc_engine* Uc) {
    uint64_t Cr0 = 0x80050033;
    uint64_t Cr3 = 0x1AD002;
    uint64_t Cr4 = 0x370678;
    uint64_t Cr8 = 0;

    uc_reg_write(Uc, UC_X86_REG_CR0, &Cr0);
    uc_reg_write(Uc, UC_X86_REG_CR3, &Cr3);
    uc_reg_write(Uc, UC_X86_REG_CR4, &Cr4);
    uc_reg_write(Uc, UC_X86_REG_CR8, &Cr8);
}

void UnicornEmu::SetupMsrs(uc_engine* Uc) {
    struct MsrEntry {
        uint32_t Id;
        uint64_t Val;
    };

    MsrEntry MsrTable[] = {
        { 0x3A,        0x1 },
        { 0x1D9,       0 },
        { 0x122,       0 },
        { 0x1DB,       0 },
        { 0x1DC,       0 },
        { 0x1DD,       0 },
        { 0x1DE,       0 },
        { 0xC0000082,  SYSMOD_BASE_UC + 0x411a00 },
        { 0xC0000080,  0xD01 },
        { 0xC0000081,  0x0023001000000000ULL },
        { 0xC0000083,  0 },
        { 0xC0000084,  0x4700 },
        { 0xC0000103,  0 },
        { 0x1B,        0xFEE00D00 },
        { 0x1A0,       0x850089 },
        { 0x48,        0 },
        { 0x10A,       0x1 },
        { 0x480,       0 },
        { 0x481,       0 },
        { 0x482,       0 },
        { 0x483,       0 },
        { 0x484,       0 },
        { 0x485,       0 },
        { 0x486,       0 },
        { 0x487,       0 },
        { 0x488,       0 },
        { 0x489,       0 },
        { 0x48A,       0 },
        { 0x48B,       0 },
        { 0x48C,       0 },
        { 0x48D,       0 },
        { 0xC0010114,  0 },
        { 0x570,       0 },
        { 0x571,       0 },
        { 0x572,       0 },
        { 0x560,       0 },
        { 0x561,       0 },
        { 0x580,       0 },
        { 0x581,       0 },
        { 0x582,       0 },
        { 0x583,       0 },
        { 0xCE,        0x00050A2200000000ULL },
        { 0xE7,        0 },
        { 0xE8,        0 },
        { 0x38D,       0 },
        { 0x38E,       0 },
        { 0x38F,       0 },
        { 0x309,       0 },
        { 0x30A,       0 },
        { 0x30B,       0 },
    };

    for (auto& Entry : MsrTable) {
        uc_x86_msr MsrVal;
        MsrVal.rid = Entry.Id;
        MsrVal.value = Entry.Val;
        uc_err Err = uc_reg_write(Uc, UC_X86_REG_MSR, &MsrVal);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}MSR 0x%x write failed: %s{RESET}\n", Entry.Id, uc_strerror(Err));
        }
    }
}

