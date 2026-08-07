#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <intrin.h>
#include <iostream>
#include <malloc.h>
#include <mutex>
#include <thread>
#include <atomic>

#include <PEMapper/pefile.h>

#include <Logger/Logger.h>
#include <SymParser/symparser.hpp>

#include "host/config/config.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/timing_spoof.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"
#include "core/loader/environment.h"
#include "core/loader/kernel_structs.h"

#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/static_export_provider.h"
#include "host/providers/provider.h"
#include "core/registry/virtual_fs.h"
#include "core/diagnostics/diag_center.h"
#include "api/io/io_device.h"
#include "api/ke/ke_misc.h"
#include "api/ke/ke_sync.h"
#include "api/ke/ke_timer.h"
#include "api/ke/ke_event.h"

static bool NoPause = false;
static bool SelfTest = false;

// Host-level selftest for the ke_* semantics: exercises IRQL, APC queue/delivery,
// DPC queue and timer cancel/periodic directly against the built environment.
// Runs without a target driver; smoke.ps1 invokes `KEVLAR.exe --selftest`.
static int RunSelfTest() {
    int Fails = 0;
    auto Check = [&Fails](bool Cond, const char* Msg) {
        if (Cond)
            Logger::Log("{GRN}  [PASS] %s{RESET}\n", Msg);
        else {
            Logger::Log("{RED}  [FAIL] %s{RESET}\n", Msg);
            Fails++;
        }
    };

    const uint64_t SelftestBase = 0xFFFFF10000000000ULL;
    const uint64_t RegionSize = 0x1000;
    void* RegionHost = _aligned_malloc((size_t)RegionSize, 0x1000);
    if (!RegionHost) { Logger::Log("{RED}selftest: region alloc failed{RESET}\n"); return 1; }
    memset(RegionHost, 0, (size_t)RegionSize);
    if (!UnicornEmu::MapRegionPtr(UnicornEmu::PrimaryEngine, SelftestBase, RegionSize, UC_PROT_ALL, RegionHost, "SelftestRegion")) {
        Logger::Log("{RED}selftest: region map failed{RESET}\n");
        return 1;
    }
    UnicornMem::TrackExisting(SelftestBase, RegionHost, RegionSize, "SelftestRegion");

    uint8_t* R = (uint8_t*)RegionHost;
    // Guest routines (position-independent):
    //   APC:  rax=[r8]; [rax]=0x41414141; ret     (r8 = &Apc->NormalContext)
    //   DPC:  rax=rdx; [rax]=0x42424242; ret       (rdx = DeferredContext)
    //   cancel/timer probes: same shape, distinct markers
    static const uint8_t ApcRoutine[]  = { 0x49, 0x8B, 0x00, 0xC7, 0x00, 0x41, 0x41, 0x41, 0x41, 0xC3 };
    static const uint8_t DpcRoutine[]  = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x42, 0x42, 0x42, 0x42, 0xC3 };
    static const uint8_t CancelRoutine[] = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x43, 0x43, 0x43, 0x43, 0xC3 };
    static const uint8_t TimerRoutine[] = { 0x48, 0x89, 0xD0, 0xC7, 0x00, 0x44, 0x44, 0x44, 0x44, 0xC3 };
    memcpy(R + 0x100, ApcRoutine, sizeof(ApcRoutine));
    memcpy(R + 0x200, DpcRoutine, sizeof(DpcRoutine));
    memcpy(R + 0x300, CancelRoutine, sizeof(CancelRoutine));
    memcpy(R + 0x350, TimerRoutine, sizeof(TimerRoutine));

    const uint64_t ApcMarker = SelftestBase + 0x000;
    const uint64_t DpcMarker = SelftestBase + 0x010;
    const uint64_t CancelMarker = SelftestBase + 0x020;
    const uint64_t TimerMarker = SelftestBase + 0x030;

    // --- IRQL ---
    Logger::Log("{CYN}=== SELFTEST: IRQL ==={RESET}\n");
    UCHAR Old = h_KfRaiseIrql(2);
    Check(Old == 0 && h_KeGetCurrentIrql() == 2, "KfRaiseIrql(2)->0, KeGetCurrentIrql()==2");
    h_KeLowerIrql(0);
    Check(h_KeGetCurrentIrql() == 0, "KeLowerIrql(0)->KeGetCurrentIrql()==0");
    Check(h_KeRaiseIrql(2) == 0 && h_KeGetCurrentIrql() == 2, "KeRaiseIrql(2)->0, KeGetCurrentIrql()==2");
    Check(h_KeRaiseIrqlToDpcLevel() == 2, "KeRaiseIrqlToDpcLevel() at DPC returns old IRQL 2");
    h_KeLowerIrql(0);

    // --- APC: critical region suppresses, delivery runs KernelRoutine ---
    // Structs live in the guest region; pass their guest addresses to the ke_*
    // handlers (UcPtr resolves them), read fields back from the host copies.
    Logger::Log("{CYN}=== SELFTEST: APC ==={RESET}\n");
    uint64_t ApcGuest = SelftestBase + 0x400;
    _KAPC* ApcHost = (_KAPC*)(R + 0x400);
    h_KeInitializeApc((_KAPC*)ApcGuest, (_KTHREAD*)&FakeKernelThread, 0, (void*)(SelftestBase + 0x100), nullptr, nullptr, 0, (void*)ApcMarker);
    h_KeEnterCriticalRegion();
    BOOLEAN Inserted = h_KeInsertQueueApc((_KAPC*)ApcGuest, nullptr, nullptr, 0);
    Check(Inserted && ApcHost->Inserted == 1, "KeInsertQueueApc queued while in critical region");
    h_KeLeaveCriticalRegion();
    h_KeTestAlertThread(0);
    Check(ApcHost->Inserted == 0, "APC delivered after leaving critical region (Inserted cleared)");
    volatile uint32_t* ApcMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(ApcMarker);
    for (int I = 0; I < 200 && *ApcMarkerHost != 0x41414141; I++) Sleep(10);
    Check(*ApcMarkerHost == 0x41414141, "APC KernelRoutine ran and wrote the marker");

    // --- DPC via KeInsertQueueDpc ---
    Logger::Log("{CYN}=== SELFTEST: DPC ==={RESET}\n");
    uint64_t DpcGuest = SelftestBase + 0x500;
    _KDPC* DpcHost = (_KDPC*)(R + 0x500);
    h_KeInitializeDpc((_KDPC*)DpcGuest, (void*)(SelftestBase + 0x200), (void*)DpcMarker);
    Check((uint64_t)DpcHost->DeferredRoutine == (SelftestBase + 0x200), "KeInitializeDpc stored the routine");
    Check(h_KeInsertQueueDpc((_KDPC*)DpcGuest, nullptr, nullptr), "KeInsertQueueDpc accepted the DPC");
    volatile uint32_t* DpcMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(DpcMarker);
    for (int I = 0; I < 200 && *DpcMarkerHost != 0x42424242; I++) Sleep(10);
    Check(*DpcMarkerHost == 0x42424242, "DPC routine ran");

    // --- Timer DPC fires; KeCancelTimer prevents a canceled timer's DPC ---
    Logger::Log("{CYN}=== SELFTEST: Timer ==={RESET}\n");
    uint64_t TimerGuest = SelftestBase + 0x600;
    uint64_t TimerDpcGuest = SelftestBase + 0x700;
    LARGE_INTEGER Due; Due.QuadPart = -100000;   // 10ms relative
    h_KeInitializeTimer((_KTIMER*)TimerGuest);
    h_KeInitializeDpc((_KDPC*)TimerDpcGuest, (void*)(SelftestBase + 0x350), (void*)TimerMarker);
    h_KeSetTimer((_KTIMER*)TimerGuest, Due, (_KDPC*)TimerDpcGuest);
    volatile uint32_t* TimerMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(TimerMarker);
    for (int I = 0; I < 200 && *TimerMarkerHost != 0x44444444; I++) Sleep(10);
    Check(*TimerMarkerHost == 0x44444444, "timer DPC fired after the due time");

    uint64_t CancelTimerGuest = SelftestBase + 0x800;
    uint64_t CancelDpcGuest = SelftestBase + 0x900;
    h_KeInitializeTimer((_KTIMER*)CancelTimerGuest);
    h_KeInitializeDpc((_KDPC*)CancelDpcGuest, (void*)(SelftestBase + 0x300), (void*)CancelMarker);
    h_KeSetTimer((_KTIMER*)CancelTimerGuest, Due, (_KDPC*)CancelDpcGuest);
    Check(h_KeCancelTimer((_KTIMER*)CancelTimerGuest), "KeCancelTimer cancels a pending timer");
    volatile uint32_t* CancelMarkerHost = (volatile uint32_t*)UnicornMem::UcToHost(CancelMarker);
    Sleep(100);
    Check(*CancelMarkerHost == 0, "canceled timer's DPC did not fire");

    Logger::Log("{CYN}=== SELFTEST %s (%d failures) ==={RESET}\n", Fails == 0 ? "PASS" : "FAIL", Fails);
    return Fails == 0 ? 0 : 1;
}

__forceinline void InitDirs() {
    char ExePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, ExePath, MAX_PATH);
    std::string ExePathStr = ExePath;
    auto LastSlash = ExePathStr.find_last_of("\\/");
    if (LastSlash != std::string::npos)
        KevlarGlobal::ExeDir = ExePathStr.substr(0, LastSlash + 1);
    else
        KevlarGlobal::ExeDir = ".\\";

    auto CacheDir = KevlarGlobal::GetCacheDir();
    std::filesystem::create_directories(CacheDir);
}

int main(int Argc, char* Argv[]) {
    std::set_terminate([]() {
        Logger::Log("{RED}=== std::terminate() called === (thread %u){RESET}\n", GetCurrentThreadId());
        fflush(stdout);
        fflush(stderr);
        abort();
    });

    _set_abort_behavior(0, _WRITE_ABORT_MSG);

    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ExInfo) -> LONG {
        auto Rec = ExInfo->ExceptionRecord;
        auto Ctx = ExInfo->ContextRecord;
        Logger::Log("{RED}=== KEVLAR HOST CRASH === (thread %u){RESET}\n", GetCurrentThreadId());
        Logger::Log("{RED}Exception 0x%08x at RIP=0x%llx{RESET}\n", Rec->ExceptionCode, Ctx->Rip);
        HMODULE HMod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)Ctx->Rip, &HMod);
        if (HMod) {
            char ModName[MAX_PATH] = {};
            GetModuleFileNameA(HMod, ModName, MAX_PATH);
            Logger::Log("{RED}Module: %s + 0x%llx{RESET}\n", ModName, Ctx->Rip - (uint64_t)HMod);
        }
        Logger::Log("{RED}RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx{RESET}\n",
            Ctx->Rax, Ctx->Rbx, Ctx->Rcx, Ctx->Rdx);
        Logger::Log("{RED}RSI=0x%llx RDI=0x%llx RSP=0x%llx RBP=0x%llx{RESET}\n",
            Ctx->Rsi, Ctx->Rdi, Ctx->Rsp, Ctx->Rbp);
        Logger::Log("{RED}R8=0x%llx R9=0x%llx R10=0x%llx R11=0x%llx{RESET}\n",
            Ctx->R8, Ctx->R9, Ctx->R10, Ctx->R11);
        Logger::Log("{RED}R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx{RESET}\n",
            Ctx->R12, Ctx->R13, Ctx->R14, Ctx->R15);
        if (Rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && Rec->NumberParameters >= 2) {
            Logger::Log("{RED}Access violation: %s address 0x%llx{RESET}\n",
                Rec->ExceptionInformation[0] == 0 ? "read" : "write",
                Rec->ExceptionInformation[1]);
        }
        fflush(stdout);
        fflush(stderr);
        return EXCEPTION_EXECUTE_HANDLER;
    });
    InitDirs();

    auto LogPath = KevlarGlobal::ExeDir + "kevlar.log";
    Logger::InitFile(LogPath.c_str());
    atexit(Logger::CloseFile);

    auto ThreadLogDir = KevlarGlobal::ExeDir + "easyanticheat_threads";
    if (Logger::EnablePerThreadFiles(ThreadLogDir.c_str())) {
        Logger::MarkThreadStart("main");
        Logger::Log("{CYN}Per-thread logging enabled: {WHT}%s{RESET}\n", ThreadLogDir.c_str());
    } else {
        Logger::Log("{YEL}Per-thread logging disabled: failed to initialize thread log folder{RESET}\n");
    }

    DWORD DwMode;
    auto HOut = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(HOut, &DwMode);
    DwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(HOut, DwMode);

    Logger::Log("{CYN}KEVLAR - Kernel Export Virtualization Layer And Runtime{RESET}\n");

    auto PrintUsage = [](const char* Exe) {
        Logger::Log("{WHT}Usage: %s <driver.sys> [options]{RESET}\n", Exe);
        Logger::Log("{WHT}Options:{RESET}\n");
        Logger::Log("  --diag                  Enable diagnostic hooks (slow){RESET}\n");
        Logger::Log("  --no-seh                Disable SEH dispatch{RESET}\n");
        Logger::Log("  --modreads               Enable module read logging{RESET}\n");
        Logger::Log("  --intel                 (no-op) coherent Intel CPU profile is always active{RESET}\n");
        Logger::Log("  --seed <n>              Deterministic seed for TSC jitter (default fixed){RESET}\n");
        Logger::Log("  --vgk-override          Override STATUS_ACCESS_DENIED from vgk DriverEntry{RESET}\n");
        Logger::Log("  --devirt                Enable devirtualization testing{RESET}\n");
        Logger::Log("  --strict-exports        Unhandled exports return STATUS_NOT_IMPLEMENTED instead of 0{RESET}\n");
        Logger::Log("  --provenance            Trace branch decisions + API results for rejection paths{RESET}\n");
        Logger::Log("  --trace <file>          Record deterministic execution trace{RESET}\n");
        Logger::Log("  --check <file>          Replay trace; report first divergence{RESET}\n");
        Logger::Log("  --no-pause              Skip final pause; exit ~5s after a no-thread run (automation){RESET}\n");
        Logger::Log("  --selftest              Run the ke_* semantics self-test and exit (no driver){RESET}\n");
    };

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    Logger::Log("{GRN}Process priority: HIGH, Thread priority: HIGHEST{RESET}\n");

    Logger::Log("{GRY}Downloading NTDLL Symbol...{RESET}");

    symparser::download_symbols("c:\\Windows\\System32\\ntdll.dll");

    Logger::Log("{GRY}Downloading NTOSKRNL Symbol...{RESET}");

    symparser::download_symbols("c:\\Windows\\System32\\ntoskrnl.exe");

    Logger::Log("{GRN}Downloaded Symbols{RESET}");

    if (!UnicornEmu::Initialize()) {
        Logger::Log("{RED}Failed to initialize Unicorn engine{RESET}\n");
        return 1;
    }

    Logger::Log("{GRN}Initialized.{RESET}");

    Environment::InitializeSystemModules();
    ntoskrnl_provider::Initialize();
    ntoskrnl_export::Initialize();

    UnicornEmu::PatchSystemModuleExports();
    UnicornEmu::BuildSysModFuncCache();

    Logger::Log("{CYN}Loading driver module{RESET}\n");

    std::string DriverPath;

    for (int I = 1; I < Argc; I++) {
        std::string Arg = Argv[I];
        if (Arg.rfind("--", 0) == 0) {
            if (Arg == "--vgk-override") {
                UnicornEmu::VgkErrorOverrideEnabled = true;
                Logger::Log("{CYN}VGK error override ENABLED (STATUS_ACCESS_DENIED -> STATUS_SUCCESS){RESET}\n");
            } else if (Arg == "--diag") {
                UnicornEmu::DiagnosticHooksEnabled = true;
                Logger::Log("{YEL}Diagnostic hooks ENABLED (slow mode){RESET}\n");
            } else if (Arg == "--no-seh") {
                UnicornEmu::SehDispatchEnabled = false;
                Logger::Log("{YEL}SEH dispatch DISABLED{RESET}\n");
            } else if (Arg == "--modreads") {
                UnicornEmu::ModuleReadLoggingEnabled = true;
                Logger::Log("{CYN}Module read logging ENABLED{RESET}\n");
            } else if (Arg == "--intel") {
                UnicornEmu::IntelCpuSpoofEnabled = true;
                Logger::Log("{CYN}--intel is a no-op: coherent Intel CPU profile is always active{RESET}\n");
            } else if (Arg.rfind("--seed", 0) == 0) {
                std::string Val = (Arg.size() > 6 && Arg[6] == '=')
                    ? Arg.substr(7) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    TimingSeed = strtoull(Val.c_str(), nullptr, 0);
                    Logger::Log("{CYN}Timing seed set to 0x%llx{RESET}\n", TimingSeed);
                } else {
                    Logger::Log("{RED}--seed requires a value (e.g. --seed 0x1234){RESET}\n");
                }
            } else if (Arg.rfind("--devirt", 0) == 0) {
                UnicornEmu::DevirtualizationTest = true;
                Logger::Log("{CYN}Devirtualization Testing ENABLED{RESET}\n");
            } else if (Arg == "--strict-exports") {
                UnicornEmu::StrictExportsEnabled = true;
                Logger::Log("{CYN}Strict exports ENABLED (unhandled -> STATUS_NOT_IMPLEMENTED){RESET}\n");
            } else if (Arg == "--provenance") {
                UnicornEmu::ProvenanceEnabled = true;
                if (!DiagCenter::Instance().IsEnabled())
                    DiagCenter::Instance().Initialize();
                Logger::Log("{CYN}Provenance tracing ENABLED (branch decisions + API results){RESET}\n");
            } else if (Arg.rfind("--trace", 0) == 0) {
                std::string Val = (Arg.size() > 7 && Arg[7] == '=')
                    ? Arg.substr(8) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    UnicornEmu::TraceRecordPath = Val;
                    Logger::Log("{CYN}Trace recording to %s{RESET}\n", Val.c_str());
                } else {
                    Logger::Log("{RED}--trace requires a file path{RESET}\n");
                }
            } else if (Arg.rfind("--check", 0) == 0) {
                std::string Val = (Arg.size() > 7 && Arg[7] == '=')
                    ? Arg.substr(8) : (I + 1 < Argc ? Argv[++I] : "");
                if (!Val.empty()) {
                    UnicornEmu::TraceCheckPath = Val;
                    Logger::Log("{CYN}Trace check against %s (differential validation){RESET}\n", Val.c_str());
                } else {
                    Logger::Log("{RED}--check requires a file path{RESET}\n");
                }
            } else if (Arg == "--no-pause") {
                NoPause = true;
            } else if (Arg == "--selftest") {
                SelfTest = true;
            } else if (Arg == "--pause")
            {
               system("pause");
            } else {
                Logger::Log("{RED}Unknown option: %s{RESET}\n", Arg.c_str());
                PrintUsage(Argv[0]);
                return 1;
            }
        } else {
            if (DriverPath.empty()) {
                DriverPath = Arg;
            } else {
                Logger::Log("{RED}Multiple driver paths specified: %s and %s{RESET}\n", DriverPath.c_str(), Arg.c_str());
                PrintUsage(Argv[0]);
                return 1;
            }
        }
    }

    if (SelfTest) {
        int SelfResult = RunSelfTest();
        // ExitProcess bypasses the global-destructor teardown that crashes on the
        // no-driver exit path (pre-existing: a std::string holds a stale guest pointer).
        // Flush first -- ExitProcess skips stdio flushing, which drops redirected output.
        fflush(stdout);
        fflush(stderr);
        ExitProcess((UINT)SelfResult);
    }

    if (DriverPath.empty()) {
        PrintUsage(Argv[0]);
        return 1;
    }

    Logger::Log("{CYN}[ARGS] driver=%s diag=%d vgk_override=%d{RESET}\n",
        DriverPath.c_str(),
        UnicornEmu::DiagnosticHooksEnabled ? 1 : 0,
        UnicornEmu::VgkErrorOverrideEnabled ? 1 : 0);

    Logger::Log("{GRY}Opening File...{RESET}");

    bool IsACE = false;
    {
        
    }
    auto MainModule = PEFile::Open(DriverPath, "MyDriver");
    if (!MainModule) {
        Logger::Log("{RED}Failed to open driver: {WHT}%s{RESET}\n", DriverPath.c_str());
        return 1;
    }
    Logger::Log("{GRN}File opened. {GRY}MappedBase={WHT}0x%llx {GRY}VirtSize={WHT}0x%llx {GRY}EP={WHT}0x%llx{RESET}\n",
        MainModule->GetMappedImageBase(), MainModule->GetVirtualSize(), MainModule->GetEP());

    {
        std::string Fname = DriverPath;
        auto Slash = Fname.find_last_of("\\/");
        std::string BaseNameStr = (Slash != std::string::npos) ? Fname.substr(Slash + 1) : Fname;

        int WideLen = MultiByteToWideChar(CP_ACP, 0, BaseNameStr.c_str(), -1, NULL, 0);
        DriverBaseName.resize(WideLen - 1);
        MultiByteToWideChar(CP_ACP, 0, BaseNameStr.c_str(), -1, &DriverBaseName[0], WideLen);

        DriverFullPath = L"\\SystemRoot\\system32\\drivers\\" + DriverBaseName;

        std::string SvcName = BaseNameStr;
        auto Dot = SvcName.find_last_of('.');
        if (Dot != std::string::npos)
            SvcName = SvcName.substr(0, Dot);

        static std::wstring WDriverName;
        static std::wstring WRegistryBuffer;
        int Len2 = MultiByteToWideChar(CP_ACP, 0, SvcName.c_str(), -1, NULL, 0);
        std::wstring WideSvc(Len2 - 1, 0);
        MultiByteToWideChar(CP_ACP, 0, SvcName.c_str(), -1, &WideSvc[0], Len2);

        WDriverName = L"\\Driver\\" + WideSvc;
        WRegistryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\" + WideSvc;
        DriverName = WDriverName.c_str();
        RegistryBuffer = WRegistryBuffer.c_str();

        VirtualFs::Initialize(KevlarGlobal::ExeDir, std::string(BaseNameStr.begin(), BaseNameStr.end()));
        {
            std::wstring SvcRegPath = VirtualFs::GetVregRoot() + L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\" + WideSvc;
            std::wstring SwRegPath = VirtualFs::GetVregRoot() + L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\" + WideSvc;

            std::wstring ImagePath = L"\\SystemRoot\\system32\\drivers\\" + DriverBaseName;
            VirtualReg::WriteValueToFile(SvcRegPath, L"ImagePath", 2, ImagePath.c_str(), (ULONG)((ImagePath.size() + 1) * sizeof(wchar_t)));

            uint32_t StartType = 0;
            VirtualReg::WriteValueToFile(SvcRegPath, L"Start", 4, &StartType, sizeof(StartType));

            uint32_t SvcType = 1;
            VirtualReg::WriteValueToFile(SvcRegPath, L"Type", 4, &SvcType, sizeof(SvcType));

            uint32_t ErrorControl = 1;
            VirtualReg::WriteValueToFile(SvcRegPath, L"ErrorControl", 4, &ErrorControl, sizeof(ErrorControl));

            VirtualReg::WriteValueToFile(SvcRegPath, L"DisplayName", 1, WideSvc.c_str(), (ULONG)((WideSvc.size() + 1) * sizeof(wchar_t)));

            std::error_code RegEc;
            std::filesystem::create_directories(std::filesystem::path(SwRegPath), RegEc);
        }
    }

    if (!UnicornEmu::MapDriverImage(MainModule, DRIVER_BASE_UC)) {
        Logger::Log("{RED}Failed to map driver image into Unicorn{RESET}\n");
        return 1;
    }
    Logger::Log("{GRN}Driver mapped. {GRY}Resolving imports.{RESET}\n");

    Logger::Log("{GRY}Resolving Imports...{RESET}");
    MainModule->ResolveImport();
    Logger::Log("{GRN}Imports Resolved.{RESET}\n");

    UnicornEmu::BuildSentinelIat(MainModule);

    PopulateKernelStructs();
    SetupDriverLdrEntry(MainModule);

    drvObj.DriverStart = (PVOID)DRIVER_BASE_UC;
    drvObj.DriverSize = (ULONG)MainModule->GetVirtualSize();
    drvObj.DriverInit = (decltype(drvObj.DriverInit))(DRIVER_BASE_UC + MainModule->GetEP());

    {
        uint64_t ExtSize = sizeof(_DRIVER_EXTENSION) + 0x200;
        uint64_t ExtUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, ExtSize, "DriverExtension");
        auto ExtHost = (_DRIVER_EXTENSION*)UnicornMem::UcToHost(ExtUcAddr);
        memset(ExtHost, 0, ExtSize);
        ExtHost->DriverObject = (_DRIVER_OBJECT*)DRIVER_OBJ_BASE_UC;

        size_t SvcNameOff = sizeof(_DRIVER_EXTENSION);
        SvcNameOff = (SvcNameOff + 0xF) & ~0xFULL;
        size_t SvcBytes = (wcslen(RegistryBuffer) + 1) * sizeof(wchar_t);
        if (SvcNameOff + SvcBytes < ExtSize) {
            memcpy((uint8_t*)ExtHost + SvcNameOff, RegistryBuffer, SvcBytes);
            ExtHost->ServiceKeyName.Buffer = (WCHAR*)(ExtUcAddr + SvcNameOff);
            ExtHost->ServiceKeyName.Length = (USHORT)(wcslen(RegistryBuffer) * sizeof(wchar_t));
            ExtHost->ServiceKeyName.MaximumLength = ExtHost->ServiceKeyName.Length + sizeof(wchar_t);
        }

        drvObj.DriverExtension = (_DRIVER_EXTENSION*)ExtUcAddr;
        Logger::Log("{GRY}DriverExtension at UC {WHT}0x%llx{RESET}\n", ExtUcAddr);
    }

    {
        static const wchar_t* HwDbPath = L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\System";
        uint64_t HwDbSize = sizeof(UNICODE_STRING) + 0x100;
        uint64_t HwDbUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, HwDbSize, "HardwareDatabase");
        auto HwDbHost = (UNICODE_STRING*)UnicornMem::UcToHost(HwDbUcAddr);
        memset(HwDbHost, 0, HwDbSize);

        size_t StrOff = sizeof(UNICODE_STRING);
        StrOff = (StrOff + 0xF) & ~0xFULL;
        size_t StrBytes = (wcslen(HwDbPath) + 1) * sizeof(wchar_t);
        memcpy((uint8_t*)HwDbHost + StrOff, HwDbPath, StrBytes);
        HwDbHost->Buffer = (WCHAR*)(HwDbUcAddr + StrOff);
        HwDbHost->Length = (USHORT)(wcslen(HwDbPath) * sizeof(wchar_t));
        HwDbHost->MaximumLength = HwDbHost->Length + sizeof(wchar_t);

        drvObj.HardwareDatabase = (_PRIMITIVE_UNICODE_STRING*)HwDbUcAddr;
    }

    Logger::Log("{CYN}DRIVER_OBJECT: {WHT}Start={GRY}0x%llx {WHT}Size={GRY}0x%x {WHT}Section={GRY}0x%llx {WHT}Init={GRY}0x%llx {WHT}Ext={GRY}0x%llx{RESET}\n",
        (uint64_t)drvObj.DriverStart, drvObj.DriverSize,
        (uint64_t)drvObj.DriverSection, (uint64_t)drvObj.DriverInit,
        (uint64_t)drvObj.DriverExtension);

    UnicornEmu::MapKernelStructs();
    UnicornEmu::MapKuserSharedData();

    UnicornEmu::InstallWatchpoints(UnicornEmu::PrimaryEngine);

    if (!UnicornEmu::TraceRecordPath.empty() || !UnicornEmu::TraceCheckPath.empty() || UnicornEmu::ProvenanceEnabled) {
        UnicornEmu::InstallTraceCapture(UnicornEmu::PrimaryEngine, DRIVER_BASE_UC, MainModule->GetVirtualSize());
    }

    //UnicornEmu::InstallFocusedTrace(UnicornEmu::PrimaryEngine,
    //    DRIVER_BASE_UC + 0x11000, DRIVER_BASE_UC + 0x12FFF);

    //UnicornEmu::InstallStackWriteWatch(UnicornEmu::PrimaryEngine,
    //    STACK_BASE_UC + 0x3FC80, 0x80);

    {
        Logger::Log("{CYN}=== PsLoadedModuleList validation ==={RESET}\n");
        uint64_t ListHead = (uint64_t)Environment::PsLoadedModuleList;
        Logger::Log("{GRY}PsLoadedModuleList sentinel at UC {WHT}0x%llx{RESET}\n", ListHead);

        auto SentinelHost = (LIST_ENTRY*)UnicornMem::UcToHost(ListHead);
        if (SentinelHost) {
            uint64_t CurrentUc = (uint64_t)SentinelHost->Flink;
            int ModCount = 0;
            while (CurrentUc && CurrentUc != ListHead && ModCount < 300) {
                auto CurrentHost = (KLDR_DATA_TABLE_ENTRY*)UnicornMem::UcToHost(CurrentUc);
                if (!CurrentHost) {
                    Logger::Log("{RED}  [%d] UC 0x%llx -> HOST NULL (broken link!){RESET}\n", ModCount, CurrentUc);
                    break;
                }

                uint64_t DllBaseVal = (uint64_t)CurrentHost->DllBase;

                wchar_t NameBuf[256] = { 0 };
                if (CurrentHost->BaseDllName.Buffer && CurrentHost->BaseDllName.Length > 0) {
                    auto NameHost = (wchar_t*)UnicornMem::UcToHost((uint64_t)CurrentHost->BaseDllName.Buffer);
                    if (NameHost) {
                        size_t CopyLen = CurrentHost->BaseDllName.Length / sizeof(wchar_t);
                        if (CopyLen > 255) CopyLen = 255;
                        memcpy(NameBuf, NameHost, CopyLen * sizeof(wchar_t));
                    }
                }

                if (DllBaseVal != 0) {
                    Logger::Log("{GRY}  [%d] UC {WHT}0x%llx{GRY}: DllBase={WHT}0x%llx {GRY}Size={WHT}0x%x {GRY}Name={WHT}%ws{RESET}\n",
                        ModCount, CurrentUc, DllBaseVal, CurrentHost->SizeOfImage, NameBuf);
                }

                CurrentUc = (uint64_t)CurrentHost->InLoadOrderLinks.Flink;
                ModCount++;
            }
            Logger::Log("{CYN}=== %d modules in list ==={RESET}\n", ModCount);
        } else {
            Logger::Log("{RED}PsLoadedModuleList sentinel host lookup FAILED{RESET}\n");
        }
    }

    Logger::Log("{CYN}Starting DriverEntry at RVA {WHT}0x%llx{RESET}\n", MainModule->GetEP());

    bool Result = UnicornEmu::StartEmulation(UnicornEmu::PrimaryEngine, DRIVER_BASE_UC + MainModule->GetEP());

    if (Result)
        Logger::Log("{GRN}DriverEntry completed successfully{RESET}\n");
    else
        Logger::Log("{RED}DriverEntry failed or was stopped{RESET}\n");

    Logger::Log("{MAG}Waiting for spawned threads (will keep alive up to 3600s for deferred work)...{RESET}\n");

    {
        LARGE_INTEGER WaitStart;
        QueryPerformanceCounter(&WaitStart);
        LARGE_INTEGER WaitFreq;
        QueryPerformanceFrequency(&WaitFreq);
        const double MaxWaitSeconds = 3600.0;
        int LastReportSec = 0;
        bool EverHadThreads = false;
        int IdleCycles = 0;

        while (true) {
            bool AnyRunning = false;
            int TotalThreads = 0;
            int RunningThreads = 0;
            {
                std::lock_guard<std::mutex> Lock(UnicornThread::ThreadLock);
                TotalThreads = (int)UnicornThread::ThreadMap.size();
                for (auto& [Id, Ctx] : UnicornThread::ThreadMap) {
                    if (Ctx->Running) {
                        RunningThreads++;
                        AnyRunning = true;
                    }
                }
            }

            if (AnyRunning) {
                EverHadThreads = true;
                IdleCycles = 0;
            }

            LARGE_INTEGER Now;
            QueryPerformanceCounter(&Now);
            double Elapsed = (double)(Now.QuadPart - WaitStart.QuadPart) / (double)WaitFreq.QuadPart;
            int ElapsedSec = (int)Elapsed;

            if (ElapsedSec >= LastReportSec + 10) {
                LastReportSec = ElapsedSec;
                Logger::Log("{GRY}[ALIVE %.0fs] threads: %d total, %d running%s{RESET}\n",
                    Elapsed, TotalThreads, RunningThreads,
                    EverHadThreads ? "" : " (waiting for first thread)");
            }

            if (EverHadThreads && !AnyRunning) {
                IdleCycles++;
                if (IdleCycles > 50) {
                    Logger::Log("{CYN}All spawned threads finished after %.1fs{RESET}\n", Elapsed);
                    break;
                }
            }

            double NoThreadTimeout = NoPause ? 5.0 : MaxWaitSeconds;
            if (!EverHadThreads && Elapsed >= NoThreadTimeout) {
                Logger::Log("{YEL}No threads spawned after %.0fs — giving up{RESET}\n", Elapsed);
                break;
            }

            Sleep(100);
        }
    }

    Logger::Log("{GRN}Done. Press any key to exit.{RESET}\n");
    if (!NoPause)
        system("pause");

    UnicornEmu::Shutdown();
    Logger::MarkThreadEnd("main");

    return 0;
}
