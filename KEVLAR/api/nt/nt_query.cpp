#include "nt_query.h"
#include "core/registry/virtual_fs.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/memory/unicorn_memory.h"
#include "core/diagnostics/diag_center.h"

static uint64_t gNtQueryLastClass = 0;
static uint64_t gNtQueryLastCallerRva = 0;

static std::mutex gFirmwareHookLock;
static std::vector<uint64_t> gFirmwareHookedAddsrs;
static uint64_t gFirmwareHookedAddrs[16] = {};
static int gFirmwareHookedCount = 0;
static void* gFirmwareHookedBufs[16] = {};
static int gFirmwareHookedBufCount = 0;

static std::mutex gBootEnvHookLock;
static uint64_t gBootEnvUcAddr = 0;
static void* gBootEnvLocalBuf = nullptr;
static uint64_t gBootEnvCallerRva = 0;

static std::mutex gCiHookLock;
static uint64_t gCiUcAddr = 0;
static void* gCiLocalBuf = nullptr;
static uint64_t gCiCallerRva = 0;

static std::mutex gHvPageHookLock;
static uint64_t gHvPageUcAddr = 0;
static void* gHvPageLocalBuf = nullptr;
static uint64_t gHvPageCallerRva = 0;

static std::mutex gCallerRvaLock;
static uint64_t gNtQueryCallerRvaStack[8] = {};
static int gCallerRvaStackTop = 0;

static uc_engine* GetActiveEngine() {
    auto Engine = UnicornThread::GetCurrentEngine();
    return Engine ? Engine : UnicornEmu::PrimaryEngine;
}

static void PushCallerRva(uint64_t Rva) {
    std::lock_guard<std::mutex> lk(gCallerRvaLock);
    if (gCallerRvaStackTop < 8) gNtQueryCallerRvaStack[gCallerRvaStackTop++] = Rva;
}
static uint64_t PopCallerRva(void) {
    std::lock_guard<std::mutex> lk(gCallerRvaLock);
    return (gCallerRvaStackTop > 0) ? gNtQueryCallerRvaStack[--gCallerRvaStackTop] : 0;
}

static const char* GetSystemInfoClassName(uint32_t cls) {
    switch (cls) {
    case 0x00: return "SystemBasicInformation";
    case 0x01: return "SystemProcessorInformation";
    case 0x02: return "SystemPerformanceInformation";
    case 0x03: return "SystemTimeOfDayInformation";
    case 0x04: return "SystemPathInformation";
    case 0x05: return "SystemProcessInformation";
    case 0x06: return "SystemCallCountInformation";
    case 0x07: return "SystemDeviceInformation";
    case 0x08: return "SystemProcessorPerformanceInformation";
    case 0x09: return "SystemFlagsInformation";
    case 0x0A: return "SystemCallTimeInformation";
    case 0x0B: return "SystemModuleInformation";
    case 0x0C: return "SystemLocksInformation";
    case 0x0D: return "SystemStackTraceInformation";
    case 0x0E: return "SystemPoolEntryInformation";
    case 0x0F: return "SystemPoolTagInformation";
    case 0x10: return "SystemHandleInformation";
    case 0x11: return "SystemObjectInformation";
    case 0x12: return "SystemFileCacheInformation";
    case 0x13: return "SystemPoolTagCheckInformation";
    case 0x14: return "SystemTimeZoneInformation";
    case 0x15: return "SystemLookasideInformation";
    case 0x16: return "SystemSetTimeZoneInformation";
    case 0x17: return "SystemThreadInformation";
    case 0x18: return "SystemSectorClusterInformation";
    case 0x19: return "SystemLocksInformation";
    case 0x1A: return "SystemLegacyClusterInformation";
    case 0x1B: return "SystemAccessInformation";
    case 0x1C: return "SystemQueryPerformanceInformation";
    case 0x1D: return "SystemSessionConnectInformation";
    case 0x1E: return "SystemResGpu RendezvousInformation";
    case 0x1F: return "SystemSessionConnectInformation";
    case 0x20: return "SystemSystemSharesInformation";
    case 0x21: return "SystemSystemCodeInformation";
    case 0x22: return "SystemSystemCallHookInformation";
    case 0x23: return "SystemKernelDebuggerInformation";
    case 0x24: return "SystemContextInformation";
    case 0x25: return "SystemEntityQuotaInformation";
    case 0x26: return "SystemSystemInformation";
    case 0x27: return "SystemPolicyInformation";
    case 0x28: return "SystemProcessIdInformation";
    case 0x3D: return "SystemX64Data";
    case 0x40: return "SystemExtendedHandleInformation";
    case 0x4D: return "SystemModuleInformationEx";
    case 0x5A: return "SystemBootEnvironmentInformation";
    case 0x67: return "SystemFirmwareTableInformation";
    case 0x5F: return "SystemSpecialPoolInformation";
    case 0x63: return "SystemAllowedCpuSetsInformation";
    case 0x68: return "SystemMemoryTopologyInformation";
    case 0x6C: return "SystemThreadChoiceInformation";
    case 0x6E: return "SystemHypervisorSharedPageInformation";
    case 0x6F: return "SystemFreeLogicalClockInformation";
    case 0x73: return "SystemPhysicalMonitoring";
    case 0x74: return "SystemMcaLog";
    case 0x78: return "SystemNumaProfiler";
    case 0x7D: return "SystemNumaProximityDomainInformation";
    case 0x7E: return "SystemNumaProximityDomainInformation";
    case 0x80: return "SystemMemoryListInformation";
    case 0x81: return "SystemCommitLimitInformation";
    case 0x82: return "SystemVantiySetInformation";
    case 0x83: return "SystemPhysicalPagesInformation";
    case 0x84: return "SystemLogicalPagesInformation";
    case 0x85: return "SystemPhysicalMemoryMonitor";
    case 0x86: return "SystemLargePageFaultInformation";
    case 0x87: return "SystemCreateSessionInformation";
    case 0x88: return "SystemBootLog";
    case 0x89: return "SystemSessionManagerMap";
    case 0x8A: return "SystemPolicyBody";
    case 0x8B: return "SystemDeviceInformationEx";
    case 0x8C: return "SystemBasicBackupInformation";
    case 0x8D: return "SystemInternalCpuSets";
    case 0x8E: return "SystemBigPoolEntryInformation";
    case 0x8F: return "SystemDmaTransferInformation";
    case 0x90: return "SystemPoolZeroBitInformation";
    case 0x91: return "SystemCodeIntegrityPolicyInformation";
    case 0x92: return "SystemIsolatedUserModeInformation";
    case 0x93: return "SystemHypervisorProcessorCountInformation";
    case 0x94: return "SystemHwCountersProductInformation";
    case 0x95: return "SystemSecureKernelDebuggerInformation";
    case 0x97: return "System卸andom PhysicalPagesInformation";
    case 0x9E: return "SystemEli国土";
    case 0xA0: return "SystemDmaAdapterInformation";
    case 0xA1: return "SystemDmaChannelInformation";
    case 0xA2: return "SystemFullProcessStopInformation";
    case 0xA3: return "SystemDatabaseBackup";
    case 0xA4: return "SystemMcaDriStationInformation";
    case 0xA5: return "SystemOpaqueDiagnosticInformation";
    case 0xA6: return "SystemPersistentMemoryBank Information";
    case 0xA7: return "SystemPersistentMemoryBank";
    case 0xA8: return "SystemBuildAfdNameInformation";
    case 0xA9: return "SystemDbgRpcQueryInformation";
    case 0xAA: return "SystemKernelFUSInformation";
    case 0xAB: return "SystemFreePagesInformation";
    case 0xAC: return "SystemHighEventPriorityInformation";
    case 0xAD: return "SystemPool憎";
    case 0xAE: return "SystemAcpiAuditInformation";
    case 0xAF: return "SystemByteLogicPages";
    case 0xB0: return "SystemSession PoolAllocationInfo";
    case 0xB1: return "SystemHypervisorSharedPageInformation";
    case 0xB2: return "SystemKTM";
    case 0xB3: return "SystemMemoryUsedTable";
    case 0xB4: return "SystemKernelConfig";
    case 0xB5: return "SystemSpecialPoolRelocationInformation";
    case 0xB6: return "SystemInstructionMixProbe";
    case 0xB7: return "SystemMcaExceptionInformation";
    case 0xB8: return "SystemKernelDebugInformation";
    case 0xB9: return "SystemProcessorMicrocodeInformation";
    case 0xBA: return "SystemSpecialPoolAllocationInformation";
    case 0xBB: return "SystemSecureKernelDebuggerInformation";
    case 0xBC: return "SystemCpuSetInformation";
    case 0xBD: return "SystemMcaExceptionInformation";
    case 0xBE: return "SystemSpecialPoolRelocationInformation";
    case 0xBF: return "SystemKernelDebugInformation";
    case 0xC0: return "SystemKernelVirtualizationInformation";
    case 0xC2: return "SystemCriticalProcessDefaultCpuSetInformation";
    case 0xC3: return "SystemEnhancedGraphicsInitiatIOr";
    case 0xC4: return "SystemThreadChoiceCpuSetInformation";
    case 0xC5: return "SystemHypervisorSharedPageInformation";
    case 0xC7: return "SystemSecureKernelDebuggerMode";
    case 0xC9: return "SystemCpuSetTagInformation";
    case 0xCA: return "SystemSecureKernelDebuggerInformation";
    case 0xCB: return "SystemDeletedSharedMemory";
    case 0xCC: return "SystemSystemPublisherInformation";
    case 0xCD: return "SystemMcaExceptionInformation";
    case 0xCE: return "SystemNumaMemoryB Configuration";
    case 0xCF: return "SystemNumaNodeInformation";
    case 0xD0: return "SystemPoolEntryCheckInformation";
    case 0xD1: return "SystemDmaAdapterInformation";
    case 0xD2: return "SystemDmaChannelInformation";
    case 0xD3: return "SystemSecureKernelDebuggerMode";
    case 0xD4: return "SystemKernelDebuggerInformation";
    case 0xD5: return "SystemPersistentMemoryGarbageCollection";
    case 0xD6: return "SystemMcaException";
    case 0xD7: return "SystemMcaException";
    case 0xD8: return "SystemNumaNodeInformation";
    case 0xD9: return "SystemMcaException";
    case 0xDA: return "SystemSpecialPoolAllocationInformation";
    case 0xDB: return "SystemKernelDebuggerInformation";
    case 0xDC: return "SystemMcaException";
    case 0xDD: return "SystemMcaException";
    case 0xDE: return "SystemSecureKernelDebuggerMode";
    case 0xDF: return "SystemKernelDebuggerInformation";
    case 0xE0: return "SystemNumaNodeInformation";
    case 0xE1: return "SystemMcaException";
    case 0xE2: return "SystemSpecialPoolRelocationInformation";
    case 0xE3: return "SystemKernelDebuggerInformation";
    case 0xE4: return "SystemMcaException";
    case 0xE5: return "SystemMcaException";
    case 0xE6: return "SystemMcaException";
    case 0xE7: return "SystemKernelDebuggerInformation";
    case 0xE8: return "SystemNumaNodeInformation";
    case 0xE9: return "SystemMcaException";
    case 0xEA: return "SystemSpecialPoolRelocationInformation";
    case 0xEB: return "SystemKernelDebuggerInformation";
    case 0xEC: return "SystemMcaException";
    case 0xED: return "SystemMcaException";
    case 0xEE: return "SystemKernelDebuggerInformation";
    case 0xEF: return "SystemMcaException";
    case 0xF0: return "SystemNumaNodeInformation";
    case 0xF1: return "SystemMcaException";
    case 0xF2: return "SystemMcaException";
    case 0xF3: return "SystemKernelDebuggerInformation";
    case 0xF4: return "SystemMcaException";
    case 0xF5: return "SystemMcaException";
    case 0xF6: return "SystemKernelDebuggerInformation";
    case 0xF7: return "SystemMcaException";
    case 0xF8: return "SystemNumaNodeInformation";
    case 0xF9: return "SystemMcaException";
    case 0xFA: return "SystemSpecialPoolRelocationInformation";
    case 0xFB: return "SystemKernelDebuggerInformation";
    case 0xFC: return "SystemMcaException";
    case 0xFD: return "SystemMcaException";
    case 0xFE: return "SystemKernelDebuggerInformation";
    case 0xFF: return "SystemMcaException";
    default: return "Unknown";
    }
}

static NTSTATUS SafeNtQuerySystemInformation(uint32_t Class, uintptr_t Buf, ULONG Len, PULONG RetLen) {
    __try {
        return NtQuerySystemInformation(Class, Buf, Len, RetLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}SafeNtQuerySystemInformation CRASH: class=0x%x buf=0x%llx len=0x%x retLen=%p exception=0x%08x{RESET}\n",
            Class, (uint64_t)Buf, Len, RetLen, GetExceptionCode());
        return 0xC0000005;
    }
}

static NTSTATUS SafeNtQuerySystemInformationLocalBuf(uint32_t Class, ULONG Len, PULONG RetLen, uint8_t* LocalBuf, ULONG LocalBufSize) {
    ULONG RequiredLen = 0;
    NTSTATUS Status;
    __try {
        Status = NtQuerySystemInformation(Class, LocalBuf, LocalBufSize, &RequiredLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}SafeNtQuerySystemInformationLocalBuf CRASH: class=0x%x exception=0x%08x{RESET}\n",
            Class, GetExceptionCode());
        Status = 0xC0000005;
    }
    if (RetLen) *RetLen = RequiredLen;
    return Status;
}

static const char* GetFirmwareTableProviderName(uint32_t sig) {
    switch (sig) {
    case 0x41445343: return "ACPI";
    case 0x534D4243: return "SMBIOS";
    case 0x534D5043: return "SMBIOS3";
    case 0x52464453: return "RAW";
    case 0x53444253: return "SBB_HV_"; // Hyper-V synthetic firmware
    default: return "Unknown";
    }
}

static uint64_t GetNtQueryCallerRva(void) {
    uint64_t StackPtr = 0;
    auto Engine = GetActiveEngine();
    if (!Engine) return 0;
    uc_reg_read(Engine, UC_X86_REG_RSP, &StackPtr);
    uint64_t RetAddr = 0;
    if (StackPtr && uc_mem_read(Engine, StackPtr, &RetAddr, 8) == UC_ERR_OK) {
        if (RetAddr >= SYSMOD_BASE_UC && RetAddr < SYSMOD_BASE_UC + 0x10000000ULL) {
            return RetAddr - SYSMOD_BASE_UC;
        }
        if (RetAddr >= DRIVER_BASE_UC && RetAddr < DRIVER_BASE_UC + 0x10000000ULL) {
            return RetAddr - DRIVER_BASE_UC;
        }
    }
    return 0;
}

static bool ShouldInjectHyperVideoModule(const char* modulename) {
    static const char* HyperVDrivers[] = {
        "hypervideo.sys", "vm3dmp.sys", "vboxguest.sys", "vboxvideo.sys",
        "vboxsf.sys", "vboxmouse.sys", "prl_kmdd.sys", "vrd.sys",
        "viostor.sys", "vioscsi.sys", "dbgv.sys", "PROCMON23.sys", "dbk64.sys"
    };
    for (int i = 0; i < 13; i++) {
        if (_stricmp(modulename, HyperVDrivers[i]) == 0) return true;
    }
    return false;
}

static uint64_t GetModuleUcBase(PEFile* Module) {
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (Mod.Pe == Module) return Mod.UcBase;
    }
    uint64_t HostBase = Module->GetMappedImageBase();
    for (auto& Region : UnicornEmu::MappedRegions) {
        if (Region.HostPtr == (void*)HostBase)
            return Region.UcBase;
    }
    return HostBase;
}

static uint64_t FindModuleUcBaseByName(const char* ModuleName) {
    std::string NameLower = ModuleName;
    for (auto& C : NameLower) C = (char)tolower((unsigned char)C);

    for (auto& [UcAddr, Entry] : Environment::environment_module) {
        if (!Entry.BaseDllName.Buffer || !Entry.BaseDllName.Length) continue;
        std::wstring WName(Entry.BaseDllName.Buffer, Entry.BaseDllName.Length / sizeof(wchar_t));
        std::string EntryName(WName.begin(), WName.end());
        for (auto& C : EntryName) C = (char)tolower((unsigned char)C);
        if (EntryName == NameLower)
            return (uint64_t)Entry.DllBase;
    }
    return 0;
}

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#ifndef STATUS_INVALID_PARAMETER
    // It is now defined in Windows 2008 SDK.
    #define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#define STATUS_CONFLICTING_ADDRESSES ((NTSTATUS)0xC0000018L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007AL)
#define STATUS_INVALID_IMAGE_FORMAT ((NTSTATUS)0xC000007BL)
#define STATUS_NO_TOKEN ((NTSTATUS)0xC000007CL)

#define CURRENT_PROCESS ((HANDLE)-1)
#define CURRENT_THREAD ((HANDLE)-2)
#define NtCurrentProcess CURRENT_PROCESS

static bool IsBlacklistedModule(const char* ModuleName) {
    static const char* Blacklist[] = {
        "vmci.sys", "vsock.sys", "vmx86.sys", "vmnet.sys",
        "vmnetbridge.sys", "vmnetuserif.sys", "vm3dmp.sys",
        "vm3dmp-debug.sys", "vm3dmp-stats.sys", "vm3dmp_loader.sys",
        "vmhgfs.sys", "vmmouse.sys", "vmusbmouse.sys", "vmrawdsk.sys",
        "vmmemctl.sys", "vmxnet3.sys",
        "parsecvusba.sys",
        "droidcamvideo.sys", "droidcamaudio.sys",
        "iriuna0.sys",
        "vbaudio_cable64_win10.sys",
        "vboxguest.sys", "vboxsf.sys", "vboxmouse.sys", "vboxvideo.sys",
    };
    std::string NameLower = ModuleName;
    for (auto& C : NameLower) C = (char)tolower(C);
    for (auto& Bl : Blacklist) {
        if (NameLower == Bl)
            return true;
    }
    return false;
}

NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

    uint64_t CallerRva = 0;
    uint64_t StackPtr = 0;
    auto Engine = GetActiveEngine();
    if (Engine) {
        uc_reg_read(Engine, UC_X86_REG_RSP, &StackPtr);
    }
    uint64_t RetAddr = 0;
    if (Engine && StackPtr && uc_mem_read(Engine, StackPtr, &RetAddr, 8) == UC_ERR_OK) {
        if (RetAddr >= DRIVER_BASE_UC && RetAddr < DRIVER_BASE_UC + 0x10000000ULL) {
            CallerRva = RetAddr - DRIVER_BASE_UC;
        }
    }

    gNtQueryLastClass = SystemInformationClass;
    gNtQueryLastCallerRva = CallerRva;

    auto HostSysInfo = (uintptr_t)UnicornMem::UcToHost(SystemInformation);
    bool HostBufValid = (HostSysInfo != 0);
    auto HostRetLenRaw = (uintptr_t)UnicornMem::UcToHost((uint64_t)ReturnLength);
    PULONG HostRetLen = HostRetLenRaw ? (PULONG)HostRetLenRaw : nullptr;
    ULONG ReportedRetLen = 0;
    bool HasReportedRetLen = false;
    auto WriteRetLen = [&](ULONG Val) {
        if ((uintptr_t)ReturnLength == 0) return;
        if (HostRetLenRaw) {
            *(PULONG)HostRetLenRaw = Val;
        } else {
            if (Engine) {
                uc_mem_write(Engine, (uint64_t)ReturnLength, &Val, sizeof(ULONG));
            }
        }
        ReportedRetLen = Val;
        HasReportedRetLen = true;
    };

    const char* ClassName = GetSystemInfoClassName(SystemInformationClass);
    Logger::Log("{CYN}NtQuerySystemInformation: class=0x%x (%s) buf=0x%llx hostBuf=0x%llx valid=%d len=0x%x retLen=%p hostRetLen=%p caller=drv+0x%llx{RESET}\n",
        SystemInformationClass, ClassName, (uint64_t)SystemInformation, (uint64_t)HostSysInfo, HostBufValid, SystemInformationLength, ReturnLength, HostRetLen, CallerRva);

    if (SystemInformationClass == 0x10) {
        ULONG RequiredSize = sizeof(ULONG);
        WriteRetLen(RequiredSize);
        if (SystemInformationLength < RequiredSize) {
            Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0x%x{YEL} ({YEL}%s{YEL}) bufLen={WHT}0x%x{YEL} -> STATUS_BUFFER_OVERFLOW {YEL}caller=drv+0x%llx{RESET}\n",
                SystemInformationClass, ClassName, SystemInformationLength, CallerRva);
            return (NTSTATUS)0xC0000004;
        }
        if (HostBufValid) {
            *(ULONG*)HostSysInfo = 0;
        } else {
            ULONG Zero = 0;
            if (Engine) {
                uc_mem_write(Engine, SystemInformation, &Zero, sizeof(ULONG));
            }
        }
        Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0x%x {YEL}(%s) {YEL}bufLen={WHT}0x%x {YEL}-> fake empty (0 handles) {YEL}caller=drv+0x%llx{RESET}\n",
            SystemInformationClass, ClassName, SystemInformationLength, CallerRva);
        return 0;
    }

    if (SystemInformationClass == 0x40) {
        ULONG RequiredSize = sizeof(ULONG) + sizeof(ULONG);
        WriteRetLen(RequiredSize);
        if (SystemInformationLength < RequiredSize) {
            Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0x%x{YEL} ({YEL}%s{YEL}) {YEL}bufLen={WHT}0x%x{YEL} -> buffer too small {YEL}caller=drv+0x%llx{RESET}\n",
                SystemInformationClass, ClassName, SystemInformationLength, CallerRva);
            return (NTSTATUS)0xC0000004;
        }
        if (HostBufValid) {
            memset((void*)HostSysInfo, 0, RequiredSize);
        } else {
            uint8_t ZeroBuf[8] = {};
            if (Engine) {
                uc_mem_write(Engine, SystemInformation, ZeroBuf, RequiredSize);
            }
        }
        Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0x%x {YEL}(%s) {YEL}bufLen={WHT}0x%x {YEL}-> fake empty {YEL}caller=drv+0x%llx{RESET}\n",
            SystemInformationClass, ClassName, SystemInformationLength, CallerRva);
        return 0;
    }

    uint8_t FakeOutBuf[0x100];
    auto WriteBuf = [&](uint8_t* Src, ULONG Len) {
        if (HostBufValid) {
            memcpy((void*)HostSysInfo, Src, Len);
        } else {
            if (Engine) {
                uc_mem_write(Engine, SystemInformation, Src, Len);
            }
        }
    };
    auto ReadBuf = [&](uint8_t* Dst, ULONG Len) {
        if (HostBufValid) {
            memcpy(Dst, (void*)HostSysInfo, Len);
        } else {
            if (Engine) {
                uc_mem_read(Engine, SystemInformation, Dst, Len);
            }
        }
    };

    if (SystemInformationClass == 0x5A) {
        ULONG RequiredSize = 0x20;
        WriteRetLen(RequiredSize);
        if (SystemInformationLength < RequiredSize) {
            Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0x5A{MAG} (SystemBootEnvironmentInformation) {MAG}bufLen={WHT}0x%x {MAG}-> STATUS_BUFFER_OVERFLOW {MAG}caller=drv+0x%llx{RESET}\n",
                SystemInformationLength, CallerRva);
            return (NTSTATUS)0xC0000004;
        }
        uint64_t FakeBootEnvBufAddr = 0xFFFFF80200180000ULL;
        {
            std::lock_guard<std::mutex> lk(gBootEnvHookLock);
            gBootEnvUcAddr = FakeBootEnvBufAddr;
            gBootEnvLocalBuf = (void*)0xFFFFF80200180000ULL;
            gBootEnvCallerRva = CallerRva;
        }
        memset(FakeOutBuf, 0, 0x20);
        *(uint32_t*)(FakeOutBuf + 0x00) = 0x5A3F9EB2;
        *(uint32_t*)(FakeOutBuf + 0x04) = 0x428B4E1D;
        *(uint32_t*)(FakeOutBuf + 0x08) = 0x5FB8A42C;
        *(uint32_t*)(FakeOutBuf + 0x0C) = 0x45678B1F;
        *(uint32_t*)(FakeOutBuf + 0x10) = 0x02;
        *(uint64_t*)(FakeOutBuf + 0x18) = 0x0000000000000001ULL;
        WriteBuf(FakeOutBuf, 0x20);
        Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0x5A{MAG} (SystemBootEnvironmentInformation) {MAG}-> BootIdentifier=0x5A3F9EB2... FirmwareType=UEFI(2) BootFlags=0x1 {MAG}caller=drv+0x%llx{RESET}\n", CallerRva);
        if (DIAG_IS_ENABLED()) {
            BootEnvReadEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.AccessType = ACCESS_API;
            Ev.BufferAddr = SystemInformation;
            Ev.BufferLen = SystemInformationLength;
            Ev.Status = 0;
            Ev.FirmwareType = 2;
            Ev.BootFlags = 1;
            DIAG_BOOTENV_READ(Ev);
        }
        return 0;
    }

    if (SystemInformationClass == 0x91) {
        ULONG RequiredSize = 0x20;
        WriteRetLen(RequiredSize);
        if (SystemInformationLength < RequiredSize) {
            Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0x91{MAG} (SystemCodeIntegrityPolicyInformation) {MAG}bufLen={WHT}0x%x {MAG}-> STATUS_BUFFER_OVERFLOW {MAG}caller=drv+0x%llx{RESET}\n",
                SystemInformationLength, CallerRva);
            return (NTSTATUS)0x80000005;
        }
        uint64_t FakeCIPolicyBufAddr = 0xFFFFF80200190000ULL;
        {
            std::lock_guard<std::mutex> lk(gCiHookLock);
            gCiUcAddr = FakeCIPolicyBufAddr;
            gCiLocalBuf = (void*)0xFFFFF80200190000ULL;
            gCiCallerRva = CallerRva;
        }
        memset(FakeOutBuf, 0, RequiredSize);
        *(uint32_t*)(FakeOutBuf + 0x00) = 0x01;
        *(uint32_t*)(FakeOutBuf + 0x04) = 0x00;
        *(uint64_t*)(FakeOutBuf + 0x08) = 0x0000000100000000ULL;
        *(uint8_t*)(FakeOutBuf + 0x10) = 0;
        *(uint8_t*)(FakeOutBuf + 0x11) = 0;
        *(uint8_t*)(FakeOutBuf + 0x12) = 0;
        *(uint8_t*)(FakeOutBuf + 0x13) = 0;
        WriteBuf(FakeOutBuf, RequiredSize);
        Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0x91{MAG} (SystemCodeIntegrityPolicyInformation) {MAG}-> Options=0x01 HVCI=0x00 Version=1.0.0.0 PolicyGuid=NULL {MAG}caller=drv+0x%llx{RESET}\n", CallerRva);
        if (DIAG_IS_ENABLED()) {
            CiReadEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.AccessType = ACCESS_API;
            Ev.BufferAddr = SystemInformation;
            Ev.BufferLen = SystemInformationLength;
            Ev.Status = 0;
            Ev.Options = 0x01;
            Ev.HVCIOptions = 0x00;
            Ev.Version = 0x0000000100000000ULL;
            DIAG_CI_READ(Ev);
        }
        return 0;
    }

    if (SystemInformationClass == 0xC5) {
        ULONG RequiredSize = sizeof(uint64_t);
        WriteRetLen(RequiredSize);
        if (SystemInformationLength < RequiredSize) {
            Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0xC5{MAG} (SystemHypervisorSharedPageInformation) {MAG}bufLen={WHT}0x%x {MAG}-> STATUS_BUFFER_OVERFLOW {MAG}caller=drv+0x%llx{RESET}\n",
                SystemInformationLength, CallerRva);
            return (NTSTATUS)0xC0000004;
        }
        uint64_t SharedPageVa = HYPERVISOR_SHARED_PAGE_BASE_UC;
        WriteBuf((uint8_t*)&SharedPageVa, sizeof(uint64_t));
        Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0xC5{MAG} (SystemHypervisorSharedPageInformation) {MAG}-> HypervisorSharedUserVa=0x%llx {MAG}caller=drv+0x%llx{RESET}\n", SharedPageVa, CallerRva);
        if (DIAG_IS_ENABLED()) {
            HvspReadEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.AccessType = ACCESS_API;
            Ev.Address = SharedPageVa;
            Ev.Offset = 0;
            Ev.Size = 8;
            Ev.Value = SharedPageVa;
            strncpy(Ev.FieldName, "HypervisorSharedUserVa", sizeof(Ev.FieldName) - 1);
            DIAG_HVSP_READ(Ev);
        }
        return 0;
    }

    if (SystemInformationClass == 0x67) {
        uint8_t FwInBuf[16] = {};
        ReadBuf(FwInBuf, 16);
        uint32_t ProviderSig = *(uint32_t*)(FwInBuf + 0);
        uint32_t Action = *(uint32_t*)(FwInBuf + 4);
        uint32_t TableId = *(uint32_t*)(FwInBuf + 8);
        uint32_t TableLen = *(uint32_t*)(FwInBuf + 12);
        const char* ProvName = GetFirmwareTableProviderName(ProviderSig);
        Logger::Log("  {MAG}NtQuerySystemInformation class={WHT}0x67{MAG} (SystemFirmwareTableInformation) {MAG}provider=0x%x (%s) action=%d tableId=0x%x {MAG}caller=drv+0x%llx{RESET}\n",
            ProviderSig, ProvName, Action, TableId, CallerRva);
        if (Action == 0) {
            WriteRetLen(16);
            Logger::Log("  {MAG}Firmware table enumerate -> fake SBB_HV_ (HyperVideo) signature {MAG}caller=drv+0x%llx{RESET}\n", CallerRva);
            uint8_t FakeAcpi[] = {
                0x53, 0x42, 0x42, 0x5F, 0x48, 0x56, 0x5F, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x48, 0x79, 0x70, 0x65,
                0x72, 0x56, 0x69, 0x64, 0x65, 0x6F, 0x00, 0x00
            };
            if (TableLen < sizeof(FakeAcpi)) return (NTSTATUS)0xC0000023;
            memset(FakeOutBuf, 0, 16 + sizeof(FakeAcpi));
            memcpy(FakeOutBuf + 16, FakeAcpi, sizeof(FakeAcpi));
            ULONG WriteLen = 16 + (ULONG)sizeof(FakeAcpi);
            WriteBuf(FakeOutBuf, WriteLen);
            WriteRetLen(WriteLen);
            return 0;
        }
        Logger::Log("  {MAG}Firmware table get -> fake SBB_HV_ (HyperVideo) ACPI data {MAG}caller=drv+0x%llx{RESET}\n", CallerRva);
        uint8_t FakeAcpiData[] = {
            0x53, 0x42, 0x42, 0x5F, 0x48, 0x56, 0x5F, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x48, 0x79, 0x70, 0x65,
            0x72, 0x56, 0x69, 0x64, 0x65, 0x6F, 0x00, 0x00
        };
        WriteBuf(FakeAcpiData, (ULONG)sizeof(FakeAcpiData));
        WriteRetLen((ULONG)sizeof(FakeAcpiData));
        if (DIAG_IS_ENABLED()) {
            FirmwareQueryEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.AccessType = ACCESS_API;
            Ev.BufferAddr = SystemInformation;
            Ev.InputLen = SystemInformationLength;
            Ev.OutputLen = HasReportedRetLen ? ReportedRetLen : 0;
            Ev.Status = 0;
            Ev.Provider = ProviderSig;
            Ev.Action = Action;
            Ev.TableId = TableId;
            Ev.IsFake = 1;
            strncpy(Ev.ProviderName, ProvName, sizeof(Ev.ProviderName) - 1);
            memcpy(Ev.First32Bytes, FakeAcpiData, sizeof(FakeAcpiData) < 32 ? sizeof(FakeAcpiData) : 32);
            DIAG_FW_QUERY(Ev);
        }
        return 0;
    }

    ULONG ApiBufSize = SystemInformationLength;
    if (ApiBufSize < 0x10000) ApiBufSize = 0x10000;
    uint8_t* ApiBuf = (uint8_t*)malloc(ApiBufSize);
    if (!ApiBuf) return STATUS_UNSUCCESSFUL;
    memset(ApiBuf, 0, ApiBufSize);

    ULONG ApiRetLen = 0;
    NTSTATUS x = SafeNtQuerySystemInformationLocalBuf(SystemInformationClass, ApiBufSize, &ApiRetLen, ApiBuf, ApiBufSize);

    Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0x%x {YEL}(%s) {YEL}bufLen={WHT}0x%x {YEL}apiBufSize={WHT}0x%x {YEL}status={WHT}0x%08x {YEL}apiRetLen={WHT}0x%x {YEL}caller=drv+0x%llx{RESET}\n",
        SystemInformationClass, ClassName, SystemInformationLength, ApiBufSize, x, ApiRetLen, CallerRva);

    WriteRetLen(ApiRetLen);

    if (x == 0) {
        if (UnicornEmu::DiagnosticHooksEnabled)
            Logger::Log("  {GRN}Class {WHT}%08x {GRN}success{RESET}\n", SystemInformationClass);
        if (SystemInformationClass == 0xb) {
            RTL_PROCESS_MODULES* loadedmodules = (RTL_PROCESS_MODULES*)ApiBuf;
            if (ApiRetLen < sizeof(ULONG)) {
                free(ApiBuf);
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            ULONG MaxModulesByLen = 0;
            if (ApiRetLen > sizeof(ULONG)) {
                MaxModulesByLen = (ApiRetLen - sizeof(ULONG)) / sizeof(RTL_PROCESS_MODULE_INFORMATION);
            }
            ULONG ReportedModules = loadedmodules->NumberOfModules;
            if (ReportedModules > MaxModulesByLen) {
                if (UnicornEmu::DiagnosticHooksEnabled) {
                    Logger::Log("  {YEL}NtQuerySystemInformation(0xB): clamping module count from {WHT}%u{YEL} to {WHT}%u{YEL} (apiRetLen=0x%x){RESET}\n",
                        ReportedModules, MaxModulesByLen, ApiRetLen);
                }
                loadedmodules->NumberOfModules = MaxModulesByLen;
            }

            bool ObserveOnlyModuleStructReads = UnicornEmu::DiagnosticHooksEnabled;
            if (ObserveOnlyModuleStructReads) {
                ULONG ModuleCount = loadedmodules->NumberOfModules;
                ULONG RequiredSize = sizeof(ULONG) + ModuleCount * sizeof(RTL_PROCESS_MODULE_INFORMATION);
                if (RequiredSize > ApiRetLen) RequiredSize = ApiRetLen;
                WriteRetLen(RequiredSize);

                if (SystemInformationLength < RequiredSize) {
                    Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0xB{YEL} observeOnly requiredLen={WHT}0x%x {YEL}callerLen={WHT}0x%x {YEL}-> STATUS_INFO_LENGTH_MISMATCH{RESET}\n",
                        RequiredSize, SystemInformationLength);
                    free(ApiBuf);
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                WriteBuf(ApiBuf, RequiredSize);

                if (DIAG_IS_ENABLED()) {
                    ModuleQueryEvent Ev = {};
                    Ev.Base.Sequence = DIAG_SEQ;
                    Ev.Base.AccessType = ACCESS_API;
                    Ev.BufferAddr = SystemInformation;
                    Ev.BufferLen = SystemInformationLength;
                    Ev.RequiredLen = HasReportedRetLen ? ReportedRetLen : ApiRetLen;
                    Ev.InitiaStatus = 0;
                    Ev.FinalStatus = x;
                    Ev.ModuleCountBefore = ModuleCount;
                    Ev.ModuleCountAfter = ModuleCount;
                    Ev.ModuleCountInjected = 0;
                    DIAG_MODULE_QUERY(Ev);
                }

                static int ModuleQueryCount = 0;
                ModuleQueryCount++;
                if (ModuleQueryCount <= 2) {
                    Logger::Log("  {CYN}=== SystemModuleInformation observe-only response #%d: %u modules ==={RESET}\n", ModuleQueryCount, ModuleCount);
                    for (ULONG i = 0; i < ModuleCount && i < 30; i++) {
                        char* Mn = (char*)loadedmodules->Modules[i].FullPathName;
                        Logger::Log("  {YEL}[%02u] base={WHT}%016llx {YEL}size={WHT}%08x {YEL}%s{RESET}\n",
                            i, (uint64_t)loadedmodules->Modules[i].ImageBase,
                            loadedmodules->Modules[i].ImageSize, Mn);
                    }
                    if (ModuleCount > 30)
                        Logger::Log("  {YEL}... and %u more modules{RESET}\n", ModuleCount - 30);
                }

                free(ApiBuf);
                return x;
            }

            int WriteIdx = 0;
            for (ULONG i = 0; i < loadedmodules->NumberOfModules; i++) {
                char* modulename = (char*)loadedmodules->Modules[i].FullPathName;
                while (strstr(modulename, "\\"))
                    modulename++;

                if (IsBlacklistedModule(modulename)) {
                    if (UnicornEmu::DiagnosticHooksEnabled)
                        Logger::Log("  {YEL}Filtering VM module from query: %s{RESET}\n", modulename);
                    continue;
                }

                auto mapped_module = PEFile::FindModule(modulename);

                if (mapped_module) {
                    if (UnicornEmu::DiagnosticHooksEnabled)
                        Logger::Log("  {GRY}Patching {WHT}%s {GRY}base from {WHT}%llx {GRY}to {WHT}%llx{RESET}\n", modulename, (PVOID)loadedmodules->Modules[i].ImageBase,
                            (PVOID)GetModuleUcBase(mapped_module));
                    loadedmodules->Modules[i].ImageBase = GetModuleUcBase(mapped_module);
                } else {
                    uint64_t UcBase = FindModuleUcBaseByName(modulename);
                    if (UcBase) {
                        loadedmodules->Modules[i].ImageBase = UcBase;
                    }
                }

                if (WriteIdx != i) {
                    memcpy(&loadedmodules->Modules[WriteIdx], &loadedmodules->Modules[i], sizeof(loadedmodules->Modules[0]));
                }
                WriteIdx++;
            }

            bool HyperVideoInjected = false;
            for (int i = 0; i < WriteIdx; i++) {
                char* mn = (char*)loadedmodules->Modules[i].FullPathName;
                while (strstr(mn, "\\")) mn++;
                if (strstr(mn, "hypervideo.sys")) {
                    HyperVideoInjected = true;
                    break;
                }
            }

            if (!HyperVideoInjected && (ULONG)WriteIdx < MaxModulesByLen) {
                auto& hvMod = loadedmodules->Modules[WriteIdx];
                memset(&hvMod, 0, sizeof(hvMod));
                uint64_t hvBase = 0xFFFFF80301000000ULL;
                hvMod.ImageBase = hvBase;
                hvMod.ImageSize = 0x15000;
                strcpy_s((char*)hvMod.FullPathName, sizeof(hvMod.FullPathName), "\\SystemRoot\\System32\\drivers\\hypervideo.sys");
                WriteIdx++;
                Logger::Log("  {MAG}[INJECT] HyperVideo.sys injected into SystemModuleInformation {WHT}base=0x%llx size=0x%llx caller=drv+0x%llx{RESET}\n",
                    hvBase, (uint64_t)hvMod.ImageSize, CallerRva);
            }

            loadedmodules->NumberOfModules = WriteIdx;

            ULONG PatchedSize = sizeof(ULONG) + WriteIdx * sizeof(RTL_PROCESS_MODULE_INFORMATION);
            if (PatchedSize > ApiBufSize) PatchedSize = ApiBufSize;
            WriteRetLen(PatchedSize);

            if (SystemInformationLength < PatchedSize) {
                if (UnicornEmu::DiagnosticHooksEnabled) {
                    Logger::Log("  {YEL}NtQuerySystemInformation class={WHT}0xB{YEL} patchedLen={WHT}0x%x {YEL}callerLen={WHT}0x%x {YEL}-> STATUS_INFO_LENGTH_MISMATCH{RESET}\n",
                        PatchedSize, SystemInformationLength);
                }
                free(ApiBuf);
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            WriteBuf(ApiBuf, PatchedSize);

            if (DIAG_IS_ENABLED()) {
                ModuleQueryEvent Ev = {};
                Ev.Base.Sequence = DIAG_SEQ;
                Ev.Base.AccessType = ACCESS_API;
                Ev.BufferAddr = SystemInformation;
                Ev.BufferLen = SystemInformationLength;
                Ev.RequiredLen = HasReportedRetLen ? ReportedRetLen : ApiRetLen;
                Ev.InitiaStatus = 0;
                Ev.FinalStatus = x;
                Ev.ModuleCountBefore = 0;
                Ev.ModuleCountAfter = WriteIdx;
                Ev.ModuleCountInjected = HyperVideoInjected ? 1 : 0;
                if (Ev.ModuleCountInjected > 0) {
                    strncpy(Ev.InjectedModuleName, "hypervideo.sys", sizeof(Ev.InjectedModuleName) - 1);
                    Ev.InjectedModuleBase = 0xFFFFF80301000000ULL;
                }
                DIAG_MODULE_QUERY(Ev);
            }

            static int ModuleQueryCount = 0;
            ModuleQueryCount++;
            if (ModuleQueryCount <= 2) {
                Logger::Log("  {CYN}=== SystemModuleInformation response #%d: %d modules ==={RESET}\n", ModuleQueryCount, WriteIdx);
                for (int i = 0; i < WriteIdx && i < 30; i++) {
                    char* Mn = (char*)loadedmodules->Modules[i].FullPathName;
                    Logger::Log("  {YEL}[%02d] base={WHT}%016llx {YEL}size={WHT}%08x {YEL}%s{RESET}\n",
                        i, (uint64_t)loadedmodules->Modules[i].ImageBase,
                        loadedmodules->Modules[i].ImageSize, Mn);
                }
                if (WriteIdx > 30)
                    Logger::Log("  {YEL}... and %d more modules{RESET}\n", WriteIdx - 30);
            }

            free(ApiBuf);
            return x;

        } else if (SystemInformationClass == 0x4D) {
            if (ApiRetLen < sizeof(ULONG)) {
                free(ApiBuf);
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            uint8_t* ReadCur = ApiBuf + sizeof(ULONG);
            uint8_t* WriteCur = ApiBuf + sizeof(ULONG);
            uint8_t* End = ApiBuf + ApiRetLen;
            ULONG NumModules = 0;
            bool ParsedAny = false;

            while ((ReadCur + sizeof(_SYSTEM_MODULE_EX)) <= End) {
                auto* Mod = (_SYSTEM_MODULE_EX*)ReadCur;
                ULONG EntrySize = Mod->Size;
                if (EntrySize < sizeof(_SYSTEM_MODULE_EX))
                    break;
                if (ReadCur + EntrySize > End)
                    break;
                ParsedAny = true;

                char* modulename = (char*)Mod->FullDllName;
                while (strstr(modulename, "\\"))
                    modulename++;

                bool SkipModule = IsBlacklistedModule(modulename);
                if (SkipModule) {
                    if (UnicornEmu::DiagnosticHooksEnabled)
                        Logger::Log("  {YEL}Filtering VM module from query(0x4D): %s{RESET}\n", modulename);
                } else {
                    auto mapped_module = PEFile::FindModule(modulename);
                    if (mapped_module) {
                        if (UnicornEmu::DiagnosticHooksEnabled)
                            Logger::Log("  {GRY}Patching {WHT}%s {GRY}base from {WHT}%llx {GRY}to {WHT}%llx{RESET}\n", modulename, Mod->ImageBase, GetModuleUcBase(mapped_module));
                        Mod->ImageBase = (PVOID)GetModuleUcBase(mapped_module);
                    } else {
                        uint64_t UcBase = FindModuleUcBaseByName(modulename);
                        if (UcBase) {
                            Mod->ImageBase = (PVOID)UcBase;
                        }
                    }

                    if (WriteCur != ReadCur) {
                        memmove(WriteCur, ReadCur, EntrySize);
                    }
                    WriteCur += EntrySize;
                    NumModules++;
                }

                ReadCur += EntrySize;
            }

            if (!ParsedAny) {
                WriteRetLen(ApiRetLen);
                if (SystemInformationLength < ApiRetLen) {
                    free(ApiBuf);
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                WriteBuf(ApiBuf, ApiRetLen);
                free(ApiBuf);
                return x;
            }

            ULONG FinalSize = (ULONG)(sizeof(ULONG) + (WriteCur - (ApiBuf + sizeof(ULONG))));
            *(ULONG*)ApiBuf = NumModules;
            WriteRetLen(FinalSize);

            if (SystemInformationLength < FinalSize) {
                free(ApiBuf);
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            WriteBuf(ApiBuf, FinalSize);
            free(ApiBuf);
            return x;
        }

        // Real Windows returns STATUS_INFO_LENGTH_MISMATCH when the caller's buffer is
        // smaller than the required size and reports the required size in ReturnLength.
        // Copying only min(len, required) with STATUS_SUCCESS broke the standard two-phase
        // size probe (call tiny buffer, read required size, call again) that drivers like
        // FACEIT_IOMMU use for SystemThreadInformation.
        if (SystemInformationLength < ApiRetLen) {
            WriteRetLen(ApiRetLen);
            free(ApiBuf);
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        WriteBuf(ApiBuf, ApiRetLen);
    } else if (x == STATUS_BUFFER_OVERFLOW || x == STATUS_INFO_LENGTH_MISMATCH) {
        WriteRetLen(ApiRetLen);
    }

    if (x == 0 && SystemInformationClass == 3 && SystemInformationLength >= 0x30) {
        int64_t* BootTime = (int64_t*)ApiBuf;
        int64_t* CurrentTime = (int64_t*)(ApiBuf + 8);
        *BootTime = *CurrentTime - (10 * 10000000LL);
        int64_t* BootTimeBias = (int64_t*)(ApiBuf + 0x20);
        int64_t* SleepTimeBias = (int64_t*)(ApiBuf + 0x28);
        *BootTimeBias = 0;
        *SleepTimeBias = 0;
        Logger::Log("  {BLU}Spoofed boot time (10s ago){RESET}\n");
        WriteBuf(ApiBuf, SystemInformationLength);
    }

    free(ApiBuf);
    return x;
}

NTSTATUS h_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength) {

    auto HostProcInfo = UcPtr(ProcessInformation);
    auto HostRetLen = UcPtr(ReturnLength);

    if ((int)(uintptr_t)ProcessInformationClass == 0x1B) {
        ULONG RequiredSize = 64;
        if (HostRetLen) *HostRetLen = RequiredSize;
        if (ProcessInformationLength < RequiredSize) {
            Logger::Log("{CYN}\tProcessInformation handle %llx class 0x1B -> fake STATUS_INFO_LENGTH_MISMATCH{RESET}\n", ProcessHandle);
            return (NTSTATUS)0xC0000004;
        }
        memset(HostProcInfo, 0, RequiredSize);
        Logger::Log("{CYN}\tProcessInformation handle %llx class 0x1B (ProcessImageInformation) -> fake zeroed{RESET}\n", ProcessHandle);
        return 0;
    }

    if (ProcessHandle == (HANDLE)-1) {
        auto Ret = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, HostProcInfo, ProcessInformationLength, HostRetLen);
        Logger::Log("{CYN}\tProcessInformation for handle %llx - class %llx - ret : %llx{RESET}\n", ProcessHandle, ProcessInformationClass, Ret);
        if (Ret == 0 && HostProcInfo && ProcessInformationLength >= 4) {
            *(DWORD*)HostProcInfo = 1;
        }
        return Ret;
    } else {
        auto Ret = __NtRoutine("NtQueryInformationProcess", ProcessHandle, ProcessInformationClass, HostProcInfo, ProcessInformationLength, HostRetLen);
        Logger::Log("{CYN}\tProcessInformation for handle %llx - class %llx - ret : %llx{RESET}\n", ProcessHandle, ProcessInformationClass, Ret);
        return Ret;
    }
}

NTSTATUS h_NtQueryInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) {
    Logger::Log("  {GRY}QueryInformationFile class {WHT}%08x{RESET}\n", FileInformationClass);
    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostInfo = UcPtr(FileInformation);
    auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, HostIsb, HostInfo, Length, FileInformationClass);
    return ret;
}

NTSTATUS h_ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength) {
    auto HostValName = UcPtr(ValueName);
    UNICODE_STRING LocalValName = *HostValName;
    LocalValName.Buffer = UcPtr(LocalValName.Buffer);
    auto HostKvi = UcPtr(KeyValueInformation);
    auto HostResLen = UcPtr(ResultLength);

    if (VRegHandleManager::IsVRegHandle(KeyHandle)) {
        std::wstring RegPath = VRegHandleManager::GetPath(KeyHandle);
        std::wstring ValNameStr(LocalValName.Buffer, LocalValName.Length / sizeof(wchar_t));

        ULONG StoredType = 0;
        ULONG StoredDataSize = 0;
        BYTE TempData[4096];

        if (!VirtualReg::ReadValueRaw(RegPath, ValNameStr.c_str(), &StoredType, TempData, sizeof(TempData), &StoredDataSize)) {
            Logger::Log("{YEL}\tVReg: value not found: %ls\\%ls{RESET}\n", RegPath.c_str(), ValNameStr.c_str());
            return (NTSTATUS)0xC0000034;
        }

        Logger::Log("{GRN}\tVReg: read %ls\\%ls type=%d size=%d{RESET}\n", RegPath.c_str(), ValNameStr.c_str(), StoredType, StoredDataSize);

        if (KeyValueInformationClass == KeyValuePartialInformation) {
            ULONG RequiredSize = 12 + StoredDataSize;
            if (HostResLen) *HostResLen = RequiredSize;
            if (Length < RequiredSize) {
                return (NTSTATUS)0xC0000023;
            }
            BYTE* Out = (BYTE*)HostKvi;
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = StoredDataSize;
            if (StoredDataSize > 0)
                memcpy(Out + 12, TempData, StoredDataSize);
            return 0;
        } else if (KeyValueInformationClass == KeyValueFullInformation) {
            ULONG NameLenBytes = (ULONG)(ValNameStr.size() * sizeof(wchar_t));
            ULONG HeaderSize = 20 + NameLenBytes;
            ULONG DataOffset = (HeaderSize + 7) & ~7;
            ULONG RequiredSize = DataOffset + StoredDataSize;
            if (HostResLen) *HostResLen = RequiredSize;
            if (Length < RequiredSize) {
                return (NTSTATUS)0xC0000023;
            }
            BYTE* Out = (BYTE*)HostKvi;
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = DataOffset;
            *(ULONG*)(Out + 12) = StoredDataSize;
            *(ULONG*)(Out + 16) = NameLenBytes;
            memcpy(Out + 20, ValNameStr.c_str(), NameLenBytes);
            if (StoredDataSize > 0)
                memcpy(Out + DataOffset, TempData, StoredDataSize);
            return 0;
        } else if (KeyValueInformationClass == KeyValueBasicInformation) {
            ULONG NameLenBytes = (ULONG)(ValNameStr.size() * sizeof(wchar_t));
            ULONG RequiredSize = 12 + NameLenBytes;
            if (HostResLen) *HostResLen = RequiredSize;
            if (Length < RequiredSize) {
                return (NTSTATUS)0xC0000023;
            }
            BYTE* Out = (BYTE*)HostKvi;
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = NameLenBytes;
            memcpy(Out + 12, ValNameStr.c_str(), NameLenBytes);
            return 0;
        }

        return (NTSTATUS)0xC0000002;
    }

    auto ret = __NtRoutine("NtQueryValueKey", KeyHandle, &LocalValName, KeyValueInformationClass, HostKvi, Length, HostResLen);
    return ret;
}

NTSTATUS h_ZwQueryFullAttributesFile(OBJECT_ATTRIBUTES* ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);
    auto HostFileInfo = UcPtr(FileInformation);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";

    if (!LocalPath.empty() && VirtualFs::LocalExists(LocalPath)) {
        WIN32_FILE_ATTRIBUTE_DATA Fad = {};
        if (GetFileAttributesExW(LocalPath.c_str(), GetFileExInfoStandard, &Fad)) {
            memset(HostFileInfo, 0, sizeof(FILE_NETWORK_OPEN_INFORMATION));
            HostFileInfo->CreationTime.LowPart = Fad.ftCreationTime.dwLowDateTime;
            HostFileInfo->CreationTime.HighPart = Fad.ftCreationTime.dwHighDateTime;
            HostFileInfo->LastAccessTime.LowPart = Fad.ftLastAccessTime.dwLowDateTime;
            HostFileInfo->LastAccessTime.HighPart = Fad.ftLastAccessTime.dwHighDateTime;
            HostFileInfo->LastWriteTime.LowPart = Fad.ftLastWriteTime.dwLowDateTime;
            HostFileInfo->LastWriteTime.HighPart = Fad.ftLastWriteTime.dwHighDateTime;
            HostFileInfo->ChangeTime = HostFileInfo->LastWriteTime;
            HostFileInfo->EndOfFile.LowPart = Fad.nFileSizeLow;
            HostFileInfo->EndOfFile.HighPart = Fad.nFileSizeHigh;
            HostFileInfo->AllocationSize = HostFileInfo->EndOfFile;
            HostFileInfo->FileAttributes = Fad.dwFileAttributes;
            Logger::Log("{GRN}\tVFS: QueryFullAttrs found %ls{RESET}\n", LocalPath.c_str());
            return 0;
        }
    }

    auto Ret = __NtRoutine("NtQueryFullAttributesFile", &LocalOa, HostFileInfo);
    Logger::Log("{CYN}\tQuerying information for %ls : %08x{RESET}\n", PathStr ? PathStr : L"(null)", Ret);
    return Ret;
}

NTSTATUS h_ZwQueryVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, uint32_t MemInfoClass,
    void* MemInfo, uint64_t MemInfoLength, uint64_t* ReturnLength)
{
    Logger::Log("{BLU}\tZwQueryVirtualMemory: handle=%p base=%p class=%u{RESET}\n",
        ProcessHandle, BaseAddress, MemInfoClass);
    return __NtRoutine("NtQueryVirtualMemory",
        ProcessHandle, BaseAddress, MemInfoClass,
        MemInfo, MemInfoLength, ReturnLength);
}
