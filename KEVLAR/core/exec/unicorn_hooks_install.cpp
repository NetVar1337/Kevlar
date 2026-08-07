#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include "core/diagnostics/diag_center.h"
#include "host/providers/provider.h"
#include <PEMapper/pefile.h>

extern void OnRipRingTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);

void UnicornEmu::Hooks::OnNtoskrnlRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    NtoskrnlReadCount++;

    bool FoundMod = false;
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") == std::string::npos)
            continue;

        FoundMod = true;
        uint64_t Rva = Addr - Mod.UcBase;

        if (Rva < 0x200000) {
            if (Rva < 0x1000) {
                NtoskrnlHdrReadCount++;
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                if (HdrFirstLogged < 50) {
                    HdrFirstLogged++;
                    Logger::Log("{GRY}[HDR #%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
                        NtoskrnlHdrReadCount, Rva, Size, ReadVal, Rip);
                }
                HdrRingBuf[HdrRingIdx % 64] = { Rva, Size, ReadVal, Rip };
                HdrRingIdx++;
            }
            else if (Rva < 0xC9000) NtoskrnlRdataReadCount++;
            else if (Rva < 0x131000) NtoskrnlPdataReadCount++;
            else if (Rva < 0x134000) NtoskrnlIdataReadCount++;
            else if (Rva < 0x14D000) {
                NtoskrnlEdataReadCount++;
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                if (EdataFirstLogged < 30) {
                    EdataFirstLogged++;
                    Logger::Log("{GRY}[EDATA #%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
                        NtoskrnlEdataReadCount, Rva, Size, ReadVal, Rip);
                }
                EdataRingBuf[EdataRingIdx % 32] = { Rva, Size, ReadVal, Rip };
                EdataRingIdx++;

                if (Size == 2 && Rva >= 0x13A074 && Rva < 0x13A074 + 3070*2) {
                    OrdinalReadCount++;
                    uint16_t Ord = (uint16_t)(ReadVal & 0xFFFF);
                    auto& Rec = OrdRingBuf[OrdRingIdx % 64];
                    Rec.NameRva = 0;
                    Rec.Ordinal = Ord;
                    Rec.FuncRva = 0;
                    Rec.Rip = Rip;
                    OrdRingIdx++;
                }
                if (Size == 4 && Rva >= 0x134028 && Rva < 0x134028 + 3093*4) {
                    FuncAddrReadCount++;
                    uint32_t FuncRva = (uint32_t)(ReadVal & 0xFFFFFFFF);
                    uint16_t LastOrdinal = 0;
                    bool HaveLastOrdinal = false;
                    if (OrdRingIdx > 0) {
                        auto& Prev = OrdRingBuf[(OrdRingIdx - 1) % 64];
                        LastOrdinal = Prev.Ordinal;
                        HaveLastOrdinal = true;
                        if (Prev.FuncRva == 0) {
                            Prev.FuncRva = FuncRva;
                        }
                    }

                    const char* ExportName = nullptr;
                    if (Mod.Pe) {
                        ExportName = Mod.Pe->GetExport(FuncRva);
                    }
                    static std::unordered_map<uint32_t, uint32_t> ExportResolveHits;
                    uint32_t& HitCount = ExportResolveHits[FuncRva];
                    HitCount++;
                    if (ExportName && (HitCount == 1 || (HitCount % 50000 == 0))) {
                        if (HaveLastOrdinal) {
                            Logger::Log("{CYN}[EXPORT RESOLVE] ordinal=%u funcRVA=0x%x name=%s RIP=0x%llx{RESET}\n",
                                (uint32_t)LastOrdinal, FuncRva, ExportName, Rip);
                        } else {
                            Logger::Log("{CYN}[EXPORT RESOLVE] funcRVA=0x%x name=%s RIP=0x%llx{RESET}\n",
                                FuncRva, ExportName, Rip);
                        }
                    }
                }
            } else NtoskrnlGfidsReadCount++;
        } else if (Rva < 0xc00000) {
            NtoskrnlCodeReadCount++;
            if (NtoskrnlCodeReadCount <= 20) {
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                Logger::Log("{YEL}[NTOS CODE READ] RVA=0x%llx (size=%d, val=0x%llx) at RIP=0x%llx{RESET}\n",
                    Rva, Size, ReadVal, Rip);
            }
        } else {
            NtoskrnlDataReadCount++;
            uint64_t Rip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
            uint64_t ReadVal = 0;
            if (Size <= 8) {
                void* HostPtr = UnicornMem::UcToHost(Addr);
                if (HostPtr)
                    memcpy(&ReadVal, HostPtr, Size);
            }

            bool IsPatchedExport = false;
            for (auto& [Name, Ptr] : Provider::data_providers) {
                uint64_t ExportUcAddr = (uint64_t)Ptr;
                if (Addr >= ExportUcAddr && Addr < ExportUcAddr + 16) {
                    size_t ExpSize = 8;
                    if (Provider::data_export_sizes.contains(Name))
                        ExpSize = Provider::data_export_sizes[Name];
                    Logger::Log("{YEL}[PATCHED EXPORT READ] %s RVA=0x%llx size=%d val=0x%llx (exportSize=%zu) at RIP=0x%llx{RESET}\n",
                        Name.c_str(), Rva, Size, ReadVal, ExpSize, Rip);
                    IsPatchedExport = true;
                    break;
                }
            }

            if (!IsPatchedExport && NtoskrnlDataReadCount <= 20) {
                Logger::Log("{GRY}[NTOS DATA READ] RVA=0x%llx (size=%d, val=0x%llx) at RIP=0x%llx{RESET}\n",
                    Rva, Size, ReadVal, Rip);
            }
        }

        if (NtoskrnlReadCount % 100000 == 0) {
            Logger::Log("{CYN}[NTOS READS] total=%d hdr=%d rdata=%d pdata=%d idata=%d edata=%d gfids=%d code=%d data=%d{RESET}\n",
                NtoskrnlReadCount, NtoskrnlHdrReadCount, NtoskrnlRdataReadCount, NtoskrnlPdataReadCount,
                NtoskrnlIdataReadCount, NtoskrnlEdataReadCount, NtoskrnlGfidsReadCount,
                NtoskrnlCodeReadCount, NtoskrnlDataReadCount);
        }

        if (DIAG_IS_ENABLED() && NtoskrnlReadCount <= 512) {
            uint64_t Rip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
            uint64_t ReadVal = 0;
            if (Size <= 8) {
                void* HostPtr = UnicornMem::UcToHost(Addr);
                if (HostPtr) memcpy(&ReadVal, HostPtr, Size);
            }
            NtosReadEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.Rip = Rip;
            Ev.Base.AccessType = ACCESS_READ;
            {
                uint64_t TmpBase = 0;
                uint32_t TmpRva = 0;
                DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.Section, sizeof(Ev.Section));
                Ev.Base.ModuleBase = TmpBase;
                Ev.Base.ModuleRva = TmpRva;
            }
            Ev.TargetVa = Addr;
            Ev.TargetRva = (uint32_t)Rva;
            Ev.Size = (uint32_t)Size;
            Ev.Value = ReadVal;
            DiagCenter::Instance().ResolveVaToPeSection(Addr, Ev.Section, sizeof(Ev.Section));
            DiagCenter::Instance().ResolveVaToSymbol(Addr, Ev.Symbol, sizeof(Ev.Symbol));
            DIAG_NTOS_READ(Ev);
        }
        return;
    }
    if (!FoundMod) {
        NtoskrnlNoModCount++;
        if (NtoskrnlNoModCount <= 5)
            Logger::Log("{RED}[NTOS READ] no module found for addr 0x%llx{RESET}\n", Addr);
    }
}

void UnicornEmu::Hooks::OnKusdRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    KusdReadCount++;
    uint64_t Offset = Addr - KUSD_BASE_UC;

    if (DIAG_IS_ENABLED() && KusdReadCount <= 256) {
        KusdReadEvent Ev = {};
        Ev.Base.Sequence = DIAG_SEQ;
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Ev.Base.Rip = Rip;
        Ev.Base.AccessType = ACCESS_READ;
        {
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.FieldName, sizeof(Ev.FieldName));
            Ev.Base.ModuleBase = TmpBase;
            Ev.Base.ModuleRva = TmpRva;
        }
        Ev.Address = Addr;
        Ev.Offset = (uint32_t)Offset;
        Ev.Size = (uint32_t)Size;
        if (Size <= 8) {
            void* HostPtr = UnicornMem::UcToHost(Addr);
            if (HostPtr) memcpy(&Ev.Value, HostPtr, Size);
        }
        const char* FieldName = "???";
        if (Offset == 0x00) FieldName = "TickCount";
        else if (Offset == 0x14) FieldName = "SystemTime";
        else if (Offset == 0x320) FieldName = "TickCountQuad";
        strncpy(Ev.FieldName, FieldName, sizeof(Ev.FieldName) - 1);
        DIAG_KUSD_READ(Ev);
    }

    if (DiagnosticHooksEnabled) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        if (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000) {
            Logger::Log("  {GRY}KUSD read offset={WHT}0x%03llx {GRY}size=%d RIP=drv+0x%llx{RESET}\n", Offset, Size, Rip - DRIVER_BASE_UC);
        }
    }

    if (Offset >= 0x08 && Offset < 0x20) {
        int64_t EmulatedElapsed = GetEmulatedQpcElapsed();
        int64_t ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;

        if (Offset >= 0x14 && Offset < 0x1C) {
            int64_t VirtualSystemTime = UnicornEmu::EmulationStartSystemTime + ElapsedIn100Ns;
            void* SystemTimeHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x14);
            if (SystemTimeHost) {
                *(volatile int64_t*)SystemTimeHost = VirtualSystemTime;
            }
        } else {
            int64_t VirtualInterruptTime = ElapsedIn100Ns;
            void* InterruptTimeHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x08);
            if (InterruptTimeHost) {
                *(volatile int64_t*)InterruptTimeHost = VirtualInterruptTime;
            }
        }
        return;
    }

    if (Offset >= 0x320 && Offset < 0x32C) {
        int64_t EmulatedElapsed = GetEmulatedQpcElapsed();
        int64_t ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;
        uint32_t VirtualTickCount = (uint32_t)(ElapsedIn100Ns / 156250);

        void* TickHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x320);
        if (TickHost) {
            auto Tc = (volatile uint32_t*)TickHost;
            Tc[0] = VirtualTickCount;
            Tc[1] = 0;
            Tc[2] = VirtualTickCount;
        }
        return;
    }
}

void UnicornEmu::Hooks::OnSysModRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    SysModReadCount++;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    bool IsDriverCaller = (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL);

    for (auto& Mod : UnicornEmu::MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") != std::string::npos)
            continue;

        if (Addr >= Mod.UcBase && Addr < Mod.UcBase + Mod.Size) {
            uint64_t Rva = Addr - Mod.UcBase;

            if (ModuleReadLoggingEnabled && IsDriverCaller) {
                static FILE* ModReadFile = nullptr;
                static std::mutex ModReadFileLock;
                static std::unordered_map<std::string, uint64_t> ModReadCounts;

                std::lock_guard<std::mutex> Guard(ModReadFileLock);
                if (!ModReadFile) {
                    ModReadFile = fopen("modreads.tsv", "w");
                    if (ModReadFile)
                        fprintf(ModReadFile, "module\trva\tsize\tcaller_rva\n");
                }

                ModReadCounts[Mod.Name]++;

                if (ModReadFile && ModReadCounts[Mod.Name] <= 10000) {
                    fprintf(ModReadFile, "%s\t0x%llx\t%d\t0x%llx\n",
                        Mod.Name.c_str(), Rva, Size, Rip - DRIVER_BASE_UC);
                    if (SysModReadCount % 1000 == 0)
                        fflush(ModReadFile);
                }
            }

            if (DiagnosticHooksEnabled && SysModReadCount <= 500) {
                Logger::Log("{MAG}[SYSMOD READ] %s RVA=0x%llx size=%d at RIP=0x%llx{RESET}\n",
                    Mod.Name.c_str(), Rva, Size, Rip);
            }
            return;
        }
    }
}

void UnicornEmu::InstallWatchpoints(uc_engine* Uc) {
    uc_hook Hh;

    if (DiagnosticHooksEnabled) {
        uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnDrvObjRead, nullptr,
            DRIVER_OBJ_BASE_UC, DRIVER_OBJ_BASE_UC + 0x10000 - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}Watchpoint: DRIVER_OBJECT reads (0x%llx - 0x%llx){RESET}\n",
                DRIVER_OBJ_BASE_UC, DRIVER_OBJ_BASE_UC + 0x10000 - 1);
        }

        uint64_t PoolStart = POOL_BASE_UC;
        uint64_t PoolEnd = UnicornMem::NextPoolAddr;
        if (PoolEnd > PoolStart) {
            Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnModuleListRead, nullptr,
                PoolStart, PoolEnd - 1);
            if (Err == UC_ERR_OK) {
                Logger::Log("{CYN}Watchpoint: Pool/LDR reads (0x%llx - 0x%llx){RESET}\n", PoolStart, PoolEnd - 1);
            }
        }
    } else {
        Logger::Log("{YEL}FAST MODE: Skipping DRIVER_OBJECT and Pool/LDR read hooks{RESET}\n");
    }

    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSC);
    if (Err == UC_ERR_OK) {
        Logger::Log("{GRN}RDTSC hook installed{RESET}\n");
    }

    uc_hook RdtscpHook;
    Err = uc_hook_add(Uc, &RdtscpHook, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSCP);
    if (Err == UC_ERR_OK) {
        Logger::Log("{GRN}RDTSCP hook installed{RESET}\n");
    }

    uc_hook RdmsrHook;
    UnicornEmu::RdmsrInsnHookSupported = false;
    UnicornEmu::WrmsrInsnHookSupported = false;
    UnicornEmu::MsrCodeInterceptEnabled = false;
    Err = uc_hook_add(Uc, &RdmsrHook, UC_HOOK_INSN, (void*)Hooks::OnRdmsr, nullptr, 1, 0, UC_X86_INS_RDMSR);
    if (Err == UC_ERR_OK) {
        UnicornEmu::RdmsrInsnHookSupported = true;
        Logger::Log("{GRN}RDMSR hook installed{RESET}\n");
    } else {
        Logger::Log("{YEL}RDMSR insn hook not supported (err=%s){RESET}\n", uc_strerror(Err));
    }

    uc_hook WrmsrHook;
    Err = uc_hook_add(Uc, &WrmsrHook, UC_HOOK_INSN, (void*)Hooks::OnWrmsr, nullptr, 1, 0, UC_X86_INS_WRMSR);
    if (Err == UC_ERR_OK) {
        UnicornEmu::WrmsrInsnHookSupported = true;
        Logger::Log("{GRN}WRMSR hook installed{RESET}\n");
    } else {
        Logger::Log("{YEL}WRMSR insn hook not supported (err=%s){RESET}\n", uc_strerror(Err));
    }

    if (!UnicornEmu::RdmsrInsnHookSupported || !UnicornEmu::WrmsrInsnHookSupported) {
        UnicornEmu::MsrCodeInterceptEnabled = true;
        uc_hook MsrFallbackHook;
        uc_err MsrFallbackErr = uc_hook_add(Uc, &MsrFallbackHook, UC_HOOK_CODE, (void*)Hooks::OnMsrFallback, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x10000000ULL - 1);
        if (MsrFallbackErr == UC_ERR_OK) {
            Logger::Log("{GRN}MSR fallback code hook installed (rdmsr=%d wrmsr=%d){RESET}\n",
                UnicornEmu::RdmsrInsnHookSupported ? 1 : 0,
                UnicornEmu::WrmsrInsnHookSupported ? 1 : 0);
        } else {
            Logger::Log("{RED}MSR fallback code hook failed: %s{RESET}\n", uc_strerror(MsrFallbackErr));
        }
    }

    if (DiagnosticHooksEnabled) {
        InstallSseAlignCheck(Uc, DRIVER_BASE_UC, 0x10000000ULL);
    } else {
        Logger::Log("{YEL}FAST MODE: Skipping SSE alignment check hook{RESET}\n");
    }

    DrvObjReadCount = 0;
    ModListReadCount = 0;
    NtoskrnlReadCount = 0;
    KusdReadCount = 0;
    SysModReadCount = 0;

    for (auto& Mod : MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") != std::string::npos) {
            if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
                Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnNtoskrnlRead, nullptr,
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                if (Err == UC_ERR_OK) {
                    Logger::Log("{CYN}Watchpoint: ntoskrnl reads (0x%llx - 0x%llx){RESET}\n",
                        Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                }
            } else {
                Logger::Log("{YEL}FAST MODE: Skipping ntoskrnl read hook (0x%llx - 0x%llx){RESET}\n",
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
            }
        } else {
            if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
                Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnSysModRead, nullptr,
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                if (Err == UC_ERR_OK) {
                    Logger::Log("{CYN}Watchpoint: %s reads (0x%llx - 0x%llx){RESET}\n",
                        Mod.Name.c_str(), Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                }
            }
        }
    }

    UpdateKusdTimeValues();
    bool KusdReadHookInstalled = false;
    if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
        uc_hook HhKusd;
        uc_err KusdHookErr = uc_hook_add(Uc, &HhKusd, UC_HOOK_MEM_READ, (void*)Hooks::OnKusdRead, nullptr,
            KUSD_BASE_UC, KUSD_BASE_UC + 0x1000 - 1);
        if (KusdHookErr == UC_ERR_OK) {
            KusdReadHookInstalled = true;
            Logger::Log("{CYN}Watchpoint: KUSER_SHARED_DATA reads (0x%llx - 0x%llx){RESET}\n",
                KUSD_BASE_UC, KUSD_BASE_UC + 0x1000 - 1);
        } else {
            Logger::Log("{YEL}KUSER_SHARED_DATA hook failed: %s{RESET}\n", uc_strerror(KusdHookErr));
        }
    }
    Logger::Log("{GRN}KUSD time values: periodic heartbeat updates%s{RESET}\n",
        KusdReadHookInstalled ? " + read hook" : " (no read hook)");

    uc_hook HhHvPage;
    Err = uc_hook_add(Uc, &HhHvPage, UC_HOOK_MEM_READ, (void*)Hooks::OnHypervisorSharedPageRead, nullptr,
        HYPERVISOR_SHARED_PAGE_BASE_UC, HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000 - 1);
    if (Err == UC_ERR_OK) {
        Logger::Log("{CYN}Watchpoint: HypervisorSharedPage reads (0x%llx - 0x%llx){RESET}\n",
            HYPERVISOR_SHARED_PAGE_BASE_UC, HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000 - 1);
    } else {
        Logger::Log("{YEL}HypervisorSharedPage hook failed: %s{RESET}\n", uc_strerror(Err));
    }

    if (DiagnosticHooksEnabled) {
        auto OnDriverSelfRead = [](uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
            DrvSelfReadCount++;
            uint64_t Rva = Addr - DRIVER_BASE_UC;

            if (Rva < 0x1000) {
                DrvSelfHdrReadCount++;
                if (DrvSelfHdrReadCount <= 30) {
                    uint64_t Rip = 0;
                    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                    uint64_t ReadVal = 0;
                    if (Size <= 8) {
                        void* HostPtr = UnicornMem::UcToHost(Addr);
                        if (HostPtr)
                            memcpy(&ReadVal, HostPtr, Size);
                    }
                    bool External = (Rip < DRIVER_BASE_UC || Rip >= DRIVER_BASE_UC + 0x10000000ULL);
                    if (!External) {
                        Logger::Log("{RED}[DRV SELF-READ HDR] RVA=0x%llx size=%d val=0x%llx drv+0x%llx{RESET}\n",
                            Rva, Size, ReadVal, Rip - DRIVER_BASE_UC);
                    }
                }
            }

            if (Rva >= 0x1FA000 && Rva < 0x1FB000) {
                DrvSelfIatReadCount++;
                static std::unordered_map<uint64_t, std::string> IatSlotNamesByRva;
                static std::once_flag IatSlotInitFlag;
                std::call_once(IatSlotInitFlag, []() {
                    uint8_t* DriverHostBase = (uint8_t*)UnicornMem::UcToHost(DRIVER_BASE_UC);
                    if (!DriverHostBase)
                        return;

                    auto Dos = (PIMAGE_DOS_HEADER)DriverHostBase;
                    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
                        return;

                    auto Nt = (PIMAGE_NT_HEADERS)(DriverHostBase + Dos->e_lfanew);
                    auto& ImportDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                    if (!ImportDir.VirtualAddress || !ImportDir.Size)
                        return;

                    auto ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(DriverHostBase + ImportDir.VirtualAddress);
                    for (; ImportDesc->Name; ImportDesc++) {
                        const char* DllName = (const char*)(DriverHostBase + ImportDesc->Name);
                        PIMAGE_THUNK_DATA OrigThunk = nullptr;
                        if (ImportDesc->OriginalFirstThunk)
                            OrigThunk = (PIMAGE_THUNK_DATA)(DriverHostBase + ImportDesc->OriginalFirstThunk);
                        else
                            OrigThunk = (PIMAGE_THUNK_DATA)(DriverHostBase + ImportDesc->FirstThunk);

                        uint64_t IatThunkRva = ImportDesc->FirstThunk;
                        for (; OrigThunk && OrigThunk->u1.AddressOfData; OrigThunk++, IatThunkRva += sizeof(IMAGE_THUNK_DATA)) {
                            std::string SlotName;
                            if (IMAGE_SNAP_BY_ORDINAL(OrigThunk->u1.Ordinal)) {
                                char Buf[256] = {};
                                sprintf_s(Buf, sizeof(Buf), "%s!#%u", DllName, (unsigned)IMAGE_ORDINAL(OrigThunk->u1.Ordinal));
                                SlotName = Buf;
                            } else {
                                auto ImportByName = (PIMAGE_IMPORT_BY_NAME)(DriverHostBase + (OrigThunk->u1.AddressOfData & 0x7FFFFFFF));
                                if (ImportByName && ImportByName->Name) {
                                    SlotName = std::string(DllName) + "!" + (const char*)ImportByName->Name;
                                }
                            }
                            if (!SlotName.empty())
                                IatSlotNamesByRva[IatThunkRva] = SlotName;
                        }
                    }
                });

                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }

                const char* SlotName = "?";
                auto SlotIt = IatSlotNamesByRva.find(Rva);
                if (SlotIt != IatSlotNamesByRva.end()) {
                    SlotName = SlotIt->second.c_str();
                }

                std::string TargetName = "unknown";
                if (ReadVal != 0) {
                    auto SentinelIt = UnicornEmu::SentinelMap.find(ReadVal);
                    if (SentinelIt == UnicornEmu::SentinelMap.end()) {
                        SentinelIt = UnicornEmu::SentinelMap.find(ReadVal & ~0xFULL);
                    }
                    if (SentinelIt != UnicornEmu::SentinelMap.end()) {
                        TargetName = SentinelIt->second.Name;
                    } else {
                        std::lock_guard<std::mutex> Guard(UnicornEmu::SysModFuncCacheLock);
                        auto FuncIt = UnicornEmu::SysModFuncCache.find(ReadVal);
                        if (FuncIt != UnicornEmu::SysModFuncCache.end()) {
                            TargetName = FuncIt->second.ModName + "!" + FuncIt->second.FuncName;
                        }
                    }
                    if (TargetName == "unknown") {
                        if (ReadVal >= DRIVER_BASE_UC && ReadVal < DRIVER_BASE_UC + 0x10000000ULL) {
                            char Buf[64] = {};
                            sprintf_s(Buf, sizeof(Buf), "driver+0x%llx", ReadVal - DRIVER_BASE_UC);
                            TargetName = Buf;
                        } else {
                            for (auto& MapMod : UnicornEmu::MappedSysMods) {
                                if (ReadVal >= MapMod.UcBase && ReadVal < MapMod.UcBase + MapMod.Size) {
                                    char Buf[256] = {};
                                    sprintf_s(Buf, sizeof(Buf), "%s+0x%llx", MapMod.Name.c_str(), ReadVal - MapMod.UcBase);
                                    TargetName = Buf;
                                    break;
                                }
                            }
                        }
                    }
                }

                Logger::Log("{RED}[DRV IAT READ] RVA=0x%llx slot=%s size=%d val=0x%llx target=%s RIP=drv+0x%llx{RESET}\n",
                    Rva, SlotName, Size, ReadVal, TargetName.c_str(), Rip - DRIVER_BASE_UC);
            }

            if (DrvSelfReadCount % 100000 == 0) {
                Logger::Log("{CYN}[DRV SELF-READS] total=%d hdr=%d iat=%d{RESET}\n",
                    DrvSelfReadCount, DrvSelfHdrReadCount, DrvSelfIatReadCount);
            }
        };

        using DrvSelfReadFn = void(*)(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*);
        static DrvSelfReadFn DrvSelfReadPtr = OnDriverSelfRead;

        Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)DrvSelfReadPtr, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x200000 - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}Watchpoint: Driver self-reads (0x%llx - 0x%llx){RESET}\n",
                DRIVER_BASE_UC, DRIVER_BASE_UC + 0x200000 - 1);
        }

        RipRingIdx = 0;
        RipRingTotal = 0;
        using RipTraceFn = void(*)(uc_engine*, uint64_t, uint32_t, void*);
        static RipTraceFn RipTracePtr = OnRipRingTrace;
        Err = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)RipTracePtr, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x3000000ULL - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}RIP ring trace installed (last %d instructions){RESET}\n", RIP_RING_SIZE);
        }

        static auto OnStackErrorWrite = [](uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
            if (Size >= 4) {
                uint32_t Val32 = (uint32_t)(Value & 0xFFFFFFFF);
                uint64_t Val64 = (uint64_t)Value;
                if (Val32 == 0xC0000022 || Val64 == 0xC0000022) {
                    uint64_t Rip = 0;
                    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                    uint64_t DriverRva = (Rip >= DRIVER_BASE_UC) ? Rip - DRIVER_BASE_UC : Rip;
                    //Logger::Log("{RED}[STACK WRITE 0xC0000022] addr=0x%llx size=%d val=0x%llx RIP=drv+0x%llx insn#%llu{RESET}\n",
                    //    Addr, Size, Val64, DriverRva, RipRingTotal);
                }
            }
        };
        using StackWriteFn = void(*)(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*);
        static StackWriteFn StackWritePtr = OnStackErrorWrite;
        uint64_t StackBase = STACK_BASE_UC;
        uint64_t StackEnd = StackBase + STACK_SIZE_UC - 1;
        Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_WRITE, (void*)StackWritePtr, nullptr, StackBase, StackEnd);
        if (Err == UC_ERR_OK) {
            //Logger::Log("{CYN}Watchpoint: Stack writes for 0xC0000022 (0x%llx - 0x%llx){RESET}\n", StackBase, StackEnd);
        }

    } else {
        RipRingIdx = 0;
        RipRingTotal = 0;
        Logger::Log("{YEL}FAST MODE: Skipping driver self-read hook, RIP ring trace, sysmod read hooks{RESET}\n");
    }

    
}
