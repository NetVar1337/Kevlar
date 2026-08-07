#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/provider.h"
#include "core/loader/environment.h"
#include "core/memory/unicorn_memory.h"
#include <malloc.h>

uint64_t UnicornEmu::MapStubModule(const char* Name, uint64_t ClaimedImageSize) {
    uint64_t StubSize = 0x2000;

    void* HostBuf = _aligned_malloc((size_t)StubSize, 0x1000);
    if (!HostBuf) {
        Logger::Log("{RED}MapStubModule '%s' alloc failed{RESET}\n", Name);
        return 0;
    }
    memset(HostBuf, 0, (size_t)StubSize);

    uint64_t UcBase = NextSysModAddr;
    NextSysModAddr += StubSize + 0x10000;
    NextSysModAddr = (NextSysModAddr + 0xFFFF) & ~0xFFFFULL;

    auto DosHeader = (PIMAGE_DOS_HEADER)HostBuf;
    DosHeader->e_magic = IMAGE_DOS_SIGNATURE;
    DosHeader->e_lfanew = 0x80;

    auto NtHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)HostBuf + 0x80);
    NtHeaders->Signature = IMAGE_NT_SIGNATURE;
    NtHeaders->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    NtHeaders->FileHeader.NumberOfSections = 1;
    NtHeaders->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    NtHeaders->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    auto OptHeader = (PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader;
    OptHeader->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    OptHeader->ImageBase = UcBase;
    OptHeader->SectionAlignment = 0x1000;
    OptHeader->FileAlignment = 0x200;
    OptHeader->SizeOfImage = (ClaimedImageSize > 0) ? (DWORD)ClaimedImageSize : 0x10000;
    OptHeader->SizeOfHeaders = 0x1000;
    OptHeader->Subsystem = IMAGE_SUBSYSTEM_NATIVE;
    OptHeader->MajorOperatingSystemVersion = 10;
    OptHeader->MinorOperatingSystemVersion = 0;
    OptHeader->MajorSubsystemVersion = 10;
    OptHeader->MinorSubsystemVersion = 0;
    OptHeader->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    OptHeader->SizeOfStackReserve = 0x40000;
    OptHeader->SizeOfStackCommit = 0x1000;
    OptHeader->SizeOfHeapReserve = 0x100000;
    OptHeader->SizeOfHeapCommit = 0x1000;

    auto SectionHeader = (PIMAGE_SECTION_HEADER)((uint8_t*)OptHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);
    memcpy(SectionHeader->Name, ".text\0\0\0", 8);
    SectionHeader->Misc.VirtualSize = 0x1000;
    SectionHeader->VirtualAddress = 0x1000;
    SectionHeader->SizeOfRawData = 0x200;
    SectionHeader->PointerToRawData = 0x200;
    SectionHeader->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    memset((uint8_t*)HostBuf + 0x1000, 0xC3, 0x1000);

    uc_err Err = uc_mem_map_ptr(PrimaryEngine, UcBase, StubSize, UC_PROT_ALL, HostBuf);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}MapStubModule '%s' uc_mem_map_ptr failed: %s{RESET}\n", Name, uc_strerror(Err));
        _aligned_free(HostBuf);
        return 0;
    }

    std::string StubName = std::string(Name) + " (stub)";
    MappedRegions.push_back({ UcBase, StubSize, HostBuf, StubName, UC_PROT_ALL });
    UnicornMem::TrackExisting(UcBase, HostBuf, StubSize, StubName.c_str());

    return UcBase;
}

uint64_t UnicornEmu::MapKernelStructs() {
    uint64_t KpcrSize = 0x10000;
    KpcrBlock = _aligned_malloc((size_t)KpcrSize, 0x1000);
    if (!KpcrBlock) {
        Logger::Log("{RED}Failed to allocate KPCR block{RESET}\n");
        return 1;
    }
    memset(KpcrBlock, 0, (size_t)KpcrSize);

    memcpy(KpcrBlock, &FakeKPCR, sizeof(_KPCR));

    size_t KprcbCopySize = sizeof(_KPRCB);
    if (KprcbCopySize > KpcrSize - 0x180)
        KprcbCopySize = (size_t)(KpcrSize - 0x180);
    memcpy((uint8_t*)KpcrBlock + 0x180, &FakeCPU, KprcbCopySize);

    MapRegionPtr(PrimaryEngine, KPCR_BASE_UC, KpcrSize, UC_PROT_ALL, KpcrBlock, "KPCR+KPRCB");

    uint64_t KpcrAddr = KPCR_BASE_UC;
    uc_mem_write(PrimaryEngine, KPCR_BASE_UC + 0x18, &KpcrAddr, 8);

    uint64_t KprcbAddr = KPCR_BASE_UC + 0x180;
    uc_mem_write(PrimaryEngine, KPCR_BASE_UC + 0x20, &KprcbAddr, 8);

    uint64_t IdtAddr = IDT_BASE_UC;
    uc_mem_write(PrimaryEngine, KPCR_BASE_UC + 0x38, &IdtAddr, 8);

    uint64_t EthreadAddr = ETHREAD_BASE_UC;
    uc_mem_write(PrimaryEngine, KPCR_BASE_UC + 0x188, &EthreadAddr, 8);

    uint64_t EthreadSize = 0x10000;
    EthreadBlock = _aligned_malloc((size_t)EthreadSize, 0x1000);
    if (!EthreadBlock) {
        Logger::Log("{RED}Failed to allocate ETHREAD block{RESET}\n");
        return 1;
    }
    memset(EthreadBlock, 0, (size_t)EthreadSize);
    memcpy(EthreadBlock, &FakeKernelThread, sizeof(_ETHREAD));

    MapRegionPtr(PrimaryEngine, ETHREAD_BASE_UC, EthreadSize, UC_PROT_ALL, EthreadBlock, "ETHREAD");

    uint64_t EprocessAddr = EPROCESS_BASE_UC;
    uc_mem_write(PrimaryEngine, ETHREAD_BASE_UC + 0x220, &EprocessAddr, 8);
    uc_mem_write(PrimaryEngine, ETHREAD_BASE_UC + 0xB8, &EprocessAddr, 8);

    uint64_t EprocessSize = 0x10000;
    EprocessBlock = _aligned_malloc((size_t)EprocessSize, 0x1000);
    if (!EprocessBlock) {
        Logger::Log("{RED}Failed to allocate EPROCESS block{RESET}\n");
        return 1;
    }
    memset(EprocessBlock, 0, (size_t)EprocessSize);
    memcpy(EprocessBlock, &FakeSystemProcess, sizeof(_EPROCESS));

    MapRegionPtr(PrimaryEngine, EPROCESS_BASE_UC, EprocessSize, UC_PROT_ALL, EprocessBlock, "EPROCESS");

    uint64_t DrvObjSize = 0x10000;
    DrvObjBlock = _aligned_malloc((size_t)DrvObjSize, 0x1000);
    if (!DrvObjBlock) {
        Logger::Log("{RED}Failed to allocate DriverObject block{RESET}\n");
        return 1;
    }
    memset(DrvObjBlock, 0, (size_t)DrvObjSize);
    memcpy(DrvObjBlock, &drvObj, sizeof(_DRIVER_OBJECT));

    if (drvObj.DriverName.Buffer && drvObj.DriverName.Length > 0) {
        size_t DrvNameOff = sizeof(_DRIVER_OBJECT);
        DrvNameOff = (DrvNameOff + 0xF) & ~0xFULL;
        if (DrvNameOff + drvObj.DriverName.MaximumLength < DrvObjSize) {
            memcpy((uint8_t*)DrvObjBlock + DrvNameOff, drvObj.DriverName.Buffer, drvObj.DriverName.MaximumLength);
            auto DrvObjHost = (_DRIVER_OBJECT*)DrvObjBlock;
            DrvObjHost->DriverName.Buffer = (WCHAR*)(DRIVER_OBJ_BASE_UC + DrvNameOff);
        }
    }

    MapRegionPtr(PrimaryEngine, DRIVER_OBJ_BASE_UC, DrvObjSize, UC_PROT_ALL, DrvObjBlock, "DriverObject");

    uint64_t RegPathSize = 0x10000;
    RegPathBlock = _aligned_malloc((size_t)RegPathSize, 0x1000);
    if (!RegPathBlock) {
        Logger::Log("{RED}Failed to allocate RegistryPath block{RESET}\n");
        return 1;
    }
    memset(RegPathBlock, 0, (size_t)RegPathSize);
    memcpy(RegPathBlock, &RegistryPath, sizeof(UNICODE_STRING));

    if (RegistryPath.Buffer && RegistryPath.Length > 0) {
        size_t BufOffset = sizeof(UNICODE_STRING) + 0x100;
        BufOffset = (BufOffset + 0xF) & ~0xFULL;

        if (BufOffset + RegistryPath.MaximumLength < RegPathSize) {
            memcpy((uint8_t*)RegPathBlock + BufOffset, RegistryPath.Buffer, RegistryPath.MaximumLength);

            uint64_t UcBufAddr = REGISTRY_PATH_BASE_UC + BufOffset;
            uc_mem_write(PrimaryEngine, REGISTRY_PATH_BASE_UC + offsetof(UNICODE_STRING, Buffer), &UcBufAddr, sizeof(UcBufAddr));
        }
    }

    MapRegionPtr(PrimaryEngine, REGISTRY_PATH_BASE_UC, RegPathSize, UC_PROT_ALL, RegPathBlock, "RegistryPath");

    UnicornMem::TrackExisting(KPCR_BASE_UC, KpcrBlock, KpcrSize, "KPCR+KPRCB");
    UnicornMem::TrackExisting(ETHREAD_BASE_UC, EthreadBlock, EthreadSize, "ETHREAD");
    UnicornMem::TrackExisting(EPROCESS_BASE_UC, EprocessBlock, EprocessSize, "EPROCESS");
    UnicornMem::TrackExisting(DRIVER_OBJ_BASE_UC, DrvObjBlock, DrvObjSize, "DriverObject");
    UnicornMem::TrackExisting(REGISTRY_PATH_BASE_UC, RegPathBlock, RegPathSize, "RegistryPath");

    Logger::Log("{GRN}MapKernelStructs: all kernel structures mapped{RESET}\n");
    return 0;
}

uint64_t UnicornEmu::MapKuserSharedData() {
    if (!KusdBlock) {
        KusdBlock = _aligned_malloc(0x1000, 0x1000);
        memcpy(KusdBlock, (void*)0x7FFE0000, 0x1000);

        auto Kusd = (uint8_t*)KusdBlock;

        Logger::Log("{BLU}KUSD: Build=%u Product=%u Major=%u ProcArch=%u{RESET}\n",
            *(uint32_t*)(Kusd + 0x260), *(uint32_t*)(Kusd + 0x264),
            *(uint32_t*)(Kusd + 0x26C), *(uint16_t*)(Kusd + 0x26A));

        SYSTEM_INFO Si;
        GetNativeSystemInfo(&Si);
        DWORD ProcCount = Si.dwNumberOfProcessors;
        if (ProcCount < 4) ProcCount = 4;

        *(uint32_t*)(Kusd + 0x2C0) = ProcCount;
        *(uint32_t*)(Kusd + 0x2C4) = 1;

        uint32_t PhysPages = 2097152;
        *(uint32_t*)(Kusd + 0x2E8) = PhysPages;

        *(uint8_t*)(Kusd + 0x2D4) = 0;

        *(uint32_t*)(Kusd + 0x244) = 0x200000;

        uint32_t Cookie = *(uint32_t*)(Kusd + 0x330);
        if (Cookie == 0) {
            LARGE_INTEGER PerfCount;
            QueryPerformanceCounter(&PerfCount);
            Cookie = (uint32_t)(PerfCount.QuadPart ^ GetCurrentProcessId() ^ 0xBB40E64D);
            *(uint32_t*)(Kusd + 0x330) = Cookie;
        }

        *(uint8_t*)(Kusd + 0x2EC) = 0;

        Logger::Log("{BLU}KUSD hardened: ActiveProcessors=%u PhysPages=%u Cookie=0x%08x LargePageMin=0x%x{RESET}\n",
            ProcCount, PhysPages, Cookie, 0x200000);

        KusdThreadRunning = true;
        KusdThread = CreateThread(nullptr, 0, KusdUpdaterThread, KusdBlock, 0, nullptr);
        SetThreadPriority(KusdThread, THREAD_PRIORITY_HIGHEST);
    }

    MapRegionPtr(PrimaryEngine, KUSD_BASE_UC, 0x1000, UC_PROT_READ, KusdBlock, "KUSER_SHARED_DATA");
    UnicornMem::TrackExisting(KUSD_BASE_UC, KusdBlock, 0x1000, "KUSER_SHARED_DATA");

    if (!HyperspaceBlock) {
        HyperspaceBlock = _aligned_malloc((size_t)HYPERSPACE_SIZE_UC, 0x1000);
        if (!HyperspaceBlock) {
            Logger::Log("{RED}MapKuserSharedData: hyperspace allocation failed{RESET}\n");
            return KUSD_BASE_UC;
        }

        memset(HyperspaceBlock, 0, (size_t)HYPERSPACE_SIZE_UC);

        auto Hyper = (uint8_t*)HyperspaceBlock;
        *(uint64_t*)(Hyper + 0x40528) = EPROCESS_BASE_UC;
        *(uint64_t*)(Hyper + 0x417d0) = KPCR_BASE_UC;
        *(uint64_t*)(Hyper + 0x43728) = KUSD_BASE_UC;
    }

    MapRegionPtr(PrimaryEngine, HYPERSPACE_BASE_UC, HYPERSPACE_SIZE_UC, UC_PROT_ALL, HyperspaceBlock, "HYPERSPACE");
    UnicornMem::TrackExisting(HYPERSPACE_BASE_UC, HyperspaceBlock, HYPERSPACE_SIZE_UC, "HYPERSPACE");

    if (!HypervisorSharedPageBlock) {
        HypervisorSharedPageBlock = _aligned_malloc(0x1000, 0x1000);
        if (!HypervisorSharedPageBlock) {
            Logger::Log("{RED}MapHypervisorSharedPage: allocation failed{RESET}\n");
        } else {
            memset(HypervisorSharedPageBlock, 0, 0x1000);
            auto Page = (uint8_t*)HypervisorSharedPageBlock;
            *(uint32_t*)(Page + 0x00) = 0;
            *(uint32_t*)(Page + 0x04) = 0;
            LARGE_INTEGER PerfCount;
            QueryPerformanceCounter(&PerfCount);
            uint64_t QpcFreq;
            QueryPerformanceFrequency((LARGE_INTEGER*)&QpcFreq);
            uint64_t QpcMultiplier = (10000000ULL << 32) / QpcFreq;
            *(uint64_t*)(Page + 0x08) = QpcMultiplier;
            *(uint64_t*)(Page + 0x10) = 0;
            Logger::Log("{BLU}HypervisorSharedPage: TimeUpdateLock=0x%08x Reserved=0x%08x QpcMultiplier=0x%llx QpcBias=0x%llx{RESET}\n",
                *(uint32_t*)(Page + 0x00), *(uint32_t*)(Page + 0x04),
                *(uint64_t*)(Page + 0x08), *(uint64_t*)(Page + 0x10));
        }
    }

    if (HypervisorSharedPageBlock) {
        MapRegionPtr(PrimaryEngine, HYPERVISOR_SHARED_PAGE_BASE_UC, 0x1000, UC_PROT_READ, HypervisorSharedPageBlock, "HYPERVISOR_SHARED_PAGE");
        UnicornMem::TrackExisting(HYPERVISOR_SHARED_PAGE_BASE_UC, HypervisorSharedPageBlock, 0x1000, "HYPERVISOR_SHARED_PAGE");
    }

    Logger::Log("{BLU}MapKuserSharedData: KUSD=0x%llx HYPERSPACE=0x%llx HV_SHARED_PAGE=0x%llx{RESET}\n",
        KUSD_BASE_UC, HYPERSPACE_BASE_UC, HYPERVISOR_SHARED_PAGE_BASE_UC);
    return KUSD_BASE_UC;
}

uint64_t UnicornEmu::MapDataExports() {
    Logger::Log("{CYN}MapDataExports: using lazy mapping via OnMemReadUnmapped{RESET}\n");
    return 0;
}

static bool IsRvaInWritableSection(uint8_t* HostBase, uint32_t Rva) {
    auto Dos = (PIMAGE_DOS_HEADER)HostBase;
    auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
    auto Section = IMAGE_FIRST_SECTION(Nt);

    for (WORD I = 0; I < Nt->FileHeader.NumberOfSections; I++) {
        uint32_t SecStart = Section[I].VirtualAddress;
        uint32_t SecEnd = SecStart + max(Section[I].Misc.VirtualSize, Section[I].SizeOfRawData);
        if (Rva >= SecStart && Rva < SecEnd) {
            return (Section[I].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        }
    }
    return false;
}

void UnicornEmu::PatchSystemModuleExports() {
    for (auto& Mod : MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);

        bool IsNtoskrnl = NameLower.find("ntoskrnl") != std::string::npos;

        auto HostBase = (uint8_t*)UnicornMem::UcToHost(Mod.UcBase);
        if (!HostBase) continue;

        int PatchedInPlace = 0;
        int RedirectedToUc = 0;

        auto AllExports = Mod.Pe->GetAllExports();

        for (auto& [ExportRva, ExportName] : AllExports) {
            if (Provider::data_providers.contains(ExportName)) {
                if (ExportName == "PsLoadedModuleList") {
                    uint64_t SentinelUcAddr = Mod.UcBase + ExportRva;
                    auto SentinelHost = (LIST_ENTRY*)(HostBase + ExportRva);

                    uint64_t HeadLdrUc = (uint64_t)Environment::PsLoadedModuleList;
                    if (!HeadLdrUc) continue;

                    auto HeadHost = (PKLDR_DATA_TABLE_ENTRY)UnicornMem::UcToHost(HeadLdrUc);
                    if (!HeadHost) continue;

                    uint64_t LastLinkUc = (uint64_t)HeadHost->InLoadOrderLinks.Blink;
                    auto LastHost = (PKLDR_DATA_TABLE_ENTRY)UnicornMem::UcToHost(LastLinkUc);

                    SentinelHost->Flink = (LIST_ENTRY*)HeadLdrUc;
                    SentinelHost->Blink = (LIST_ENTRY*)LastLinkUc;

                    HeadHost->InLoadOrderLinks.Blink = (LIST_ENTRY*)SentinelUcAddr;

                    if (LastHost)
                        LastHost->InLoadOrderLinks.Flink = (LIST_ENTRY*)SentinelUcAddr;

                    Environment::PsLoadedModuleList = (PKLDR_DATA_TABLE_ENTRY)SentinelUcAddr;
                    Provider::data_providers["PsLoadedModuleList"] = (PVOID)SentinelUcAddr;

                    Logger::Log("{CYN}PatchSystemModuleExports: PsLoadedModuleList sentinel at UC 0x%llx (Flink=0x%llx, Blink=0x%llx){RESET}\n",
                        SentinelUcAddr, HeadLdrUc, LastLinkUc);
                    PatchedInPlace++;
                    continue;
                }

                uint64_t VarUcAddr = (uint64_t)Provider::data_providers[ExportName];
                void* VarHost = UnicornMem::UcToHost(VarUcAddr);

                size_t CopySize = sizeof(uint64_t);
                if (Provider::data_export_sizes.contains(ExportName))
                    CopySize = Provider::data_export_sizes[ExportName];

                if (!VarHost || ExportRva + CopySize > Mod.Size)
                    continue;

                uint64_t Value = 0;
                memcpy(&Value, VarHost, CopySize);

                bool Writable = IsRvaInWritableSection(HostBase, ExportRva);

                if (Writable) {
                    memcpy(HostBase + ExportRva, &Value, CopySize);
                    Provider::data_providers[ExportName] = (PVOID)(Mod.UcBase + ExportRva);
                    PatchedInPlace++;

                    Logger::Log("{CYN}  Patched %s at RVA 0x%x (%zu bytes, value=0x%llx){RESET}\n",
                        ExportName.c_str(), ExportRva, CopySize, Value);
                } else {
                    uint64_t UcAddr = UnicornMem::AllocateVariable(
                        PrimaryEngine, CopySize < 0x10 ? 0x10 : CopySize, ExportName.c_str());
                    if (UcAddr) {
                        void* UcHost = UnicornMem::UcToHost(UcAddr);
                        if (UcHost)
                            memcpy(UcHost, &Value, CopySize);
                        Provider::data_providers[ExportName] = (PVOID)UcAddr;
                        RedirectedToUc++;

                        Logger::Log("{YEL}  Redirected %s (RVA 0x%x, read-only section) to UC 0x%llx (%zu bytes, value=0x%llx){RESET}\n",
                            ExportName.c_str(), ExportRva, UcAddr, CopySize, Value);
                    }
                }
            }
        }

        Logger::Log("{CYN}PatchSystemModuleExports: %s — %d patched in-place, %d redirected to UC, %d exports total{RESET}\n",
            Mod.Name.c_str(), PatchedInPlace, RedirectedToUc, (int)AllExports.size());

        if (IsNtoskrnl) {
            auto Dos = (PIMAGE_DOS_HEADER)HostBase;
            auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
            auto ExDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            Logger::Log("{CYN}NTOS PE verify: e_lfanew=0x%x ImageBase=0x%llx ExportDir RVA=0x%x Size=0x%x SizeOfImage=0x%x{RESET}\n",
                Dos->e_lfanew, Nt->OptionalHeader.ImageBase, ExDir->VirtualAddress, ExDir->Size,
                Nt->OptionalHeader.SizeOfImage);

            auto ExportDir = (PIMAGE_EXPORT_DIRECTORY)(HostBase + ExDir->VirtualAddress);
            Logger::Log("{CYN}NTOS Export verify: NumFuncs=%u NumNames=%u AddressOfFunctions=0x%x AddressOfNames=0x%x{RESET}\n",
                ExportDir->NumberOfFunctions, ExportDir->NumberOfNames,
                ExportDir->AddressOfFunctions, ExportDir->AddressOfNames);

            auto Section = IMAGE_FIRST_SECTION(Nt);
            for (WORD I = 0; I < Nt->FileHeader.NumberOfSections; I++) {
                Logger::Log("{GRY}  Section[%d] %-8.8s VA=0x%06x VSize=0x%06x Chars=0x%08x %s{RESET}\n",
                    I, Section[I].Name, Section[I].VirtualAddress, Section[I].Misc.VirtualSize,
                    Section[I].Characteristics,
                    (Section[I].Characteristics & IMAGE_SCN_MEM_WRITE) ? "WRITABLE" : "read-only");
            }
        }
    }
}

void UnicornEmu::BuildSysModFuncCache() {
    std::lock_guard<std::mutex> Guard(SysModFuncCacheLock);
    SysModFuncCache.clear();
    for (auto& Mod : MappedSysMods) {
        auto AllExports = Mod.Pe->GetAllExports();
        for (auto& [Rva, Name] : AllExports) {
            SysModFuncEntry Entry;
            Entry.UcBase = Mod.UcBase;
            Entry.Size = Mod.Size;
            Entry.ModName = Mod.Name;
            Entry.FuncName = Name;
            Entry.HostFunc = nullptr;
            Entry.IsPassthrough = false;
            Entry.IsKnown = false;

            {
                std::shared_lock<std::shared_mutex> PGuard(Provider::ProviderLock);
                if (Provider::function_providers.contains(Name)) {
                    Entry.HostFunc = Provider::function_providers[Name];
                    Entry.IsKnown = true;
                } else if (Provider::passthrough_provider_cache.contains(Name)) {
                    Entry.HostFunc = Provider::passthrough_provider_cache[Name];
                    Entry.IsPassthrough = true;
                    Entry.IsKnown = true;
                } else if (Name == "NtQuerySystemInformation" || Name == "ZwQuerySystemInformation" ||
                           Name == "NtQueryInformationProcess" || Name == "IoWMIOpenBlock" ||
                           Name == "IoGetDeviceInterfaces" || Name == "ExGetFirmwareEnvironmentVariable") {
                    Logger::Log("{RED}BuildSysModFuncCache: critical function '%s' NOT in function_providers!{RESET}\n", Name.c_str());
                }
            }
            if (!Entry.HostFunc) {
                auto NtdllAddr = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), Name.c_str());
                if (NtdllAddr) {
                    Entry.HostFunc = NtdllAddr;
                    Entry.IsPassthrough = true;
                    Entry.IsKnown = true;
                    {
                        std::unique_lock<std::shared_mutex> PGuard(Provider::ProviderLock);
                        Provider::passthrough_provider_cache[Name] = NtdllAddr;
                    }
                }
            }
            SysModFuncCache[Mod.UcBase + Rva] = Entry;
        }
    }
    Logger::Log("{GRN}BuildSysModFuncCache: %llu functions cached across %zu modules{RESET}\n",
        (uint64_t)SysModFuncCache.size(), MappedSysMods.size());
}
