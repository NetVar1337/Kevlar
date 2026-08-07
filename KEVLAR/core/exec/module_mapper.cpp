#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include <SymParser/symparser.hpp>
#include "host/providers/provider.h"
#include "core/memory/unicorn_memory.h"
#include <malloc.h>

uint64_t UnicornEmu::AllocateSentinel(const char* FuncName, PVOID HostFunc, bool IsPassthrough) {
    std::unique_lock<std::shared_mutex> Guard(EngineLock);

    NextSentinelAddr = (NextSentinelAddr + 0xF) & ~0xFULL;

    if (NextSentinelAddr >= SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE - 0x100) {
        Logger::Log("{RED}Sentinel range exhausted!{RESET}\n");
        return 0;
    }

    uint64_t Addr = NextSentinelAddr;

    StubEntry Entry;
    Entry.Name = std::string(FuncName);
    Entry.HostFunc = HostFunc;
    Entry.SentinelAddr = Addr;
    Entry.IsPassthrough = IsPassthrough;

    SentinelMap[Addr] = Entry;
    NextSentinelAddr += 0x10;

    return Addr;
}

void UnicornEmu::BuildSentinelIat(PEFile* Module) {
    auto UcBase = DRIVER_BASE_UC;
    auto UcHostBase = (unsigned char*)UnicornMem::UcToHost(UcBase);
    if (!UcHostBase) {
        Logger::Log("{RED}BuildSentinelIat: UC image not host-backed{RESET}\n");
        return;
    }

    auto DosHeader = (PIMAGE_DOS_HEADER)UcHostBase;
    auto NtHeaders = (PIMAGE_NT_HEADERS)(UcHostBase + DosHeader->e_lfanew);
    auto ImportDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!ImportDir->VirtualAddress || !ImportDir->Size)
        return;

    auto ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(UcHostBase + ImportDir->VirtualAddress);
    auto Ntdll = LoadLibraryA("ntdll.dll");

    int CountProvider = 0;
    int CountPassthrough = 0;
    int CountUnimplemented = 0;
    int CountTotal = 0;

    std::vector<std::string> UnimplList;

    for (; ImportDesc->Name; ImportDesc++) {
        auto DllName = (char*)(UcHostBase + ImportDesc->Name);

        auto ImportedModule = PEFile::FindModule(std::string(DllName));
        HMODULE ImportedHmod = nullptr;
        if (ImportedModule)
            ImportedHmod = (HMODULE)ImportedModule->GetMappedImageBase();

        PIMAGE_THUNK_DATA OrigThunk;
        if (ImportDesc->OriginalFirstThunk)
            OrigThunk = (PIMAGE_THUNK_DATA)(UcHostBase + ImportDesc->OriginalFirstThunk);
        else
            OrigThunk = (PIMAGE_THUNK_DATA)(UcHostBase + ImportDesc->FirstThunk);

        uint64_t IatThunkRva = ImportDesc->FirstThunk;

        for (; OrigThunk->u1.AddressOfData; OrigThunk++, IatThunkRva += sizeof(IMAGE_THUNK_DATA)) {
            const char* FuncName = nullptr;
            char OrdinalName[64] = { 0 };

            if (IMAGE_SNAP_BY_ORDINAL(OrigThunk->u1.Ordinal)) {
                USHORT Ordinal = IMAGE_ORDINAL(OrigThunk->u1.Ordinal);
                if (ImportedHmod) {
                    auto ImportedDos = (PIMAGE_DOS_HEADER)ImportedHmod;
                    auto ImportedNt = (PIMAGE_NT_HEADERS)((uint8_t*)ImportedHmod + ImportedDos->e_lfanew);
                    auto ExportDirRva = ImportedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (ExportDirRva) {
                        auto ExportDir = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)ImportedHmod + ExportDirRva);
                        if (ExportDir->AddressOfNames && ExportDir->AddressOfNameOrdinals) {
                            auto Names = (PDWORD)((uint8_t*)ImportedHmod + ExportDir->AddressOfNames);
                            auto Ordinals = (PWORD)((uint8_t*)ImportedHmod + ExportDir->AddressOfNameOrdinals);
                            for (DWORD I = 0; I < ExportDir->NumberOfNames; I++) {
                                if (Ordinals[I] == (Ordinal - (USHORT)ExportDir->Base)) {
                                    FuncName = (const char*)((uint8_t*)ImportedHmod + Names[I]);
                                    break;
                                }
                            }
                        }
                    }
                }
                if (!FuncName) {
                    sprintf_s(OrdinalName, "%s!Ordinal_%u", DllName, (unsigned)IMAGE_ORDINAL(OrigThunk->u1.Ordinal));
                    FuncName = OrdinalName;
                }
            } else {
                auto ImportByName = (PIMAGE_IMPORT_BY_NAME)(UcHostBase + (OrigThunk->u1.AddressOfData & 0x7FFFFFFF));
                FuncName = (const char*)ImportByName->Name;
            }

            std::string FuncNameStr(FuncName);
            uint64_t SentinelAddr = 0;
            CountTotal++;

            if (Provider::function_providers.contains(FuncNameStr)) {
                SentinelAddr = AllocateSentinel(FuncName, Provider::function_providers[FuncNameStr]);
                CountProvider++;
            } else {
                auto NtdllAddr = (PVOID)GetProcAddress(Ntdll, FuncName);
                if (NtdllAddr) {
                    SentinelAddr = AllocateSentinel(FuncName, NtdllAddr, true);
                    CountPassthrough++;
                } else {
                    SentinelAddr = AllocateSentinel(FuncName, (PVOID)Provider::unimplemented_stub);
                    CountUnimplemented++;
                    UnimplList.push_back(std::string(DllName) + "!" + FuncNameStr);
                }
            }

            if (SentinelAddr) {
                auto ThunkHostPtr = (uint64_t*)(UcHostBase + IatThunkRva);
                *ThunkHostPtr = SentinelAddr;
            }
        }
    }

    Logger::Log("{CYN}BuildSentinelIat: %d total imports, %d provider, %d passthrough, %d unimplemented{RESET}\n",
        CountTotal, CountProvider, CountPassthrough, CountUnimplemented);

    if (!UnimplList.empty()) {
        Logger::Log("{YEL}Unimplemented imports:{RESET}\n");
        for (auto& Name : UnimplList) {
            Logger::Log("{YEL}  [STUB] %s{RESET}\n", Name.c_str());
        }
    }
}

static void RelocateImage(unsigned char* ImageBuf, uint64_t OldBase, uint64_t NewBase) {
    auto Dos = (PIMAGE_DOS_HEADER)ImageBuf;
    auto Nt = (PIMAGE_NT_HEADERS)(ImageBuf + Dos->e_lfanew);
    auto RelocDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!RelocDir->VirtualAddress || !RelocDir->Size)
        return;

    int64_t Delta = (int64_t)(NewBase - OldBase);
    if (Delta == 0)
        return;

    auto RelocBlock = (PIMAGE_BASE_RELOCATION)(ImageBuf + RelocDir->VirtualAddress);
    auto RelocEnd = (uint8_t*)RelocBlock + RelocDir->Size;

    int FixupCount = 0;

    while ((uint8_t*)RelocBlock < RelocEnd && RelocBlock->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        uint32_t PageRva = RelocBlock->VirtualAddress;
        uint32_t NumEntries = (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto Entries = (WORD*)((uint8_t*)RelocBlock + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t I = 0; I < NumEntries; I++) {
            uint16_t Type = Entries[I] >> 12;
            uint16_t Offset = Entries[I] & 0xFFF;

            if (Type == IMAGE_REL_BASED_DIR64) {
                uint64_t* FixupAddr = (uint64_t*)(ImageBuf + PageRva + Offset);
                *FixupAddr += Delta;
                FixupCount++;
            } else if (Type == IMAGE_REL_BASED_HIGHLOW) {
                uint32_t* FixupAddr = (uint32_t*)(ImageBuf + PageRva + Offset);
                *FixupAddr += (uint32_t)Delta;
                FixupCount++;
            } else if (Type == IMAGE_REL_BASED_ABSOLUTE) {
            }
        }

        RelocBlock = (PIMAGE_BASE_RELOCATION)((uint8_t*)RelocBlock + RelocBlock->SizeOfBlock);
    }

    Nt->OptionalHeader.ImageBase = NewBase;

    Logger::Log("{BLU}RelocateImage: applied %d fixups (delta=0x%llx){RESET}\n", FixupCount, Delta);
}

uint64_t UnicornEmu::MapDriverImage(PEFile* Driver, uint64_t DesiredBase) {
    uint64_t VirtSize = Driver->GetVirtualSize();
    uint64_t AlignedSize = (VirtSize + 0xFFF) & ~0xFFFULL;

    void* DriverHostCopy = _aligned_malloc((size_t)AlignedSize, 0x1000);
    if (!DriverHostCopy) {
        Logger::Log("{RED}MapDriverImage alloc failed{RESET}\n");
        return 0;
    }
    memset(DriverHostCopy, 0, (size_t)AlignedSize);
    memcpy(DriverHostCopy, (void*)Driver->GetMappedImageBase(), (size_t)VirtSize);

    uint64_t HostLoadBase = Driver->GetMappedImageBase();
    RelocateImage((unsigned char*)DriverHostCopy, HostLoadBase, DesiredBase);

    if (!MapRegionPtr(PrimaryEngine, DesiredBase, AlignedSize, UC_PROT_ALL, DriverHostCopy, "DriverImage"))
        return 0;

    UnicornMem::TrackExisting(DesiredBase, DriverHostCopy, AlignedSize, "DriverImage");

    Logger::Log("{BLU}MapDriverImage: 0x%llx (size=0x%llx, EP RVA=0x%llx, relocated from 0x%llx){RESET}\n",
        DesiredBase, AlignedSize, Driver->GetEP(), HostLoadBase);
    return DesiredBase;
}

uint64_t UnicornEmu::MapSystemModule(PEFile* Module, const char* Name) {
    uint64_t VirtSize = Module->GetVirtualSize();
    uint64_t AlignedSize = (VirtSize + 0xFFF) & ~0xFFFULL;

    void* ModHostCopy = _aligned_malloc((size_t)AlignedSize, 0x1000);
    if (!ModHostCopy) {
        Logger::Log("{RED}MapSystemModule '%s' alloc failed{RESET}\n", Name);
        return 0;
    }

    memset(ModHostCopy, 0, (size_t)AlignedSize);
    memcpy(ModHostCopy, (void*)Module->GetMappedImageBase(), (size_t)VirtSize);

    uint64_t HostLoadBase = Module->GetMappedImageBase();
    uint64_t UcBase = NextSysModAddr;
    NextSysModAddr += AlignedSize + 0x10000;
    NextSysModAddr = (NextSysModAddr + 0xFFFF) & ~0xFFFFULL;

    RelocateImage((unsigned char*)ModHostCopy, HostLoadBase, UcBase);

    if (!MapRegionPtr(PrimaryEngine, UcBase, AlignedSize, UC_PROT_ALL, ModHostCopy, Name))
        return 0;

    UnicornMem::TrackExisting(UcBase, ModHostCopy, AlignedSize, Name);

    uc_hook Hh;
    uc_hook_add(PrimaryEngine, &Hh, UC_HOOK_CODE, (void*)Hooks::OnSysModExec, nullptr,
        UcBase, UcBase + AlignedSize - 1);

    SysModInfo Info;
    Info.UcBase = UcBase;
    Info.Size = AlignedSize;
    Info.Name = std::string(Name);
    Info.Pe = Module;
    MappedSysMods.push_back(Info);

    Logger::Log("{BLU}MapSystemModule '%s': UC 0x%llx (size=0x%llx, relocated from 0x%llx){RESET}\n",
        Name, UcBase, AlignedSize, HostLoadBase);

    std::string NameLower(Name);
    for (auto& C : NameLower) C = tolower(C);
    if (NameLower.find("ntoskrnl") != std::string::npos) {
        struct { const char* Name; uint8_t Value; } KernelGlobals[] = {
            { "KdDebuggerEnabled",    0x00 },
            { "KdDebuggerNotPresent", 0x01 },
            { "KdEnteredDebugger",    0x00 },
        };
        for (auto& G : KernelGlobals) {
            uint64_t Rva = Module->GetExport(std::string(G.Name));
            if (Rva) {
                uint64_t UcAddr = UcBase + Rva;
                void* HostPtr = UnicornMem::UcToHost(UcAddr);
                if (HostPtr) {
                    *(uint8_t*)HostPtr = G.Value;
                    Logger::Log("{GRN}Patched ntoskrnl!%s (RVA 0x%llx) = 0x%02x{RESET}\n", G.Name, Rva, G.Value);
                }
            }
        }

        uint64_t Rva = Module->GetExport(std::string("KdPitchDebugger"));
        if (Rva) {
            uint64_t UcAddr = UcBase + Rva;
            void* HostPtr = UnicornMem::UcToHost(UcAddr);
            if (HostPtr) {
                *(uint8_t*)HostPtr = 0x01;
                Logger::Log("{GRN}Patched ntoskrnl!KdPitchDebugger (RVA 0x%llx) = 0x01{RESET}\n", Rva);
            }
        }

        uint64_t NtBuildRva = Module->GetExport(std::string("NtBuildNumber"));
        if (NtBuildRva) {
            uint64_t UcAddr = UcBase + NtBuildRva;
            void* HostPtr = UnicornMem::UcToHost(UcAddr);
            if (HostPtr) {
                uint32_t CurrentBuild = *(uint32_t*)HostPtr;
                Logger::Log("{GRN}ntoskrnl!NtBuildNumber (RVA 0x%llx) = 0x%x (build %u, free=%s){RESET}\n",
                    NtBuildRva, CurrentBuild, CurrentBuild & 0xFFFF,
                    (CurrentBuild & 0xF0000000) == 0xF0000000 ? "yes" : "no");
            }
        }

        auto KeSdtSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KeServiceDescriptorTable");
        if (KeSdtSym && KeSdtSym->rva) {
            uint64_t KeSdtUcAddr = UcBase + KeSdtSym->rva;
            auto KeSdtHost = (uint8_t*)UnicornMem::UcToHost(KeSdtUcAddr);

            if (KeSdtHost) {
                uint64_t CurrentServiceTable = *(uint64_t*)(KeSdtHost);

                if (CurrentServiceTable == 0) {
                    auto KiStSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiServiceTable");
                    if (KiStSym && KiStSym->rva) {
                        uint64_t KiStUcAddr = UcBase + KiStSym->rva;
                        *(uint64_t*)(KeSdtHost + 0x00) = KiStUcAddr;

                        uint32_t ServiceLimit = 500;
                        auto LimitSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiServiceLimit");
                        if (LimitSym && LimitSym->rva) {
                            auto LimitHost = (uint32_t*)UnicornMem::UcToHost(UcBase + LimitSym->rva);
                            if (LimitHost && *LimitHost > 0 && *LimitHost < 2000)
                                ServiceLimit = *LimitHost;
                        }
                        *(uint32_t*)(KeSdtHost + 0x10) = ServiceLimit;

                        auto ArgSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiArgumentTable");
                        if (ArgSym && ArgSym->rva)
                            *(uint64_t*)(KeSdtHost + 0x18) = UcBase + ArgSym->rva;

                        Logger::Log("{GRN}Initialized KeServiceDescriptorTable at UC 0x%llx: ServiceTable=0x%llx (ntoskrnl+0x%llx) Limit=%u{RESET}\n",
                            KeSdtUcAddr, KiStUcAddr, (uint64_t)KiStSym->rva, ServiceLimit);
                    } else {
                        Logger::Log("{YEL}KeServiceDescriptorTable found but KiServiceTable symbol not in PDB — SSDT will be unavailable{RESET}\n");
                    }
                } else {
                    Logger::Log("{GRN}KeServiceDescriptorTable.ServiceTable already set: 0x%llx (relocation handled it){RESET}\n", CurrentServiceTable);
                }
            }
        } else {
            Logger::Log("{YEL}KeServiceDescriptorTable symbol not found in ntoskrnl PDB{RESET}\n");
        }

        auto KeSdtShadowSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KeServiceDescriptorTableShadow");
        if (KeSdtShadowSym && KeSdtShadowSym->rva) {
            uint64_t KeSdtShadowUcAddr = UcBase + KeSdtShadowSym->rva;
            auto KeSdtShadowHost = (uint8_t*)UnicornMem::UcToHost(KeSdtShadowUcAddr);

            if (KeSdtShadowHost) {
                uint64_t CurrentShadowServiceTable = *(uint64_t*)(KeSdtShadowHost);
                if (CurrentShadowServiceTable == 0) {
                    auto KiStSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiServiceTable");
                    if (KiStSym && KiStSym->rva) {
                        *(uint64_t*)(KeSdtShadowHost + 0x00) = UcBase + KiStSym->rva;

                        uint32_t ServiceLimit = 500;
                        auto LimitSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiServiceLimit");
                        if (LimitSym && LimitSym->rva) {
                            auto LimitHost = (uint32_t*)UnicornMem::UcToHost(UcBase + LimitSym->rva);
                            if (LimitHost && *LimitHost > 0 && *LimitHost < 2000)
                                ServiceLimit = *LimitHost;
                        }
                        *(uint32_t*)(KeSdtShadowHost + 0x10) = ServiceLimit;

                        auto ArgSym = symparser::find_symbol("c:\\Windows\\System32\\ntoskrnl.exe", "KiArgumentTable");
                        if (ArgSym && ArgSym->rva)
                            *(uint64_t*)(KeSdtShadowHost + 0x18) = UcBase + ArgSym->rva;

                        Logger::Log("{GRN}Initialized KeServiceDescriptorTableShadow at UC 0x%llx{RESET}\n", KeSdtShadowUcAddr);
                    }
                }
            }
        }

        uint64_t ObfRefRva = Module->GetExport(std::string("ObfReferenceObject"));
        if (ObfRefRva) {
            uint64_t PatchAddr = UcBase + ObfRefRva + 0x31;
            uint8_t* PatchHost = (uint8_t*)UnicornMem::UcToHost(PatchAddr);
            if (PatchHost && PatchHost[0] == 0x0F && PatchHost[1] == 0x8E) {
                memset(PatchHost, 0x90, 6);
                Logger::Log("{GRN}Patched ntoskrnl!ObfReferenceObject+0x31: NOP'd bugcheck branch (6 bytes){RESET}\n");
            }
        }

        uint64_t ObfDerefRva = Module->GetExport(std::string("ObfDereferenceObject"));
        if (ObfDerefRva) {
            uint64_t FuncAddr = UcBase + ObfDerefRva;
            uint8_t* FuncHost = (uint8_t*)UnicornMem::UcToHost(FuncAddr);
            if (FuncHost) {
                for (int ScanOff = 0; ScanOff < 0x60; ScanOff++) {
                    if (FuncHost[ScanOff] == 0x0F && FuncHost[ScanOff + 1] == 0x8E) {
                        int32_t JmpDelta = *(int32_t*)&FuncHost[ScanOff + 2];
                        if (JmpDelta > 0x1000) {
                            memset(&FuncHost[ScanOff], 0x90, 6);
                            Logger::Log("{GRN}Patched ntoskrnl!ObfDereferenceObject+0x%x: NOP'd bugcheck branch{RESET}\n", ScanOff);
                            break;
                        }
                    }
                }
            }
        }
    }

    return UcBase;
}
