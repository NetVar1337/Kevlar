#include "include/common.h"
#include "mm_virtual.h"
#include <unordered_map>
#include <mutex>

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

BOOLEAN h_MmIsAddressValid(PVOID VirtualAddress) {
    if ((uintptr_t)VirtualAddress <= 0x10000)
        return false;
    if (UnicornMem::IsTracked((uint64_t)VirtualAddress))
        return true;
    return true;
}

NTSTATUS h_MmCopyMemory(
    PVOID           TargetAddress,
    MM_COPY_ADDRESS SourceAddress,
    SIZE_T          NumberOfBytes,
    ULONG           Flags,
    PSIZE_T         NumberOfBytesTransferred
){
    auto HostTarget = UcPtr(TargetAddress);
    auto HostBytesXfer = UcPtr(NumberOfBytesTransferred);
    if (Flags == MM_COPY_MEMORY_PHYSICAL) {
        *HostBytesXfer = NumberOfBytes;
    }
    else {
        Logger::Log("{BLU}\tCopyying %d bytes from %llx to %llx{RESET}\n", NumberOfBytes, SourceAddress, TargetAddress);
        *HostBytesXfer = NumberOfBytes;
    }
    return STATUS_SUCCESS;
}

PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName) {

    char CStr[512] = { 0 };
    auto HostName = (PUNICODE_STRING)UnicornMem::UcToHost((uint64_t)SystemRoutineName);
    if (!HostName)
        HostName = SystemRoutineName;

    wchar_t* WStr = HostName->Buffer;
    auto HostBuf = (wchar_t*)UnicornMem::UcToHost((uint64_t)WStr);
    if (HostBuf)
        WStr = HostBuf;

    wcstombs(CStr, WStr, 256);
    Logger::Log("{CYN}\tMmGetSystemRoutineAddress: %s{RESET}\n", CStr);

    {
        std::shared_lock<std::shared_mutex> Guard(Provider::ProviderLock);
        if (Provider::function_providers.contains(CStr)) {
            PVOID Func = Provider::function_providers[CStr];
            Guard.unlock();
            uint64_t Sentinel = UnicornEmu::AllocateSentinel(CStr, Func);
            Logger::Log("{GRN}\t-> sentinel 0x%llx{RESET}\n", Sentinel);
            return (PVOID)Sentinel;
        }

        if (Provider::data_providers.contains(CStr)) {
            auto UcAddr = Provider::data_providers[CStr];
            Logger::Log("{GRN}\t-> data export 0x%llx{RESET}\n", (uint64_t)UcAddr);
            return UcAddr;
        }

        if (Provider::passthrough_provider_cache.contains(CStr)) {
            PVOID Func = Provider::passthrough_provider_cache[CStr];
            Guard.unlock();
            uint64_t Sentinel = UnicornEmu::AllocateSentinel(CStr, Func, true);
            Logger::Log("{GRN}\t-> passthrough sentinel 0x%llx{RESET}\n", Sentinel);
            return (PVOID)Sentinel;
        }
    }

    auto NtdllAddr = (PVOID)GetProcAddress(LoadLibraryA("ntdll.dll"), CStr);
    if (NtdllAddr) {
        uint64_t Sentinel = UnicornEmu::AllocateSentinel(CStr, NtdllAddr, true);
        {
            std::unique_lock<std::shared_mutex> Guard(Provider::ProviderLock);
            Provider::passthrough_provider_cache.insert(std::pair(CStr, NtdllAddr));
        }
        Logger::Log("{GRN}\t-> ntdll passthrough sentinel 0x%llx{RESET}\n", Sentinel);
        return (PVOID)Sentinel;
    }

    Logger::Log("{YEL}\t-> not found, auto-stubbing as generic sentinel{RESET}\n");
    static std::unordered_map<std::string, PVOID> AutoStubs;
    static std::mutex AutoStubLock;
    {
        std::lock_guard<std::mutex> AsGuard(AutoStubLock);
        if (!AutoStubs.contains(CStr)) {
            AutoStubs[CStr] = (PVOID)[](uint64_t A1, uint64_t A2, uint64_t A3, uint64_t A4) -> uint64_t {
                Logger::Log("{YEL}\t[AUTO-STUB] unimplemented function called! a1=%llx a2=%llx a3=%llx a4=%llx{RESET}\n", A1, A2, A3, A4);
                return 0;
            };
        }
        PVOID StubFunc = AutoStubs[CStr];
        {
            std::unique_lock<std::shared_mutex> Guard(Provider::ProviderLock);
            Provider::function_providers[CStr] = StubFunc;
        }
        uint64_t Sentinel = UnicornEmu::AllocateSentinel(CStr, StubFunc);
        Logger::Log("{YEL}\t-> auto-stub sentinel 0x%llx{RESET}\n", Sentinel);
        return (PVOID)Sentinel;
    }
}

NTSTATUS h_MmUnmapViewOfSection(void* Process, void* BaseAddress) {
    Logger::Log("{BLU}\tMmUnmapViewOfSection: process=%p base=%p{RESET}\n", Process, BaseAddress);
    return 0;
}

NTSTATUS h_MmCopyVirtualMemory(
    void* SourceProcess, void* SourceAddress,
    void* TargetProcess, void* TargetAddress,
    uint64_t BufferSize, uint8_t PreviousMode,
    uint64_t* ReturnSize)
{
    Logger::Log("{BLU}\tMmCopyVirtualMemory: src=%p dst=%p size=%llu{RESET}\n",
        SourceAddress, TargetAddress, BufferSize);
    if (ReturnSize) {
        auto HostRet = UcPtr(ReturnSize);
        *HostRet = 0;
    }
    return 0xC0000005;
}

void* h_MmGetSystemRoutineAddressFromExport(PUNICODE_STRING SystemRoutineName) {
    Logger::Log("{CYN}\tMmGetSystemRoutineAddressFromExport{RESET}\n");
    return nullptr;
}

PVOID h_MmGetVirtualForPhysical(uint64_t PhysicalAddress) {
    Logger::Log("{BLU}\tMmGetVirtualForPhysical: PA=0x%llx{RESET}\n", PhysicalAddress);

    static std::unordered_map<uint64_t, uint64_t> PhysToVirtCache;
    static std::mutex CacheLock;

    uint64_t PagePA = PhysicalAddress & ~0xFFFULL;
    uint64_t PageOffset = PhysicalAddress & 0xFFF;

    {
        std::lock_guard<std::mutex> Guard(CacheLock);
        auto It = PhysToVirtCache.find(PagePA);
        if (It != PhysToVirtCache.end()) {
            uint64_t Result = It->second + PageOffset;
            Logger::Log("{GRN}\t-> cached VA 0x%llx{RESET}\n", Result);
            return (PVOID)Result;
        }
    }

    {
        std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
        for (auto& Region : UnicornEmu::MappedRegions) {
            if (!Region.HostPtr) continue;
            if (PhysicalAddress >= Region.UcBase && PhysicalAddress < Region.UcBase + Region.Size) {
                Logger::Log("{GRN}\t-> found in region '%s' -> VA 0x%llx{RESET}\n",
                    Region.Name.c_str(), PhysicalAddress);
                return (PVOID)PhysicalAddress;
            }
        }
    }

    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (PhysicalAddress >= Mod.UcBase && PhysicalAddress < Mod.UcBase + Mod.Size) {
            Logger::Log("{GRN}\t-> found in sysmod '%s' -> VA 0x%llx{RESET}\n",
                Mod.Name.c_str(), PhysicalAddress);
            return (PVOID)PhysicalAddress;
        }
    }

    uint64_t UcPage = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), 0x1000, 'PhMm');
    if (UcPage) {
        {
            std::lock_guard<std::mutex> Guard(CacheLock);
            PhysToVirtCache[PagePA] = UcPage;
        }
        uint64_t Result = UcPage + PageOffset;
        Logger::Log("{GRN}\t-> allocated pool page VA 0x%llx for PA 0x%llx{RESET}\n", Result, PhysicalAddress);
        return (PVOID)Result;
    }

    Logger::Log("{RED}\t-> failed to allocate backing page for PA 0x%llx{RESET}\n", PhysicalAddress);
    return nullptr;
}

PVOID h_MmAllocateContiguousNodeMemory(uint64_t NumberOfBytes, uint64_t LowestPA, uint64_t HighestPA, uint64_t BoundaryPA) {
    Logger::Log("{BLU}\tMmAllocateContiguousNodeMemory: size=0x%llx lowest=0x%llx highest=0x%llx boundary=0x%llx{RESET}\n",
        NumberOfBytes, LowestPA, HighestPA, BoundaryPA);
    uint64_t UcAddr = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), NumberOfBytes, 'CnMm');
    if (UcAddr) {
        Logger::Log("{GRN}\t-> allocated at VA 0x%llx{RESET}\n", UcAddr);
    } else {
        Logger::Log("{RED}\t-> allocation failed{RESET}\n");
    }
    return (PVOID)UcAddr;
}

void h_MmFreeContiguousMemory(PVOID BaseAddress) {
    Logger::Log("{BLU}\tMmFreeContiguousMemory: base=%p{RESET}\n", BaseAddress);
}
