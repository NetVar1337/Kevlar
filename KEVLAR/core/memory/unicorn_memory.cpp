#include "core/memory/unicorn_memory.h"
#include "core/exec/unicorn_engine.h"
#include <Logger/Logger.h>
#include <malloc.h>

namespace UnicornMem {
    uint64_t NextPoolAddr = 0xFFFFB00000000000ULL;
    uint64_t NextUsermodeAddr = USERMODE_MAPPING_BASE;
    std::unordered_map<uint64_t, void*> UcToHostMap;
    std::unordered_map<void*, uint64_t> HostToUcMap;
    std::unordered_map<uint64_t, uint64_t> PoolSizes;
    std::unordered_map<uint64_t, std::string> PoolNames;
    std::shared_mutex PoolLock;
}

uint64_t UnicornMem::AllocatePool(uc_engine* Uc, uint64_t Size) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    if (Size == 0)
        Size = 0x1000;

    uint64_t AlignedSize = PAGE_ALIGN_UP(Size);

    void* HostBuf = _aligned_malloc(AlignedSize, 0x1000);
    if (!HostBuf) {
        Logger::Log("{RED}Pool alloc FAILED: size=0x%llx{RESET}\n", AlignedSize);
        return 0;
    }
    memset(HostBuf, 0, AlignedSize);

    uint64_t CurrentAddr = NextPoolAddr;
    NextPoolAddr += AlignedSize;

    {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, CurrentAddr, AlignedSize, UC_PROT_ALL, HostBuf);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}Pool alloc uc_mem_map_ptr FAILED: 0x%llx size=0x%llx err=%d{RESET}\n", CurrentAddr, AlignedSize, Err);
            _aligned_free(HostBuf);
            NextPoolAddr -= AlignedSize;
            return 0;
        }
    }

    UcToHostMap[CurrentAddr] = HostBuf;
    HostToUcMap[HostBuf] = CurrentAddr;
    PoolSizes[CurrentAddr] = AlignedSize;

    if (UnicornEmu::DiagnosticHooksEnabled)
        Logger::Log("{BLU}Pool alloc: 0x%llx (size=0x%llx){RESET}\n", CurrentAddr, AlignedSize);

    return CurrentAddr;
}

uint64_t UnicornMem::AllocatePoolWithTag(uc_engine* Uc, uint64_t Size, uint32_t Tag) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    if (Size == 0)
        Size = 0x1000;

    uint64_t AlignedSize = PAGE_ALIGN_UP(Size);

    void* HostBuf = _aligned_malloc(AlignedSize, 0x1000);
    if (!HostBuf) {
        Logger::Log("{RED}Pool alloc (tag) FAILED: size=0x%llx{RESET}\n", AlignedSize);
        return 0;
    }
    memset(HostBuf, 0, AlignedSize);

    uint64_t CurrentAddr = NextPoolAddr;
    NextPoolAddr += AlignedSize;

    {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, CurrentAddr, AlignedSize, UC_PROT_ALL, HostBuf);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}Pool alloc (tag) uc_mem_map_ptr FAILED: 0x%llx size=0x%llx err=%d{RESET}\n", CurrentAddr, AlignedSize, Err);
            _aligned_free(HostBuf);
            NextPoolAddr -= AlignedSize;
            return 0;
        }
    }

    UcToHostMap[CurrentAddr] = HostBuf;
    HostToUcMap[HostBuf] = CurrentAddr;
    PoolSizes[CurrentAddr] = AlignedSize;

    char TagStr[5] = {};
    memcpy(TagStr, &Tag, 4);
    PoolNames[CurrentAddr] = std::string(TagStr);

    if (UnicornEmu::DiagnosticHooksEnabled)
        Logger::Log("{BLU}Pool alloc tag '%s': 0x%llx (size=0x%llx){RESET}\n", TagStr, CurrentAddr, AlignedSize);

    return CurrentAddr;
}

void UnicornMem::FreePool(uc_engine* Uc, uint64_t UcAddr) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    auto It = UcToHostMap.find(UcAddr);
    if (It == UcToHostMap.end()) {
        Logger::Log("{RED}Pool free: 0x%llx not found{RESET}\n", UcAddr);
        return;
    }

    void* HostBuf = It->second;

    HostToUcMap.erase(HostBuf);
    UcToHostMap.erase(It);
    PoolSizes.erase(UcAddr);
    PoolNames.erase(UcAddr);

    _aligned_free(HostBuf);

    if (UnicornEmu::DiagnosticHooksEnabled)
        Logger::Log("{BLU}Pool free: 0x%llx{RESET}\n", UcAddr);
}

uint64_t UnicornMem::AllocateVariable(uc_engine* Uc, uint64_t Size, const char* Name) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);
    if (UnicornEmu::DiagnosticHooksEnabled)
        Logger::Log("{BLU}Allocate Request raw size: %i{RESET}\n", Size);
    if (Size == 0)
        Size = 0x1000;

    uint64_t AlignedSize = PAGE_ALIGN_UP(Size);

    void* HostBuf = _aligned_malloc(AlignedSize, 0x1000);
    if (!HostBuf) {
        Logger::Log("{RED}Variable alloc '%s' FAILED: size=0x%llx{RESET}\n", Name, AlignedSize);
        return 0;
    }
    memset(HostBuf, 0, AlignedSize);

    uint64_t CurrentAddr = NextPoolAddr;
    NextPoolAddr += AlignedSize;

    {
        std::lock_guard<std::mutex> MapGuard(UnicornEmu::UcMapLock);
        uc_err Err = uc_mem_map_ptr(Uc, CurrentAddr, AlignedSize, UC_PROT_ALL, HostBuf);
        if (Err != UC_ERR_OK) {
            Logger::Log("{RED}Variable alloc '%s' uc_mem_map_ptr FAILED: 0x%llx size=0x%llx err=%d{RESET}\n", Name, CurrentAddr, AlignedSize, Err);
            _aligned_free(HostBuf);
            NextPoolAddr -= AlignedSize;
            return 0;
        }
    }

    UcToHostMap[CurrentAddr] = HostBuf;
    HostToUcMap[HostBuf] = CurrentAddr;
    PoolSizes[CurrentAddr] = AlignedSize;
    PoolNames[CurrentAddr] = std::string(Name);

    if (UnicornEmu::DiagnosticHooksEnabled)
        Logger::Log("{BLU}Variable alloc '%s': 0x%llx (size=0x%llx){RESET}\n", Name, CurrentAddr, AlignedSize);

    return CurrentAddr;
}

void* UnicornMem::UcToHost(uint64_t UcAddr) {
    std::shared_lock<std::shared_mutex> Guard(PoolLock);

    auto It = UcToHostMap.find(UcAddr);
    if (It != UcToHostMap.end())
        return It->second;

    for (auto& Entry : UcToHostMap) {
        uint64_t Base = Entry.first;
        auto SizeIt = PoolSizes.find(Base);
        if (SizeIt == PoolSizes.end())
            continue;
        uint64_t AllocSize = SizeIt->second;
        if (UcAddr >= Base && UcAddr < Base + AllocSize) {
            uint64_t Offset = UcAddr - Base;
            return (uint8_t*)Entry.second + Offset;
        }
    }

    return nullptr;
}

uint64_t UnicornMem::HostToUc(void* HostPtr) {
    std::shared_lock<std::shared_mutex> Guard(PoolLock);

    auto It = HostToUcMap.find(HostPtr);
    if (It != HostToUcMap.end())
        return It->second;

    return 0;
}

bool UnicornMem::IsTracked(uint64_t UcAddr) {
    std::shared_lock<std::shared_mutex> Guard(PoolLock);

    if (UcToHostMap.find(UcAddr) != UcToHostMap.end())
        return true;

    for (auto& Entry : UcToHostMap) {
        uint64_t Base = Entry.first;
        auto SizeIt = PoolSizes.find(Base);
        if (SizeIt == PoolSizes.end())
            continue;
        uint64_t AllocSize = SizeIt->second;
        if (UcAddr >= Base && UcAddr < Base + AllocSize)
            return true;
    }

    return false;
}

void UnicornMem::TrackExisting(uint64_t UcAddr, void* HostPtr, uint64_t Size, const char* Name) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    uint64_t AlignedSize = PAGE_ALIGN_UP(Size);

    UcToHostMap[UcAddr] = HostPtr;
    HostToUcMap[HostPtr] = UcAddr;
    PoolSizes[UcAddr] = AlignedSize;
    if (Name)
        PoolNames[UcAddr] = std::string(Name);

    Logger::Log("{BLU}Track existing '%s': 0x%llx -> host %p (size=0x%llx){RESET}\n", Name ? Name : "unnamed", UcAddr, HostPtr, AlignedSize);
}

bool UnicornMem::FindAllocation(uint64_t UcAddr, uint64_t& OutBase, void*& OutHost, uint64_t& OutSize) {
    std::shared_lock<std::shared_mutex> Guard(PoolLock);

    auto It = UcToHostMap.find(UcAddr);
    if (It != UcToHostMap.end()) {
        OutBase = UcAddr;
        OutHost = It->second;
        auto SizeIt = PoolSizes.find(UcAddr);
        OutSize = SizeIt != PoolSizes.end() ? SizeIt->second : 0x1000;
        return true;
    }

    for (auto& Entry : UcToHostMap) {
        uint64_t Base = Entry.first;
        auto SizeIt = PoolSizes.find(Base);
        if (SizeIt == PoolSizes.end())
            continue;
        uint64_t AllocSize = SizeIt->second;
        if (UcAddr >= Base && UcAddr < Base + AllocSize) {
            OutBase = Base;
            OutHost = Entry.second;
            OutSize = AllocSize;
            return true;
        }
    }

    return false;
}

uint64_t UnicornMem::AllocateUsermode(uc_engine* Uc, uint64_t Size, void* HostBuf) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    if (Size == 0)
        Size = 0x1000;

    uint64_t AlignedSize = PAGE_ALIGN_UP(Size);
    uint64_t CurrentAddr = NextUsermodeAddr;
    NextUsermodeAddr += AlignedSize;

    if (NextUsermodeAddr >= 0x7FFFFFFEFFFFULL) {
        Logger::Log("{RED}AllocateUsermode: exhausted usermode address space{RESET}\n");
        return 0;
    }

    uc_err Err = uc_mem_map_ptr(Uc, CurrentAddr, AlignedSize, UC_PROT_ALL, HostBuf);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}AllocateUsermode uc_mem_map_ptr FAILED: 0x%llx size=0x%llx err=%d{RESET}\n", CurrentAddr, AlignedSize, Err);
        return 0;
    }

    UcToHostMap[CurrentAddr] = HostBuf;
    HostToUcMap[HostBuf] = CurrentAddr;
    PoolSizes[CurrentAddr] = AlignedSize;
    PoolNames[CurrentAddr] = std::string("UsermodeMapping");

    Logger::Log("{BLU}AllocateUsermode: 0x%llx -> host %p (size=0x%llx){RESET}\n", CurrentAddr, HostBuf, AlignedSize);

    return CurrentAddr;
}

void UnicornMem::FreeUsermode(uc_engine* Uc, uint64_t UcAddr) {
    std::unique_lock<std::shared_mutex> Guard(PoolLock);

    auto It = UcToHostMap.find(UcAddr);
    if (It == UcToHostMap.end()) {
        for (auto& Entry : UcToHostMap) {
            uint64_t Base = Entry.first;
            auto SizeIt = PoolSizes.find(Base);
            if (SizeIt == PoolSizes.end()) continue;
            if (UcAddr >= Base && UcAddr < Base + SizeIt->second) {
                It = UcToHostMap.find(Base);
                UcAddr = Base;
                break;
            }
        }
    }

    if (It == UcToHostMap.end()) {
        Logger::Log("{YEL}FreeUsermode: 0x%llx not found{RESET}\n", UcAddr);
        return;
    }

    void* HostBuf = It->second;
    uint64_t AllocSize = PoolSizes[UcAddr];

    uc_mem_unmap(Uc, UcAddr, AllocSize);

    HostToUcMap.erase(HostBuf);
    UcToHostMap.erase(It);
    PoolSizes.erase(UcAddr);
    PoolNames.erase(UcAddr);

    Logger::Log("{BLU}FreeUsermode: 0x%llx (size=0x%llx){RESET}\n", UcAddr, AllocSize);
}
