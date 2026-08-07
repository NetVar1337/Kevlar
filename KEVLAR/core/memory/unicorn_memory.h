#pragma once

#include <unicorn/unicorn.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <cstdint>
#include <windows.h>

#define PAGE_ALIGN_UP(x) (((x) + 0xFFF) & ~0xFFFULL)

namespace UnicornMem {

extern uint64_t NextPoolAddr;
extern uint64_t NextUsermodeAddr;
extern std::unordered_map<uint64_t, void*> UcToHostMap;
extern std::unordered_map<void*, uint64_t> HostToUcMap;
extern std::unordered_map<uint64_t, uint64_t> PoolSizes;
extern std::unordered_map<uint64_t, std::string> PoolNames;
extern std::shared_mutex PoolLock;

uint64_t AllocatePool(uc_engine* Uc, uint64_t Size);
uint64_t AllocatePoolWithTag(uc_engine* Uc, uint64_t Size, uint32_t Tag);
void FreePool(uc_engine* Uc, uint64_t UcAddr);
uint64_t AllocateVariable(uc_engine* Uc, uint64_t Size, const char* Name);
uint64_t AllocateUsermode(uc_engine* Uc, uint64_t Size, void* HostBuf);
void FreeUsermode(uc_engine* Uc, uint64_t UcAddr);
void* UcToHost(uint64_t UcAddr);
uint64_t HostToUc(void* HostPtr);
bool IsTracked(uint64_t UcAddr);
void TrackExisting(uint64_t UcAddr, void* HostPtr, uint64_t Size, const char* Name);
bool FindAllocation(uint64_t UcAddr, uint64_t& OutBase, void*& OutHost, uint64_t& OutSize);

}
