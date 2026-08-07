#pragma once
#include "include/common.h"

struct RamRange {
    uint64_t base;
    uint64_t size;
};

extern RamRange myRam[9];
extern uint64_t AllocatedContiguous;

RamRange* h_MmGetPhysicalMemoryRanges();
PVOID h_MmAllocateContiguousMemorySpecifyCache(SIZE_T NumberOfBytes, uintptr_t LowestAcceptableAddress, uintptr_t HighestAcceptableAddress, uintptr_t BoundaryAddressMultiple, uint32_t CacheType);
unsigned long long h_MmGetPhysicalAddress(uint64_t BaseAddress);
PVOID k_MmMapIoSpaceEx(uint64_t PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);
