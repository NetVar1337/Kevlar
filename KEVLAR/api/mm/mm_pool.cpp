#include "include/common.h"
#include "mm_pool.h"

void* hM_AllocPool(uint32_t pooltype, size_t size);

RamRange myRam[9] = { { 0x1000, 0x57000 }, { 0x59000, 0x46000 }, { 0x100000, 0xb81b9000 }, { 0xb82f1000, 0x3b0000 }, { 0xb86a3000, 0xcc58000 },
    { 0xc6b99000, 0xfd000 }, { 0xc7ba2000, 0x5e000 }, { 0x100000000, 0x337000000 }, { 0, 0 } };

uint64_t AllocatedContiguous = 0;

RamRange* h_MmGetPhysicalMemoryRanges() { return myRam; }

PVOID h_MmAllocateContiguousMemorySpecifyCache(SIZE_T NumberOfBytes, uintptr_t LowestAcceptableAddress, uintptr_t HighestAcceptableAddress,
    uintptr_t BoundaryAddressMultiple, uint32_t CacheType) {
    Logger::Log("{BLU}\tLowest : %llx - Highest : %llx - Boundary : %llx - Cache Type : %d - Size : %08x{RESET}\n", LowestAcceptableAddress, HighestAcceptableAddress,
        BoundaryAddressMultiple, CacheType, NumberOfBytes);
    AllocatedContiguous = (uint64_t)hM_AllocPool(CacheType, NumberOfBytes);
    return (PVOID)AllocatedContiguous;
}


unsigned long long h_MmGetPhysicalAddress(uint64_t BaseAddress) { //To test shit

    Logger::Log("{BLU}\tGetting Physical address for %llx{RESET}\n", BaseAddress);
    uint64_t ret = BaseAddress/0x1000;

    if (BaseAddress == AllocatedContiguous) {
        Logger::Log("{BLU}\tGetting physical for last Contiguous Allocated Memory.{RESET}\n");
        ret = 0xb0000000;
    }
    if (BaseAddress == 0xf0f87c3e1000) {
        ret = 0x1ad000;
    } else if (BaseAddress == 0xfb7dbedf6000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfbfdfeff7000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfc7e3f1f8000) {
        ret = 0x200000;
    } else if (BaseAddress == 0xfcfe7f3f9000) {
        ret = 0x200000;
    }

    Logger::Log("{GRY}\tReturn : %llx{RESET}\n", ret);
    return ret;
}

PVOID k_MmMapIoSpaceEx(
   uint64_t PhysicalAddress,
   SIZE_T           NumberOfBytes,
   ULONG            Protect
) {
    if (PhysicalAddress == 0xfee00000)
        return 0;
    return (PVOID)(PhysicalAddress * 0x1000);
}
