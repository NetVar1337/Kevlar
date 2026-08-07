#include "include/common.h"
#include "mm_pool.h"
#include <malloc.h>

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
    if (PhysicalAddress == 0xFED90000) {
        // VT-d DMAR register block referenced by the synthetic DMAR table.
        // Map the returned VA with a host buffer holding coherent capability
        // registers so READ_REGISTER_* on it does not fault.
        // ponytail: minimal register set (version/cap/status/root table); extend
        // when a real IOMMU driver is seen polling specific bits.
        size_t Size = PAGE_ALIGN_UP(NumberOfBytes ? NumberOfBytes : 0x1000);
        uint64_t Va = PhysicalAddress * 0x1000;
        void* HostBuf = UnicornMem::UcToHost(Va);
        if (!HostBuf) {
            HostBuf = _aligned_malloc(Size, 0x1000);
            if (!HostBuf) return nullptr;
            memset(HostBuf, 0, Size);
            *(volatile uint32_t*)((uint8_t*)HostBuf + 0x00) = 0x10;      // VERSION: 1.0
            *(volatile uint64_t*)((uint8_t*)HostBuf + 0x08) = 0x200000000000000FULL; // CAP: coherent + ND=0xF (2^16 domains)
            *(volatile uint32_t*)((uint8_t*)HostBuf + 0x10) = 0;         // ECMD: all off
            *(volatile uint32_t*)((uint8_t*)HostBuf + 0x14) = 0;         // GSTS: no translation enabled
            *(volatile uint64_t*)((uint8_t*)HostBuf + 0x20) = 0;         // RTADDR: root table not set
            uc_mem_map_ptr(UnicornEmu::PrimaryEngine, Va, Size, UC_PROT_ALL, HostBuf);
            UnicornMem::TrackExisting(Va, HostBuf, Size, "VTD_MMIO");
        }
        return (PVOID)Va;
    }

    if (PhysicalAddress == 0xfee00000)
        return 0;
    return (PVOID)(PhysicalAddress * 0x1000);
}
