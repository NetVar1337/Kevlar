#include "include/common.h"
#include "mm_mdl.h"

#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(_Va, _Size) ((ULONG)((((ULONG_PTR)(_Va) & (PAGE_SIZE - 1)) + (_Size) + (PAGE_SIZE - 1)) >> PAGE_SHIFT))

typedef ULONG PFN_COUNT;
typedef ULONG PFN_NUMBER, *PPFN_NUMBER;
typedef LONG SPFN_NUMBER, *PSPFN_NUMBER;

#define MDL_ALLOCATED_FIXED_SIZE 0x0008
#define MDL_PAGES_LOCKED         0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_DESCRIBES_AWE        0x0400
#define MDL_ALLOCATED_MUST_SUCCEED 0x2000

#define BYTE_OFFSET(Va) ((ULONG)((ULONG_PTR)(Va) & (PAGE_SIZE - 1)))

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

static std::unordered_map<uint64_t, uint64_t> UsermodeMappings;
static std::mutex UsermodeMappingLock;

void MmInitializeMdl(PMDL MemoryDescriptorList, PVOID BaseVa, SIZE_T Length) {

    MemoryDescriptorList->Next = (PMDL)NULL;
    MemoryDescriptorList->Size = (USHORT)(sizeof(MDL) + (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseVa, Length)));
    MemoryDescriptorList->MdlFlags = 0;
    MemoryDescriptorList->StartVa = (PVOID)PAGE_ALIGN(BaseVa);
    MemoryDescriptorList->ByteOffset = BYTE_OFFSET(BaseVa);
    MemoryDescriptorList->ByteCount = (ULONG)Length;
}

PMDL NTAPI h_IoAllocateMdl(IN PVOID VirtualAddress, IN ULONG Length, IN BOOLEAN SecondaryBuffer, IN BOOLEAN ChargeQuota, IN _IRP* Irp) {
    PMDL Mdl = NULL, p;
    ULONG Flags = 0;
    ULONG Size;

    if (Length & 0x80000000)
        return NULL;
    Size = ADDRESS_AND_SIZE_TO_SPAN_PAGES(VirtualAddress, Length);
    if (Size > 23) {
        Size *= sizeof(PFN_NUMBER);
        Size += sizeof(MDL);
        if (Size > 0xFFFF)
            return NULL;
    } else {
        Size = (23 * sizeof(PFN_NUMBER)) + sizeof(MDL);
        Flags |= MDL_ALLOCATED_FIXED_SIZE;
    }

    if (!Mdl) {
        uint64_t UcMdl = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), Size, 'MdlT');
        if (!UcMdl)
            return NULL;
        Mdl = (PMDL)UcMdl;
    }

    auto HostMdl = (PMDL)UnicornMem::UcToHost((uint64_t)Mdl);
    if (HostMdl) {
        MmInitializeMdl(HostMdl, VirtualAddress, Length);
        HostMdl->MdlFlags |= Flags;
    }

    if (Irp) {
        auto HostIrp = UcPtr(Irp);
        if (SecondaryBuffer) {
            auto MdlAddr = HostIrp->MdlAddress;
            auto HostP = UcPtr(MdlAddr);
            while (HostP->Next) {
                MdlAddr = HostP->Next;
                HostP = UcPtr(MdlAddr);
            }
            HostP->Next = Mdl;
        } else {
            HostIrp->MdlAddress = Mdl;
        }
    }

    return Mdl;
}

void h_IoFreeMdl(PMDL Mdl) {
    UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), (uint64_t)Mdl);
}

void h_MmProbeAndLockPages(PMDL Mdl, uint32_t AccessMode, uint32_t Operation) {
    auto HostMdl = UcPtr(Mdl);
    HostMdl->MdlFlags |= MDL_PAGES_LOCKED;
}

void h_MmUnlockPages(PMDL Mdl) {
    auto HostMdl = UcPtr(Mdl);
    HostMdl->MdlFlags &= ~MDL_PAGES_LOCKED;
}

void h_MmBuildMdlForNonPagedPool(PMDL Mdl) {
    auto HostMdl = UcPtr(Mdl);
    HostMdl->MdlFlags |= MDL_SOURCE_IS_NONPAGED_POOL;
}

PVOID h_MmMapLockedPagesSpecifyCache(PMDL Mdl, uint32_t AccessMode, uint32_t CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, uint32_t Priority) {
    auto HostMdl = UcPtr(Mdl);

    if (AccessMode == 1) {
        uint64_t KernelVa = (uint64_t)HostMdl->StartVa + HostMdl->ByteOffset;
        uint64_t MapSize = HostMdl->ByteCount;

        void* HostBuf = UnicornMem::UcToHost(KernelVa);
        if (!HostBuf) {
            HostBuf = UnicornMem::UcToHost((uint64_t)HostMdl->StartVa);
        }

        if (!HostBuf) {
            Logger::Log("{RED}MmMapLockedPagesSpecifyCache: cannot resolve host ptr for StartVa=0x%llx{RESET}\n", (uint64_t)HostMdl->StartVa);
            return HostMdl->StartVa;
        }

        uint64_t UsermodeAddr = UnicornMem::AllocateUsermode(UnicornThread::GetCurrentEngine(), MapSize, HostBuf);
        if (!UsermodeAddr) {
            Logger::Log("{RED}MmMapLockedPagesSpecifyCache: usermode alloc failed{RESET}\n");
            return HostMdl->StartVa;
        }

        {
            std::lock_guard<std::mutex> Guard(UsermodeMappingLock);
            UsermodeMappings[(uint64_t)Mdl] = UsermodeAddr;
        }

        Logger::Log("{GRN}MmMapLockedPagesSpecifyCache: UserMode mapping kernel 0x%llx -> usermode 0x%llx (size=0x%x){RESET}\n",
            KernelVa, UsermodeAddr, HostMdl->ByteCount);

        HostMdl->MappedSystemVa = (PVOID)UsermodeAddr;
        return (PVOID)UsermodeAddr;
    }

    return HostMdl->StartVa;
}

void h_MmUnmapLockedPages(PVOID BaseAddress, PMDL Mdl) {
    uint64_t Addr = (uint64_t)BaseAddress;

    if (Addr < 0x7FFFFFFEFFFFULL && Addr >= USERMODE_MAPPING_BASE) {
        UnicornMem::FreeUsermode(UnicornThread::GetCurrentEngine(), Addr);

        {
            std::lock_guard<std::mutex> Guard(UsermodeMappingLock);
            UsermodeMappings.erase((uint64_t)Mdl);
        }

        Logger::Log("{GRN}MmUnmapLockedPages: unmapped usermode 0x%llx{RESET}\n", Addr);
    }
}

PVOID h_MmGetSystemAddressForMdlSafe(PMDL Mdl, ULONG Priority) {
    auto HostMdl = UcPtr(Mdl);
    if (HostMdl->MappedSystemVa)
        return HostMdl->MappedSystemVa;
    return HostMdl->StartVa;
}

PMDL h_MmAllocatePagesForMdl(uint64_t LowAddress, uint64_t HighAddress, uint64_t SkipBytes, SIZE_T TotalBytes) {
    return h_MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, TotalBytes, 0, 0);
}

PMDL h_MmAllocatePagesForMdlEx(uint64_t LowAddress, uint64_t HighAddress, uint64_t SkipBytes, SIZE_T TotalBytes, uint32_t CacheType, ULONG Flags) {
    Logger::Log("{BLU}MmAllocatePagesForMdlEx: Low=0x%llx High=0x%llx Skip=0x%llx Size=0x%llx Cache=%u Flags=0x%x{RESET}\n",
        LowAddress, HighAddress, SkipBytes, TotalBytes, CacheType, Flags);

    if (TotalBytes == 0)
        return NULL;

    uint64_t PagePoolAddr = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), TotalBytes, 'MdPg');
    if (!PagePoolAddr) {
        Logger::Log("{RED}MmAllocatePagesForMdlEx: page allocation failed{RESET}\n");
        return NULL;
    }

    ULONG PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES((PVOID)PagePoolAddr, TotalBytes);
    ULONG MdlSize = sizeof(MDL) + (PageCount * sizeof(PFN_NUMBER));

    uint64_t UcMdl = UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), MdlSize, 'MdlA');
    if (!UcMdl) {
        UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), PagePoolAddr);
        Logger::Log("{RED}MmAllocatePagesForMdlEx: MDL allocation failed{RESET}\n");
        return NULL;
    }

    auto HostMdl = (PMDL)UnicornMem::UcToHost(UcMdl);
    if (!HostMdl) {
        UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), PagePoolAddr);
        UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), UcMdl);
        return NULL;
    }

    MmInitializeMdl(HostMdl, (PVOID)PagePoolAddr, TotalBytes);
    HostMdl->MdlFlags |= MDL_PAGES_LOCKED;
    HostMdl->MappedSystemVa = (PVOID)PagePoolAddr;

    auto PfnArray = (PPFN_NUMBER)(HostMdl + 1);
    uint64_t BasePageAddr = (uint64_t)PAGE_ALIGN((PVOID)PagePoolAddr);
    for (ULONG I = 0; I < PageCount; I++) {
        PfnArray[I] = (PFN_NUMBER)((BasePageAddr + (I * PAGE_SIZE)) >> PAGE_SHIFT);
    }

    Logger::Log("{GRN}MmAllocatePagesForMdlEx: MDL=0x%llx StartVa=0x%llx ByteCount=0x%x Pages=%u{RESET}\n",
        UcMdl, (uint64_t)HostMdl->StartVa, HostMdl->ByteCount, PageCount);

    return (PMDL)UcMdl;
}

void h_MmFreePagesFromMdl(PMDL Mdl) {
    auto HostMdl = UcPtr(Mdl);
    if (!HostMdl) return;

    uint64_t PageAddr = (uint64_t)HostMdl->StartVa;
    Logger::Log("{BLU}MmFreePagesFromMdl: MDL=0x%llx StartVa=0x%llx ByteCount=0x%x{RESET}\n",
        (uint64_t)Mdl, PageAddr, HostMdl->ByteCount);

    if (PageAddr) {
        UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), PageAddr);
    }

    HostMdl->MdlFlags &= ~MDL_PAGES_LOCKED;
    HostMdl->StartVa = NULL;
    HostMdl->MappedSystemVa = NULL;
    HostMdl->ByteCount = 0;
}
