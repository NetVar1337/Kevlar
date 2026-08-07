#pragma once
#include "include/common.h"

PMDL NTAPI h_IoAllocateMdl(IN PVOID VirtualAddress, IN ULONG Length, IN BOOLEAN SecondaryBuffer, IN BOOLEAN ChargeQuota, IN _IRP* Irp);
void h_IoFreeMdl(PMDL Mdl);
void h_MmProbeAndLockPages(PMDL Mdl, uint32_t AccessMode, uint32_t Operation);
void h_MmUnlockPages(PMDL Mdl);
void h_MmBuildMdlForNonPagedPool(PMDL Mdl);
PVOID h_MmMapLockedPagesSpecifyCache(PMDL Mdl, uint32_t AccessMode, uint32_t CacheType, PVOID RequestedAddress, ULONG BugCheckOnFailure, uint32_t Priority);
void h_MmUnmapLockedPages(PVOID BaseAddress, PMDL Mdl);
PVOID h_MmGetSystemAddressForMdlSafe(PMDL Mdl, ULONG Priority);
PMDL h_MmAllocatePagesForMdl(uint64_t LowAddress, uint64_t HighAddress, uint64_t SkipBytes, SIZE_T TotalBytes);
PMDL h_MmAllocatePagesForMdlEx(uint64_t LowAddress, uint64_t HighAddress, uint64_t SkipBytes, SIZE_T TotalBytes, uint32_t CacheType, ULONG Flags);
void h_MmFreePagesFromMdl(PMDL Mdl);
