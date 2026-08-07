#pragma once
#include "include/common.h"

typedef struct _MM_COPY_ADDRESS {
    union {
        PVOID            VirtualAddress;
        PVOID PhysicalAddress;
    };
} MM_COPY_ADDRESS, * PMMCOPY_ADDRESS;

BOOLEAN h_MmIsAddressValid(PVOID VirtualAddress);
NTSTATUS h_MmCopyMemory(PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress, SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);
PVOID h_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName);
NTSTATUS h_MmUnmapViewOfSection(void* Process, void* BaseAddress);
NTSTATUS h_MmCopyVirtualMemory(void* SourceProcess, void* SourceAddress, void* TargetProcess, void* TargetAddress, uint64_t BufferSize, uint8_t PreviousMode, uint64_t* ReturnSize);
void* h_MmGetSystemRoutineAddressFromExport(PUNICODE_STRING SystemRoutineName);
PVOID h_MmGetVirtualForPhysical(uint64_t PhysicalAddress);
PVOID h_MmAllocateContiguousNodeMemory(uint64_t NumberOfBytes, uint64_t LowestPA, uint64_t HighestPA, uint64_t BoundaryPA);
void h_MmFreeContiguousMemory(PVOID BaseAddress);
