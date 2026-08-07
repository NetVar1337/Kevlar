#pragma once
#include "include/common.h"

namespace SectionHandleManager {
    HANDLE AllocateHandle();
    bool IsSectionHandle(HANDLE Handle);
    void FreeHandle(HANDLE Handle);
}

NTSTATUS h_ZwMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    uint64_t ZeroBits, uint64_t CommitSize, PLARGE_INTEGER SectionOffset,
    uint64_t* ViewSize, uint32_t InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
NTSTATUS h_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS h_ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize,
    ULONG NewProtect, PULONG OldProtect);
NTSTATUS h_ZwLockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType);
NTSTATUS h_ZwUnlockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType);
NTSTATUS h_ZwFlushInstructionCache(
    HANDLE ProcessHandle, void* BaseAddress, uint64_t Length);
NTSTATUS h_ZwAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t ZeroBits,
    uint64_t* RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS h_ZwFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG FreeType);
NTSTATUS h_ZwReadVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesRead);
NTSTATUS h_ZwWriteVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesWritten);
NTSTATUS h_ZwDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
