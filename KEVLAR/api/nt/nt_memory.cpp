#include "nt_memory.h"
#include <set>

static std::mutex SectionHandleMutex;
static std::set<uint64_t> SectionHandleSet;
static uint64_t SectionHandleCounter = 0xBEEF0001;

static std::mutex PhysMapMutex;
static std::set<uint64_t> PhysicalMappedAddresses;

HANDLE SectionHandleManager::AllocateHandle() {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    uint64_t Handle = SectionHandleCounter++;
    SectionHandleSet.insert(Handle);
    return (HANDLE)Handle;
}

bool SectionHandleManager::IsSectionHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    return SectionHandleSet.count((uint64_t)Handle) != 0;
}

void SectionHandleManager::FreeHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(SectionHandleMutex);
    SectionHandleSet.erase((uint64_t)Handle);
}

NTSTATUS h_ZwMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    uint64_t ZeroBits, uint64_t CommitSize, PLARGE_INTEGER SectionOffset,
    uint64_t* ViewSize, uint32_t InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
    auto HostBaseAddress = UcPtr(BaseAddress);
    auto HostViewSize = UcPtr(ViewSize);

    if (SectionHandleManager::IsSectionHandle(SectionHandle)) {
        uint64_t MapSize = 0x1000;
        if (HostViewSize && *HostViewSize > 0)
            MapSize = *HostViewSize;
        if (MapSize > 0x100000)
            MapSize = 0x100000;

        auto Uc = UnicornThread::GetCurrentEngine();
        if (!Uc)
            Uc = UnicornEmu::PrimaryEngine;
        uint64_t UcAddr = UnicornMem::AllocatePoolWithTag(Uc, MapSize, 'PmVw');
        auto HostPtr = UnicornMem::UcToHost(UcAddr);
        if (HostPtr)
            memset(HostPtr, 0, MapSize);

        if (HostBaseAddress)
            *HostBaseAddress = (PVOID)UcAddr;
        if (HostViewSize)
            *HostViewSize = MapSize;

        {
            std::lock_guard<std::mutex> Lock(PhysMapMutex);
            PhysicalMappedAddresses.insert(UcAddr);
        }

        LARGE_INTEGER Offset = {};
        if (SectionOffset) {
            auto HostOffset = UcPtr(SectionOffset);
            Offset = *HostOffset;
        }
        Logger::Log("{BLU}\tZwMapViewOfSection: PhysMem offset=%llx size=%llx -> UC %llx{RESET}\n",
            Offset.QuadPart, MapSize, UcAddr);
        return STATUS_SUCCESS;
    }

    Logger::Log("{BLU}\tZwMapViewOfSection: section=%p passthrough{RESET}\n", SectionHandle);
    return __NtRoutine("NtMapViewOfSection",
        SectionHandle, ProcessHandle, HostBaseAddress,
        ZeroBits, CommitSize, UcPtr(SectionOffset),
        HostViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS h_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    {
        std::lock_guard<std::mutex> Lock(PhysMapMutex);
        if (PhysicalMappedAddresses.count((uint64_t)BaseAddress)) {
            PhysicalMappedAddresses.erase((uint64_t)BaseAddress);
            auto Uc = UnicornThread::GetCurrentEngine();
            if (!Uc)
                Uc = UnicornEmu::PrimaryEngine;
            UnicornMem::FreePool(Uc, (uint64_t)BaseAddress);
            Logger::Log("{BLU}\tZwUnmapViewOfSection: freed PhysMem view %llx{RESET}\n", BaseAddress);
            return STATUS_SUCCESS;
        }
    }

    Logger::Log("{BLU}\tZwUnmapViewOfSection: process=%p base=%p passthrough{RESET}\n", ProcessHandle, BaseAddress);
    return __NtRoutine("NtUnmapViewOfSection", ProcessHandle, BaseAddress);
}

NTSTATUS h_ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    Logger::Log("{BLU}\tZwProtectVirtualMemory: handle=%p protect=%08x{RESET}\n", ProcessHandle, NewProtect);
    return __NtRoutine("NtProtectVirtualMemory",
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS h_ZwLockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType)
{
    Logger::Log("{BLU}\tZwLockVirtualMemory: handle=%p{RESET}\n", ProcessHandle);
    return 0;
}

NTSTATUS h_ZwUnlockVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG MapType)
{
    Logger::Log("{BLU}\tZwUnlockVirtualMemory: handle=%p{RESET}\n", ProcessHandle);
    return 0;
}

NTSTATUS h_ZwFlushInstructionCache(
    HANDLE ProcessHandle, void* BaseAddress, uint64_t Length)
{
    Logger::Log("{BLU}\tZwFlushInstructionCache: handle=%p base=%p{RESET}\n", ProcessHandle, BaseAddress);
    return 0;
}

NTSTATUS h_ZwAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t ZeroBits,
    uint64_t* RegionSize, ULONG AllocationType, ULONG Protect)
{
    Logger::Log("{BLU}\tZwAllocateVirtualMemory: handle=%p type=%08x protect=%08x{RESET}\n",
        ProcessHandle, AllocationType, Protect);
    return __NtRoutine("NtAllocateVirtualMemory",
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS h_ZwFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, uint64_t* RegionSize, ULONG FreeType)
{
    Logger::Log("{BLU}\tZwFreeVirtualMemory: handle=%p type=%08x{RESET}\n", ProcessHandle, FreeType);
    return __NtRoutine("NtFreeVirtualMemory",
        ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS h_ZwReadVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesRead)
{
    Logger::Log("{BLU}\tZwReadVirtualMemory: handle=%p base=%p size=%llu{RESET}\n",
        ProcessHandle, BaseAddress, BufferSize);
    return __NtRoutine("NtReadVirtualMemory",
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS h_ZwWriteVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
    uint64_t BufferSize, uint64_t* NumberOfBytesWritten)
{
    Logger::Log("{BLU}\tZwWriteVirtualMemory: handle=%p base=%p size=%llu{RESET}\n",
        ProcessHandle, BaseAddress, BufferSize);
    return __NtRoutine("NtWriteVirtualMemory",
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS h_ZwDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    Logger::Log("{CYN}\tZwDuplicateObject: src=%p dst=%p{RESET}\n", SourceHandle, TargetProcessHandle);
    return __NtRoutine("NtDuplicateObject",
        SourceProcessHandle, SourceHandle, TargetProcessHandle,
        TargetHandle, DesiredAccess, HandleAttributes, Options);
}
