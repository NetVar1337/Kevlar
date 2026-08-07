#pragma once
#include "include/common.h"

NTSTATUS h_NtQuerySystemInformation(uint32_t SystemInformationClass, uintptr_t SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS h_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS h_NtQueryInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS h_ZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength);
NTSTATUS h_ZwQueryFullAttributesFile(OBJECT_ATTRIBUTES* ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation);
NTSTATUS h_ZwQueryVirtualMemory(
    HANDLE ProcessHandle, void* BaseAddress, uint32_t MemInfoClass,
    void* MemInfo, uint64_t MemInfoLength, uint64_t* ReturnLength);
