#pragma once
#include "include/common.h"

NTSTATUS h_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS h_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS h_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS h_ZwFlushBuffersFile(HANDLE FileHandle, PVOID IoStatusBlock);
NTSTATUS h_ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
    PVOID IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS h_ZwSetInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS h_ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS h_ZwDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID  ApcRoutine,
     PVOID            ApcContext,
     PVOID IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
   ULONG            InputBufferLength,
    PVOID            OutputBuffer,
   ULONG            OutputBufferLength
);
NTSTATUS h_ZwClose(HANDLE Handle);
NTSTATUS h_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PVOID IoStatusBlock, PVOID FileInformation, ULONG Length, uint32_t FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
NTSTATUS h_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes);
