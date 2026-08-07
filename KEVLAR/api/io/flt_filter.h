#pragma once
#include "include/common.h"

NTSTATUS h_FltRegisterFilter(PVOID Driver, PVOID Registration, PVOID* RetFilter);
NTSTATUS h_FltStartFiltering(PVOID Filter);
NTSTATUS h_FltUnregisterFilter(PVOID Filter);
void h_FltObjectDereference(PVOID Object);
NTSTATUS h_FltGetFilterInformation(PVOID Filter, uint32_t InfoClass, PVOID Buffer, ULONG BufSize, PULONG BytesReturned);
PVOID h_FltGetRoutineAddress(const char* FltRoutineName);
void h_FltSetCallbackDataDirty(PVOID Data);
NTSTATUS h_FltGetDiskDeviceObject(PVOID Volume, PVOID* DiskDevice);
NTSTATUS h_FltGetVolumeFromInstance(PVOID Instance, PVOID* Volume);
NTSTATUS h_FltAllocateCallbackData(PVOID Instance, PVOID FileObject, PVOID* RetNewCbdData);
void h_FltFreeCallbackData(PVOID CbdData);
NTSTATUS h_FltPerformSynchronousIo(PVOID CbdData);
NTSTATUS h_FltCancellableWaitForSingleObject(PVOID Object, PLARGE_INTEGER Timeout, PVOID CbdData);
NTSTATUS h_FltCancellableWaitForMultipleObjects(ULONG Count, PVOID* ObjectArray, uint32_t WaitType, PLARGE_INTEGER Timeout, PVOID WaitBlockArray, PVOID CbdData);
NTSTATUS h_FltClose(PVOID* FileObject);
NTSTATUS h_FltCreateFile(PVOID Filter, PVOID Instance, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjAttr, PVOID IoStatusBlock, PLARGE_INTEGER AllocSize, ULONG FileAttrs, ULONG ShareAccess, ULONG CreateDisp, ULONG CreateOpts, PVOID EaBuffer, ULONG EaLength, ULONG Flags);
NTSTATUS h_FltGetVolumeProperties(PVOID Volume, PVOID VolumeProperties, ULONG Length, PULONG LengthReturned);
