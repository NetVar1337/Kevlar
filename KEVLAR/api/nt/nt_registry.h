#pragma once
#include "include/common.h"

NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS h_ZwFlushKey(PHANDLE KeyHandle);
NTSTATUS h_ZwSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS h_ZwDeleteKey(HANDLE KeyHandle);
NTSTATUS h_ZwEnumerateKey(HANDLE KeyHandle, ULONG Index, uint32_t KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS h_ZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, uint32_t KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS h_ZwDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
NTSTATUS h_ZwCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
    ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS h_ZwOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, ULONG OpenOptions);
NTSTATUS h_ZwQueryKey(HANDLE KeyHandle, uint32_t KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
