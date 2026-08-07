#pragma once
#include "include/common.h"

NTSTATUS h_RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength);
NTSTATUS h_RtlDeleteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName);
NTSTATUS h_RtlQueryRegistryValues(ULONG RelativeTo, PCWSTR Path, PVOID QueryTable, PVOID Context, PVOID Environment);
