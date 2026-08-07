#pragma once
#include "include/common.h"

void* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag);
void* hM_AllocPool(uint32_t pooltype, size_t size);
void h_DeAllocPoolTag(uintptr_t ptr, ULONG tag);
void h_DeAllocPool(uintptr_t ptr);
void* h_ExAllocatePool2(uint64_t Flags, size_t NumberOfBytes, ULONG Tag);
void* h_ExAllocatePool3(uint64_t Flags, size_t NumberOfBytes, ULONG Tag, PVOID ExtendedParameters, ULONG ExtendedParametersCount);
PVOID h_ExAllocatePoolZero(uint32_t PoolType, size_t NumberOfBytes);
