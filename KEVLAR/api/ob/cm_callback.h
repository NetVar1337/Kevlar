#pragma once
#include "include/common.h"

NTSTATUS h_CmRegisterCallbackEx(PVOID Function, PUNICODE_STRING Altitude, PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved);
NTSTATUS h_CmUnRegisterCallback(LARGE_INTEGER Cookie);
NTSTATUS h_CmRegisterCallback(PVOID Function, PVOID Context, PLARGE_INTEGER Cookie);
