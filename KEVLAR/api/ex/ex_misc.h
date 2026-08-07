#pragma once
#include "include/common.h"

typedef struct _CALLBACK_OBJECT {
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
} CALLBACK_OBJECT;

NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks);
PVOID h_ExRegisterCallback(PVOID CallbackObject, PVOID CallbackFunction, PVOID CallbackContext);
void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime);
NTSTATUS h_ExGetFirmwareEnvironmentVariable(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes);
ULONG h_ExGetFirmwareType();
