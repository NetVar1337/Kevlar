#pragma once
#include "include/common.h"

NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
void h_RtlInitAnsiString(STRING* DestinationString, const char* SourceString);
void h_RtlFreeAnsiString(STRING* AnsiString);
NTSTATUS h_RtlDuplicateUnicodeString(int add_nul, const UNICODE_STRING* source, UNICODE_STRING* destination);
void h_RtlCopyUnicodeString(PUNICODE_STRING Dest, PUNICODE_STRING Src);
BOOLEAN h_RtlEqualUnicodeString(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInsensitive);
LONG h_RtlCompareUnicodeString(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInsensitive);
void h_RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
LONG h_RtlCompareString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive);
NTSTATUS h_RtlAnsiStringToUnicodeString(PUNICODE_STRING Dest, STRING* Src, BOOLEAN AllocDest);
NTSTATUS h_RtlUnicodeStringToAnsiString(STRING* Dest, PUNICODE_STRING Src, BOOLEAN AllocDest);
NTSTATUS h_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, const CHAR* MultiByteString, ULONG BytesInMultiByteString);
