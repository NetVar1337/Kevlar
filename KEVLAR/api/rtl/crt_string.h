#pragma once
#include "include/common.h"

EXCEPTION_DISPOSITION _c_exception(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord,
    _DISPATCHER_CONTEXT* DispatcherContext);

int h_vswprintf_s(wchar_t* Buffer, size_t NumberOfElements, const wchar_t* Format, va_list ArgPtr);
int h_swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...);
errno_t h_wcscpy_s(wchar_t* dest, rsize_t dest_size, const wchar_t* src);
errno_t h_wcscat_s(wchar_t* strDestination, size_t numberOfElements, const wchar_t* strSource);
int h__vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr);
int h__wcsnicmp(const wchar_t* Str1, const wchar_t* Str2, uint64_t Count);
int h__wcsicmp(const wchar_t* Str1, const wchar_t* Str2);
int h__stricmp(const char* Str1, const char* Str2);
int h__strnicmp(const char* Str1, const char* Str2, uint64_t Count);
void h_ProbeForRead(void* address, size_t len, ULONG align);
void h_ProbeForWrite(void* address, size_t len, ULONG align);
size_t h_wcslen(const wchar_t* Str);
size_t h_strlen(const char* Str);
wchar_t* h_wcsrchr(const wchar_t* Str, wchar_t Ch);
wchar_t* h_wcschr(const wchar_t* Str, wchar_t Ch);
char* h_strrchr(const char* Str, int Ch);
int h_wcscmp(const wchar_t* Str1, const wchar_t* Str2);
int h_strcmp(const char* Str1, const char* Str2);
int h_wcsncmp(const wchar_t* Str1, const wchar_t* Str2, size_t Count);
int h_strncmp(const char* Str1, const char* Str2, size_t Count);
wchar_t* h_wcsstr(const wchar_t* Str, const wchar_t* SubStr);
char* h_strstr(const char* Str, const char* SubStr);
int h_towupper(int C);
int h_towlower(int C);
int h_toupper(int C);
int h_tolower(int C);
