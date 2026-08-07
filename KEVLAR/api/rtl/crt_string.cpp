#include "crt_string.h"

EXCEPTION_DISPOSITION _c_exception(_EXCEPTION_RECORD* ExceptionRecord, void* EstablisherFrame, _CONTEXT* ContextRecord,
    _DISPATCHER_CONTEXT* DispatcherContext) {
    return (EXCEPTION_DISPOSITION)__NtRoutine("__C_specific_handler", ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

static wchar_t EmptyWStr[] = L"(null)";
static char EmptyAStr[] = "(null)";

static int CountFmtArgs(const wchar_t* Fmt) {
    int Count = 0;
    for (const wchar_t* P = Fmt; *P; P++) {
        if (*P == L'%') {
            P++;
            if (!*P) break;
            if (*P == L'%') continue;
            while (*P && !iswalpha(*P) && *P != L'%') P++;
            if (*P && *P != L'%') Count++;
            if (!*P) break;
        }
    }
    return Count;
}

static void ConvertStringArgs(const wchar_t* Fmt, uint64_t* Args, int ArgCount) {
    int ArgIdx = 0;
    for (const wchar_t* P = Fmt; *P && ArgIdx < ArgCount; P++) {
        if (*P != L'%') continue;
        P++;
        if (!*P) break;
        if (*P == L'%') continue;
        while (*P && !iswalpha(*P) && *P != L'%') P++;
        if (!*P || *P == L'%') break;
        wchar_t Spec = *P;
        if (Spec == L's' || Spec == L'S') {
            uint64_t StrUc = Args[ArgIdx];
            if (StrUc) {
                void* HostStr = UnicornMem::UcToHost(StrUc);
                if (HostStr)
                    Args[ArgIdx] = (uint64_t)HostStr;
                else
                    Args[ArgIdx] = (Spec == L's') ? (uint64_t)EmptyWStr : (uint64_t)EmptyAStr;
            } else {
                Args[ArgIdx] = (Spec == L's') ? (uint64_t)EmptyWStr : (uint64_t)EmptyAStr;
            }
        }
        ArgIdx++;
    }
}

int h_vswprintf_s(wchar_t* Buffer, size_t NumberOfElements, const wchar_t* Format, va_list ArgPtr) {
    auto HostBuf = UcPtr(Buffer);
    auto HostFmt = UcPtr((wchar_t*)Format);

    if (!HostBuf || !HostFmt) {
        Logger::Log("{RED}\tvswprintf_s: null buf=%p fmt=%p{RESET}\n", HostBuf, HostFmt);
        return -1;
    }

    uint64_t UcArgPtr = (uint64_t)ArgPtr;
    auto HostArgBase = (uint64_t*)UnicornMem::UcToHost(UcArgPtr);

    int FmtArgCount = CountFmtArgs(HostFmt);

    uint64_t ConvertedArgs[16] = { 0 };
    if (HostArgBase) {
        for (int I = 0; I < FmtArgCount && I < 16; I++)
            ConvertedArgs[I] = HostArgBase[I];
    }

    ConvertStringArgs(HostFmt, ConvertedArgs, FmtArgCount);

    Logger::Log("{GRY}\tvswprintf_s fmt: %ls (argc=%d){RESET}\n", HostFmt, FmtArgCount);

    __try {
        auto Ret = vswprintf_s(HostBuf, NumberOfElements, HostFmt, (va_list)ConvertedArgs);
        Logger::Log("{GRY}\tResult : %ls{RESET}\n", HostBuf);
        return Ret;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}\tvswprintf_s CRASHED formatting '%ls'{RESET}\n", HostFmt);
        HostBuf[0] = 0;
        return -1;
    }
}

int h_swprintf_s(wchar_t* Buffer, size_t SizeOfBuffer, const wchar_t* Format, ...) {
    auto HostBuf = UcPtr(Buffer);
    auto HostFmt = UcPtr((wchar_t*)Format);

    if (!HostBuf || !HostFmt) {
        Logger::Log("{RED}\tswprintf_s: null buf=%p fmt=%p{RESET}\n", HostBuf, HostFmt);
        return -1;
    }

    va_list Ap;
    va_start(Ap, Format);

    int FmtArgCount = CountFmtArgs(HostFmt);

    uint64_t ConvertedArgs[16] = { 0 };
    for (int I = 0; I < FmtArgCount && I < 16; I++)
        ConvertedArgs[I] = va_arg(Ap, uint64_t);
    va_end(Ap);

    ConvertStringArgs(HostFmt, ConvertedArgs, FmtArgCount);

    Logger::Log("{GRY}\tswprintf_s fmt: %ls (argc=%d){RESET}\n", HostFmt, FmtArgCount);

    __try {
        auto Ret = vswprintf_s(HostBuf, SizeOfBuffer, HostFmt, (va_list)ConvertedArgs);
        Logger::Log("{GRY}\tResult : %ls{RESET}\n", HostBuf);
        return Ret;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}\tswprintf_s CRASHED formatting '%ls'{RESET}\n", HostFmt);
        HostBuf[0] = 0;
        return -1;
    }
}

errno_t h_wcscpy_s(wchar_t* dest, rsize_t dest_size, const wchar_t* src) { return wcscpy_s(UcPtr(dest), dest_size, UcPtr((wchar_t*)src)); }

errno_t h_wcscat_s(wchar_t* strDestination, size_t numberOfElements, const wchar_t* strSource) {
    auto HostDest = UcPtr(strDestination);
    auto HostSrc = UcPtr((wchar_t*)strSource);
    return wcscat_s(HostDest, numberOfElements, HostSrc);
}

void h_ProbeForRead(void* address, size_t len, ULONG align) { Logger::Log("{CYN}\tProbeForRead -> {%llx}(len: %d) align: %d{RESET}\n", address, len, align); }
void h_ProbeForWrite(void* address, size_t len, ULONG align) { Logger::Log("{CYN}\tProbeForWrite -> {%llx}(len: %d) align: %d{RESET}\n", address, len, align); }

int h__vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr) {
    auto HostBuf = UcPtr(buffer);
    auto HostFmt = UcPtr((wchar_t*)format);

    if (!HostBuf || !HostFmt) {
        Logger::Log("{RED}\t_vsnwprintf: null buf=%p fmt=%p{RESET}\n", HostBuf, HostFmt);
        return -1;
    }

    uint64_t UcArgPtr = (uint64_t)argptr;
    auto HostArgBase = (uint64_t*)UnicornMem::UcToHost(UcArgPtr);

    int FmtArgCount = CountFmtArgs(HostFmt);

    uint64_t ConvertedArgs[16] = { 0 };
    if (HostArgBase) {
        for (int I = 0; I < FmtArgCount && I < 16; I++)
            ConvertedArgs[I] = HostArgBase[I];
    }

    ConvertStringArgs(HostFmt, ConvertedArgs, FmtArgCount);

    Logger::Log("{GRY}\t_vsnwprintf fmt: %ls (argc=%d){RESET}\n", HostFmt, FmtArgCount);

    __try {
        auto Ret = _vsnwprintf(HostBuf, count, HostFmt, (va_list)ConvertedArgs);
        if (HostBuf && count > 0)
            Logger::Log("{GRY}\tResult : %ls{RESET}\n", HostBuf);
        return Ret;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}\t_vsnwprintf CRASHED formatting '%ls'{RESET}\n", HostFmt);
        if (HostBuf && count > 0) HostBuf[0] = 0;
        return -1;
    }
}

int h__wcsnicmp(const wchar_t* Str1, const wchar_t* Str2, uint64_t Count) {
    auto Host1 = UcPtr((wchar_t*)Str1);
    auto Host2 = UcPtr((wchar_t*)Str2);
    return _wcsnicmp(Host1, Host2, (size_t)Count);
}

int h__wcsicmp(const wchar_t* Str1, const wchar_t* Str2) {
    auto Host1 = UcPtr((wchar_t*)Str1);
    auto Host2 = UcPtr((wchar_t*)Str2);
    return _wcsicmp(Host1, Host2);
}

int h__stricmp(const char* Str1, const char* Str2) {
    auto Host1 = UcPtr((char*)Str1);
    auto Host2 = UcPtr((char*)Str2);
    return _stricmp(Host1, Host2);
}

int h__strnicmp(const char* Str1, const char* Str2, uint64_t Count) {
    auto Host1 = UcPtr((char*)Str1);
    auto Host2 = UcPtr((char*)Str2);
    return _strnicmp(Host1, Host2, (size_t)Count);
}

size_t h_wcslen(const wchar_t* Str) {
    auto Host = UcPtr((wchar_t*)Str);
    if (!Host) return 0;
    return wcslen(Host);
}

size_t h_strlen(const char* Str) {
    auto Host = UcPtr((char*)Str);
    if (!Host) return 0;
    return strlen(Host);
}

wchar_t* h_wcsrchr(const wchar_t* Str, wchar_t Ch) {
    auto Host = UcPtr((wchar_t*)Str);
    if (!Host) return nullptr;
    auto Ret = wcsrchr(Host, Ch);
    if (!Ret) return nullptr;
    uint64_t Offset = (uint64_t)Ret - (uint64_t)Host;
    return (wchar_t*)((uint64_t)Str + Offset);
}

wchar_t* h_wcschr(const wchar_t* Str, wchar_t Ch) {
    auto Host = UcPtr((wchar_t*)Str);
    if (!Host) return nullptr;
    auto Ret = wcschr(Host, Ch);
    if (!Ret) return nullptr;
    uint64_t Offset = (uint64_t)Ret - (uint64_t)Host;
    return (wchar_t*)((uint64_t)Str + Offset);
}

char* h_strrchr(const char* Str, int Ch) {
    auto Host = UcPtr((char*)Str);
    if (!Host) return nullptr;
    auto Ret = strrchr(Host, Ch);
    if (!Ret) return nullptr;
    uint64_t Offset = (uint64_t)Ret - (uint64_t)Host;
    return (char*)((uint64_t)Str + Offset);
}

int h_wcscmp(const wchar_t* Str1, const wchar_t* Str2) {
    auto Host1 = UcPtr((wchar_t*)Str1);
    auto Host2 = UcPtr((wchar_t*)Str2);
    return wcscmp(Host1, Host2);
}

int h_strcmp(const char* Str1, const char* Str2) {
    auto Host1 = UcPtr((char*)Str1);
    auto Host2 = UcPtr((char*)Str2);
    return strcmp(Host1, Host2);
}

int h_wcsncmp(const wchar_t* Str1, const wchar_t* Str2, size_t Count) {
    auto Host1 = UcPtr((wchar_t*)Str1);
    auto Host2 = UcPtr((wchar_t*)Str2);
    return wcsncmp(Host1, Host2, Count);
}

int h_strncmp(const char* Str1, const char* Str2, size_t Count) {
    auto Host1 = UcPtr((char*)Str1);
    auto Host2 = UcPtr((char*)Str2);
    return strncmp(Host1, Host2, Count);
}

wchar_t* h_wcsstr(const wchar_t* Str, const wchar_t* SubStr) {
    auto Host1 = UcPtr((wchar_t*)Str);
    auto Host2 = UcPtr((wchar_t*)SubStr);
    if (!Host1 || !Host2) return nullptr;
    auto Ret = wcsstr(Host1, Host2);
    if (!Ret) return nullptr;
    uint64_t Offset = (uint64_t)Ret - (uint64_t)Host1;
    return (wchar_t*)((uint64_t)Str + Offset);
}

char* h_strstr(const char* Str, const char* SubStr) {
    auto Host1 = UcPtr((char*)Str);
    auto Host2 = UcPtr((char*)SubStr);
    if (!Host1 || !Host2) return nullptr;
    auto Ret = strstr(Host1, Host2);
    if (!Ret) return nullptr;
    uint64_t Offset = (uint64_t)Ret - (uint64_t)Host1;
    return (char*)((uint64_t)Str + Offset);
}

int h_towupper(int C) { return towupper(C); }
int h_towlower(int C) { return towlower(C); }
int h_toupper(int C) { return toupper(C); }
int h_tolower(int C) { return tolower(C); }
