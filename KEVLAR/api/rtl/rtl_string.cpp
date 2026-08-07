#include "include/common.h"
#include "rtl_string.h"

NTSTATUS h_RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    auto HostDest = UcPtr(DestinationString);
    auto HostSrc = UcPtr((PWSTR)SourceString);
    auto ret = __NtRoutine("RtlInitUnicodeString", HostDest, HostSrc);
    return ret;
}

void h_RtlInitAnsiString(STRING* DestinationString, const char* SourceString) {
    auto HostDest = UcPtr(DestinationString);
    if (SourceString) {
        auto HostSrc = UcPtr((char*)SourceString);
        size_t Len = strlen(HostSrc);
        HostDest->Length = (USHORT)Len;
        HostDest->MaximumLength = (USHORT)(Len + 1);
        HostDest->Buffer = (char*)SourceString;
    } else {
        HostDest->Length = 0;
        HostDest->MaximumLength = 0;
        HostDest->Buffer = nullptr;
    }
}

void h_RtlFreeAnsiString(STRING* AnsiString) {
    auto HostStr = UcPtr(AnsiString);
    HostStr->Length = 0;
    HostStr->MaximumLength = 0;
    HostStr->Buffer = nullptr;
}

NTSTATUS h_RtlDuplicateUnicodeString(int Flags, const UNICODE_STRING* Source, UNICODE_STRING* Destination) {
    auto HostSrc = UcPtr((UNICODE_STRING*)Source);
    auto HostDst = UcPtr(Destination);

    if ((Flags & ~3) != 0 || !Destination)
        return (NTSTATUS)0xC000000D;

    bool AddNul = (Flags & 1) != 0;
    bool AllocEmpty = (Flags & 2) != 0;

    if (AllocEmpty && !AddNul)
        return (NTSTATUS)0xC000000D;

    USHORT Length = 0;
    wchar_t* SrcBufHost = nullptr;
    if (HostSrc) {
        Length = HostSrc->Length;
        if (HostSrc->Buffer)
            SrcBufHost = UcPtr(HostSrc->Buffer);
    }

    if (AddNul && Length == 0xFFFE)
        return (NTSTATUS)0xC0000106;

    USHORT MaxLen = AddNul ? (USHORT)(Length + 2) : Length;
    if (!AllocEmpty && !Length)
        MaxLen = 0;

    wchar_t* DstBufUc = nullptr;
    if (MaxLen) {
        uint64_t BufAddr = UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), MaxLen);
        if (!BufAddr)
            return (NTSTATUS)0xC0000017;
        DstBufUc = (wchar_t*)BufAddr;
        auto DstBufHost = (wchar_t*)UnicornMem::UcToHost(BufAddr);
        if (Length && SrcBufHost && DstBufHost)
            memcpy(DstBufHost, SrcBufHost, Length);
        if (AddNul && DstBufHost)
            DstBufHost[(unsigned)Length >> 1] = 0;
    }

    HostDst->MaximumLength = MaxLen;
    HostDst->Length = Length;
    HostDst->Buffer = DstBufUc;

    Logger::Log("{CYN}\tRtlDuplicateUnicodeString : %ls = 0{RESET}\n", SrcBufHost ? SrcBufHost : L"(null)");
    return STATUS_SUCCESS;
}

void h_RtlCopyUnicodeString(PUNICODE_STRING Dest, PUNICODE_STRING Src) {
    auto HostDest = UcPtr(Dest);
    auto HostSrc = UcPtr(Src);
    UNICODE_STRING LocalSrc = *HostSrc;
    LocalSrc.Buffer = UcPtr(LocalSrc.Buffer);
    auto HostDestBuf = UcPtr(HostDest->Buffer);
    USHORT CopyLen = LocalSrc.Length;
    if (CopyLen > HostDest->MaximumLength - sizeof(wchar_t))
        CopyLen = HostDest->MaximumLength - sizeof(wchar_t);
    if (HostDestBuf && LocalSrc.Buffer) {
        memcpy(HostDestBuf, LocalSrc.Buffer, CopyLen);
        HostDestBuf[CopyLen / sizeof(wchar_t)] = 0;
    }
    HostDest->Length = CopyLen;
}

BOOLEAN h_RtlEqualUnicodeString(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInsensitive) {
    auto HostStr1 = UcPtr(Str1);
    auto HostStr2 = UcPtr(Str2);
    UNICODE_STRING L1 = *HostStr1, L2 = *HostStr2;
    L1.Buffer = UcPtr(L1.Buffer);
    L2.Buffer = UcPtr(L2.Buffer);
    return (BOOLEAN)__NtRoutine("RtlEqualUnicodeString", &L1, &L2, CaseInsensitive);
}

LONG h_RtlCompareUnicodeString(PUNICODE_STRING Str1, PUNICODE_STRING Str2, BOOLEAN CaseInsensitive) {
    auto HostStr1 = UcPtr(Str1);
    auto HostStr2 = UcPtr(Str2);
    UNICODE_STRING L1 = *HostStr1, L2 = *HostStr2;
    L1.Buffer = UcPtr(L1.Buffer);
    L2.Buffer = UcPtr(L2.Buffer);
    return (LONG)__NtRoutine("RtlCompareUnicodeString", &L1, &L2, CaseInsensitive);
}

void h_RtlFreeUnicodeString(PUNICODE_STRING UnicodeString) {
    auto HostStr = UcPtr(UnicodeString);
    HostStr->Buffer = nullptr;
    HostStr->Length = 0;
    HostStr->MaximumLength = 0;
}

LONG h_RtlCompareString(const STRING* String1, const STRING* String2, BOOLEAN CaseInSensitive) {
    auto HostStr1 = UcPtr((STRING*)String1);
    auto HostStr2 = UcPtr((STRING*)String2);
    STRING LocalStr1 = *HostStr1;
    STRING LocalStr2 = *HostStr2;
    LocalStr1.Buffer = UcPtr(LocalStr1.Buffer);
    LocalStr2.Buffer = UcPtr(LocalStr2.Buffer);
    Logger::Log("{CYN}\tComparing %s to %s{RESET}\n", LocalStr1.Buffer, LocalStr2.Buffer);
    auto ret = __NtRoutine("RtlCompareString", &LocalStr1, &LocalStr2, CaseInSensitive);
    return ret;
}

NTSTATUS h_RtlAnsiStringToUnicodeString(PUNICODE_STRING Dest, STRING* Src, BOOLEAN AllocDest) {
    auto HostDest = UcPtr(Dest);
    auto HostSrc = UcPtr(Src);
    STRING LocalSrc = *HostSrc;
    LocalSrc.Buffer = UcPtr(LocalSrc.Buffer);
    if (AllocDest) {
        USHORT DestLen = (LocalSrc.Length + 1) * sizeof(wchar_t);
        uint64_t BufUc = UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), DestLen);
        auto BufHost = (wchar_t*)UnicornMem::UcToHost(BufUc);
        if (BufHost) {
            int Len = MultiByteToWideChar(CP_ACP, 0, LocalSrc.Buffer, LocalSrc.Length, BufHost, LocalSrc.Length + 1);
            BufHost[Len] = 0;
            HostDest->Buffer = (wchar_t*)BufUc;
            HostDest->Length = (USHORT)(Len * sizeof(wchar_t));
            HostDest->MaximumLength = DestLen;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS h_RtlUnicodeStringToAnsiString(STRING* Dest, PUNICODE_STRING Src, BOOLEAN AllocDest) {
    auto HostDest = UcPtr(Dest);
    auto HostSrc = UcPtr(Src);
    UNICODE_STRING LocalSrc = *HostSrc;
    LocalSrc.Buffer = UcPtr(LocalSrc.Buffer);
    if (AllocDest) {
        USHORT DestLen = LocalSrc.Length / sizeof(wchar_t) + 1;
        uint64_t BufUc = UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), DestLen);
        auto BufHost = (char*)UnicornMem::UcToHost(BufUc);
        if (BufHost) {
            int Len = WideCharToMultiByte(CP_ACP, 0, LocalSrc.Buffer, LocalSrc.Length / sizeof(wchar_t), BufHost, DestLen, nullptr, nullptr);
            BufHost[Len] = 0;
            HostDest->Buffer = (char*)BufUc;
            HostDest->Length = (USHORT)Len;
            HostDest->MaximumLength = DestLen;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS h_RtlMultiByteToUnicodeN(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, const CHAR* MultiByteString,
    ULONG BytesInMultiByteString) {
    auto HostUni = UcPtr(UnicodeString);
    auto HostBytesOut = UcPtr(BytesInUnicodeString);
    auto HostMb = UcPtr((CHAR*)MultiByteString);
    Logger::Log("  {GRY}Converting: {WHT}%s{RESET}\n", HostMb);
    return __NtRoutine("RtlMultiByteToUnicodeN", HostUni, MaxBytesInUnicodeString, HostBytesOut, HostMb, BytesInMultiByteString);
}
