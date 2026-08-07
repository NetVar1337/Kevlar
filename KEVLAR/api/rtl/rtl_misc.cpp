#include "include/common.h"
#include "rtl_misc.h"

uint64_t h_RtlRandomEx(unsigned long* seed) {
    auto HostSeed = UcPtr(seed);
    Logger::Log("  {GRY}Seed: {WHT}%llx{RESET}\n", *HostSeed);
    auto ret = __NtRoutine("RtlRandomEx", HostSeed);
    *HostSeed = ret;
    return ret;
}

NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation) {
    auto HostInfo = UcPtr(lpVersionInformation);
    auto ret = __NtRoutine("RtlGetVersion", HostInfo);
    Logger::Log("  {GRY}%d.%d.%d{RESET}\n", HostInfo->dwMajorVersion, HostInfo->dwMinorVersion, HostInfo->dwBuildNumber);
    return ret;
}

void h_RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields) {
    auto HostTime = UcPtr(Time);
    auto HostTf = UcPtr(TimeFields);
    LARGE_INTEGER LocalTime = *HostTime;
    TIME_FIELDS LocalTf = { 0 };
    typedef void(NTAPI* FnRtlTimeToTimeFields)(PLARGE_INTEGER, PTIME_FIELDS);
    static auto Fn = (FnRtlTimeToTimeFields)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlTimeToTimeFields");
    if (Fn)
        Fn(&LocalTime, &LocalTf);
    memcpy(HostTf, &LocalTf, sizeof(TIME_FIELDS));
}

BOOLEAN h_RtlTimeFieldsToTime(PTIME_FIELDS TimeFields, PLARGE_INTEGER Time) {
    auto HostTf = UcPtr(TimeFields);
    auto HostTime = UcPtr(Time);
    TIME_FIELDS LocalTf = *HostTf;
    LARGE_INTEGER LocalTime = { 0 };
    typedef BOOLEAN(NTAPI* FnRtlTimeFieldsToTime)(PTIME_FIELDS, PLARGE_INTEGER);
    static auto Fn = (FnRtlTimeFieldsToTime)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlTimeFieldsToTime");
    BOOLEAN Result = FALSE;
    if (Fn)
        Result = Fn(&LocalTf, &LocalTime);
    if (Result)
        *HostTime = LocalTime;
    Logger::Log("{GRY}\tRtlTimeFieldsToTime: %04d-%02d-%02d %02d:%02d:%02d -> %s{RESET}\n",
        LocalTf.Year, LocalTf.Month, LocalTf.Day, LocalTf.Hour, LocalTf.Minute, LocalTf.Second,
        Result ? "OK" : "FAIL");
    return Result;
}

PIMAGE_NT_HEADERS h_RtlImageNtHeader(PVOID ImageBase) {
    auto HostBase = (uint8_t*)UnicornMem::UcToHost((uint64_t)ImageBase);
    if (!HostBase) return nullptr;
    auto Dos = (PIMAGE_DOS_HEADER)HostBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
    return (PIMAGE_NT_HEADERS)((uint64_t)ImageBase + Dos->e_lfanew);
}

PRUNTIME_FUNCTION h_RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, PVOID HistoryTable) {
    auto HostImageBase = UcPtr(ImageBase);
    if (ControlPc >= DRIVER_BASE_UC && ControlPc < DRIVER_BASE_UC + 0x10000000ULL) {
        *HostImageBase = DRIVER_BASE_UC;
        auto HostDriverBase = (uint8_t*)UnicornMem::UcToHost(DRIVER_BASE_UC);
        if (HostDriverBase) {
            auto DosHdr = (PIMAGE_DOS_HEADER)HostDriverBase;
            auto NtHdr = (PIMAGE_NT_HEADERS)(HostDriverBase + DosHdr->e_lfanew);
            auto ExcDir = &NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (ExcDir->VirtualAddress && ExcDir->Size) {
                auto FuncTable = (PRUNTIME_FUNCTION)(HostDriverBase + ExcDir->VirtualAddress);
                DWORD Count = ExcDir->Size / sizeof(RUNTIME_FUNCTION);
                uint32_t Rva = (uint32_t)(ControlPc - DRIVER_BASE_UC);
                for (DWORD I = 0; I < Count; I++) {
                    if (Rva >= FuncTable[I].BeginAddress && Rva < FuncTable[I].EndAddress) {
                        return (PRUNTIME_FUNCTION)(DRIVER_BASE_UC + ExcDir->VirtualAddress + I * sizeof(RUNTIME_FUNCTION));
                    }
                }
            }
        }
    }
    Logger::Log("{RED}\tRtlLookupFunctionEntry: 0x%llx not found{RESET}\n", ControlPc);
    return nullptr;
}

PVOID h_RtlVirtualUnwind(DWORD HandlerType, uint64_t ImageBase, uint64_t ControlPc, PRUNTIME_FUNCTION FunctionEntry,
    PCONTEXT ContextRecord, PVOID* HandlerData, uint64_t* EstablisherFrame, PVOID ContextPointers) {
    Logger::Log("{CYN}\tRtlVirtualUnwind: ImageBase=0x%llx ControlPc=0x%llx{RESET}\n", ImageBase, ControlPc);
    auto HostCtx = UcPtr(ContextRecord);
    auto HostEstFrame = UcPtr(EstablisherFrame);
    if (HostEstFrame)
        *HostEstFrame = HostCtx->Rsp;
    HostCtx->Rip = *(uint64_t*)(UnicornMem::UcToHost(HostCtx->Rsp) ? UnicornMem::UcToHost(HostCtx->Rsp) : (void*)&HostCtx->Rsp);
    HostCtx->Rsp += 8;
    if (HandlerData) {
        auto HostHd = UcPtr(HandlerData);
        *HostHd = nullptr;
    }
    return nullptr;
}

void h_RtlCaptureContext(PCONTEXT ContextRecord) {
    auto HostCtx = UcPtr(ContextRecord);
    memset(HostCtx, 0, sizeof(CONTEXT));
    HostCtx->ContextFlags = CONTEXT_FULL;
}

NTSTATUS h_RtlGUIDFromString(PUNICODE_STRING GuidString, GUID* Guid) {
    auto HostStr = UcPtr(GuidString);
    UNICODE_STRING LocalStr = *HostStr;
    LocalStr.Buffer = UcPtr(LocalStr.Buffer);
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe(Guid, LocalGuid);
    if (!HostGuid) return STATUS_INVALID_PARAMETER;
    NTSTATUS Status = (NTSTATUS)__NtRoutine("RtlGUIDFromString", &LocalStr, HostGuid);
    if (HostGuid == &LocalGuid && Status >= 0) {
        uc_mem_write((uc_engine*)0x1, (uint64_t)Guid, &LocalGuid, sizeof(GUID));
    }
    return Status;
}

NTSTATUS h_RtlStringFromGUID(GUID* Guid, PUNICODE_STRING GuidString) {
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe(Guid, LocalGuid);
    auto HostStr = UcPtr(GuidString);
    if (!HostGuid) return STATUS_INVALID_PARAMETER;
    return (NTSTATUS)__NtRoutine("RtlStringFromGUID", HostGuid, HostStr);
}
