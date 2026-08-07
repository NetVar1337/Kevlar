#include "include/common.h"
#include "ex_misc.h"

CALLBACK_OBJECT test = { 0 };

NTSTATUS h_ExCreateCallback(void* CallbackObject, void* ObjectAttributes, bool Create, bool AllowMultipleCallbacks) {
    auto HostCo = UcPtr((_CALLBACK_OBJECT**)CallbackObject);
    auto HostOa = UcPtr((OBJECT_ATTRIBUTES*)ObjectAttributes);
    auto HostObjName = HostOa->ObjectName ? UcPtr(HostOa->ObjectName) : nullptr;
    auto HostBuf = HostObjName ? UcPtr(HostObjName->Buffer) : nullptr;
    Logger::Log("{CYN}\tCallback object : %llx{RESET}\n", CallbackObject);
    Logger::Log("{CYN}\tCallback name : %ls{RESET}\n", HostBuf ? HostBuf : L"(null)");
    *HostCo = (_CALLBACK_OBJECT*)0x10e4e9c820;
    return 0;
}

PVOID h_ExRegisterCallback(PVOID CallbackObject, PVOID CallbackFunction, PVOID CallbackContext) {
    return CallbackObject;
}

void h_ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime) {
    auto HostSys = UcPtr(SystemTime);
    auto HostLocal = UcPtr(LocalTime);
    TIME_ZONE_INFORMATION Tzi;
    GetTimeZoneInformation(&Tzi);
    int64_t BiasIn100Ns = (int64_t)Tzi.Bias * 60LL * 10000000LL;
    HostLocal->QuadPart = HostSys->QuadPart - BiasIn100Ns;
}

NTSTATUS h_ExGetFirmwareEnvironmentVariable(
    PUNICODE_STRING VariableName,
    LPGUID          VendorGuid,
    PVOID           Value,
    PULONG          ValueLength,
    PULONG          Attributes
) {
    auto HostVarName = UcPtr(VariableName);
    GUID LocalGuid = {};
    auto HostGuid = UcPtrSafe(VendorGuid, LocalGuid);
    auto HostValLen = UcPtr(ValueLength);
    UNICODE_STRING LocalVarName = *HostVarName;
    LocalVarName.Buffer = UcPtr(LocalVarName.Buffer);
    if (HostGuid)
        Logger::Log("{CYN}\tReading UEFI Var : %ls - GUID : %llx-%llx-%llx-%llx{RESET}\n", LocalVarName.Buffer, HostGuid->Data1, HostGuid->Data2, HostGuid->Data3, HostGuid->Data4);
    else
        Logger::Log("{CYN}\tReading UEFI Var : %ls - GUID : <untranslated>{RESET}\n", LocalVarName.Buffer);
    if (HostValLen && *HostValLen)
        Logger::Log("{GRY}\tRequested length : %llx{RESET}\n", *HostValLen);

    return STATUS_SUCCESS;
}

ULONG h_ExGetFirmwareType() {
    return 2;
}
