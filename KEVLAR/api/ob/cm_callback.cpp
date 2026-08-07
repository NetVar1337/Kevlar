#include "cm_callback.h"

NTSTATUS h_CmRegisterCallbackEx(PVOID Function, PUNICODE_STRING Altitude, PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved) {
    auto HostCookie = UcPtr(Cookie);
    if (HostCookie) HostCookie->QuadPart = 0xCAFEBABE;
    Logger::Log("{GRN}\tCmRegisterCallbackEx registered{RESET}\n");
    return STATUS_SUCCESS;
}

NTSTATUS h_CmUnRegisterCallback(LARGE_INTEGER Cookie) {
    return STATUS_SUCCESS;
}

NTSTATUS h_CmRegisterCallback(PVOID Function, PVOID Context, PLARGE_INTEGER Cookie) {
    auto HostCookie = UcPtr(Cookie);
    if (HostCookie) HostCookie->QuadPart = 0xCAFEBABE;
    return STATUS_SUCCESS;
}
