#include "include/common.h"
#include "dbg_print.h"
#include <cstdio>

NTSTATUS h_DbgPrintEx(
    ULONG ComponentId,
    ULONG Level,
    PCSTR Format,
    ...
) {
    if (!Format) {
        Logger::Log("{GRY}[DbgPrintEx] Component=%u Level=%u: (null){RESET}\n", ComponentId, Level);
        return STATUS_SUCCESS;
    }
    char Buf[512];
    uc_engine* Uc = UnicornThread::GetCurrentEngine();
    if (uc_mem_read(Uc, (uint64_t)Format, Buf, sizeof(Buf) - 1) != UC_ERR_OK) {
        Logger::Log("{GRY}[DbgPrintEx] Component=%u Level=%u: (unreadable 0x%llx){RESET}\n", ComponentId, Level, (uint64_t)Format);
        return STATUS_SUCCESS;
    }
    Buf[sizeof(Buf) - 1] = '\0';
    Logger::Log("{GRY}[DbgPrintEx] Component=%u Level=%u: %s{RESET}\n", ComponentId, Level, Buf);
    return STATUS_SUCCESS;
}

NTSTATUS h_DbgPrint(
    PCSTR Format,
    ...
) {
    if (!Format) {
        Logger::Log("{GRY}[DbgPrint] (null){RESET}\n");
        return STATUS_SUCCESS;
    }
    char Buf[512];
    uc_engine* Uc = UnicornThread::GetCurrentEngine();
    if (uc_mem_read(Uc, (uint64_t)Format, Buf, sizeof(Buf) - 1) != UC_ERR_OK) {
        Logger::Log("{GRY}[DbgPrint] (unreadable 0x%llx){RESET}\n", (uint64_t)Format);
        return STATUS_SUCCESS;
    }
    Buf[sizeof(Buf) - 1] = '\0';
    Logger::Log("{GRY}[DbgPrint] %s{RESET}\n", Buf);
    return STATUS_SUCCESS;
}