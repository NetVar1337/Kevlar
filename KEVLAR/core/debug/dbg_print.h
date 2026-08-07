#pragma once
#include "include/common.h"

NTSTATUS h_DbgPrintEx(
    ULONG ComponentId,
    ULONG Level,
    PCSTR Format,
    ...
);

NTSTATUS h_DbgPrint(
    PCSTR Format,
    ...
);