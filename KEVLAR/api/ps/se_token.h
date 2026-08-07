#pragma once
#include "include/common.h"

extern TOKEN_PRIVILEGES kernelToken[31];

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation);
