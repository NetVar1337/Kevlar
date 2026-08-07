#include "se_token.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"

TOKEN_PRIVILEGES kernelToken[31] = { 0 };

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation) {
    auto HostTokenInfo = UcPtr(TokenInformation);
    Logger::Log("{CYN}\tToken : %llx - Class : %d{RESET}\n", (const void*)Token, (int)TokenInformationClass);

    if (TokenInformationClass == 0x19) {
        *HostTokenInfo = nullptr;
        return 0;
    } else if (TokenInformationClass == 0x3) {
        ULONG AllocSize = sizeof(TOKEN_PRIVILEGES) + 5 * sizeof(LUID_AND_ATTRIBUTES);
        uint64_t PrivBuf = UnicornMem::AllocateVariable(
            UnicornThread::GetCurrentEngine(), AllocSize, "TokenPrivileges");
        auto HostPriv = (TOKEN_PRIVILEGES*)UnicornMem::UcToHost(PrivBuf);
        memset(HostPriv, 0, AllocSize);
        HostPriv->PrivilegeCount = 5;
        HostPriv->Privileges[0] = { {20, 0}, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT };
        HostPriv->Privileges[1] = { {19, 0}, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT };
        HostPriv->Privileges[2] = { {14, 0}, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT };
        HostPriv->Privileges[3] = { {23, 0}, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT };
        HostPriv->Privileges[4] = { {16, 0}, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT };
        *HostTokenInfo = (PVOID)PrivBuf;
        return 0;
    } else if (TokenInformationClass == 0x1) {
        uint64_t UserBuf = UnicornMem::AllocateVariable(
            UnicornThread::GetCurrentEngine(), 64, "TokenUser");
        auto HostUser = (uint8_t*)UnicornMem::UcToHost(UserBuf);
        memset(HostUser, 0, 64);
        *HostTokenInfo = (PVOID)UserBuf;
        return 0;
    } else if (TokenInformationClass == 0x11) {
        uint64_t IntBuf = UnicornMem::AllocateVariable(
            UnicornThread::GetCurrentEngine(), sizeof(DWORD), "TokenIntegrityLevel");
        auto HostInt = (DWORD*)UnicornMem::UcToHost(IntBuf);
        *HostInt = 0x4000;
        *HostTokenInfo = (PVOID)IntBuf;
        return 0;
    }

    *HostTokenInfo = nullptr;
    return 0;
}
