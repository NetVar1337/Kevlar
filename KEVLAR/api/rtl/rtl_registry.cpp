#include "include/common.h"
#include "rtl_registry.h"
#include "core/registry/virtual_fs.h"

static bool NtPathToWin32(ULONG RelativeTo, PCWSTR Path, HKEY& OutRoot, std::wstring& OutSubKey) {
    ULONG BaseRel = RelativeTo & ~0x80000000;
    std::wstring FullPath;

    switch (BaseRel) {
    case 0:
        FullPath = Path;
        break;
    case 1:
        FullPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        FullPath += Path;
        break;
    case 2:
        FullPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\";
        FullPath += Path;
        break;
    case 3:
        FullPath = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
        FullPath += Path;
        break;
    case 4:
        FullPath = L"\\Registry\\Machine\\Hardware\\DeviceMap\\";
        FullPath += Path;
        break;
    default:
        return false;
    }

    if (_wcsnicmp(FullPath.c_str(), L"\\Registry\\Machine\\", 18) == 0) {
        OutRoot = HKEY_LOCAL_MACHINE;
        OutSubKey = FullPath.substr(18);
        return true;
    }
    if (_wcsnicmp(FullPath.c_str(), L"\\Registry\\User\\", 15) == 0) {
        OutRoot = HKEY_USERS;
        OutSubKey = FullPath.substr(15);
        return true;
    }
    return false;
}

static std::wstring BuildFullNtRegPath(ULONG RelativeTo, PCWSTR Path) {
    ULONG BaseRel = RelativeTo & ~0x80000000;
    std::wstring FullPath;

    switch (BaseRel) {
    case 0:
        FullPath = Path;
        break;
    case 1:
        FullPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        FullPath += Path;
        break;
    case 2:
        FullPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\";
        FullPath += Path;
        break;
    case 3:
        FullPath = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
        FullPath += Path;
        break;
    case 4:
        FullPath = L"\\Registry\\Machine\\Hardware\\DeviceMap\\";
        FullPath += Path;
        break;
    default:
        return L"";
    }
    return FullPath;
}

NTSTATUS h_RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength) {
    auto HostPath = UcPtr((PWSTR)Path);
    auto HostValName = UcPtr((PWSTR)ValueName);
    auto HostValData = UcPtr(ValueData);
    Logger::Log("{CYN}\tWriting to %ls - %ls  type=%d len=%d", HostPath, HostValName, ValueType, ValueLength);
    if (HostValData && ValueLength >= 8)
        Logger::Log(" val=0x%016llx", *(uint64_t*)HostValData);
    else if (HostValData && ValueLength >= 4)
        Logger::Log(" val=0x%08x", *(uint32_t*)HostValData);
    else if (HostValData && ValueLength >= 2)
        Logger::Log(" val=0x%04x", *(uint16_t*)HostValData);
    else if (HostValData && ValueLength >= 1)
        Logger::Log(" val=0x%02x", *(uint8_t*)HostValData);
    Logger::Log("{RESET}\n");

    auto Ret = __NtRoutine("RtlWriteRegistryValue", RelativeTo, HostPath, HostValName, ValueType, HostValData, ValueLength);
    if (Ret != 0) {
        HKEY RootKey;
        std::wstring SubKey;
        if (NtPathToWin32(RelativeTo, HostPath, RootKey, SubKey)) {
            HKEY Key;
            LONG Res = RegCreateKeyExW(RootKey, SubKey.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &Key, nullptr);
            if (Res == ERROR_SUCCESS) {
                Res = RegSetValueExW(Key, HostValName, 0, ValueType, (const BYTE*)HostValData, ValueLength);
                RegCloseKey(Key);
                if (Res == ERROR_SUCCESS) {
                    Logger::Log("{GRN}\tWin32 registry write succeeded{RESET}\n");
                    return 0;
                }
            }
        }

        std::wstring FullNtPath = BuildFullNtRegPath(RelativeTo, HostPath);
        if (!FullNtPath.empty()) {
            std::wstring LocalRegPath = VirtualReg::NtRegPathToLocalW(FullNtPath.c_str());
            if (!LocalRegPath.empty()) {
                VirtualReg::WriteValueToFile(LocalRegPath, HostValName, ValueType, HostValData, ValueLength);
                return 0;
            }
        }

        Logger::Log("{YEL}\tRtlWriteRegistryValue: all fallbacks failed, faking success{RESET}\n");
        Ret = 0;
    }
    return Ret;
}

NTSTATUS h_RtlDeleteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName) {
    auto HostPath = UcPtr((PWSTR)Path);
    auto HostValName = UcPtr((PWSTR)ValueName);
    Logger::Log("{CYN}\tRtlDeleteRegistryValue: %ls \\ %ls{RESET}\n", HostPath, HostValName);

    auto Ret = __NtRoutine("RtlDeleteRegistryValue", RelativeTo, HostPath, HostValName);
    if (Ret != 0) {
        HKEY RootKey;
        std::wstring SubKey;
        if (NtPathToWin32(RelativeTo, HostPath, RootKey, SubKey)) {
            HKEY Key;
            LONG Res = RegOpenKeyExW(RootKey, SubKey.c_str(), 0, KEY_SET_VALUE, &Key);
            if (Res == ERROR_SUCCESS) {
                Res = RegDeleteValueW(Key, HostValName);
                RegCloseKey(Key);
                if (Res == ERROR_SUCCESS) {
                    Logger::Log("{GRN}\tWin32 registry delete succeeded{RESET}\n");
                    return 0;
                }
            }
            Logger::Log("{YEL}\tWin32 delete fallback failed (%d), faking success{RESET}\n", Res);
        } else {
            Logger::Log("{YEL}\tRtlDeleteRegistryValue failed 0x%08x, path conversion failed, faking success{RESET}\n", Ret);
        }
        Ret = 0;
    }
    return Ret;
}

NTSTATUS h_RtlQueryRegistryValues(ULONG RelativeTo, PCWSTR Path, PVOID QueryTable, PVOID Context, PVOID Environment) {
    auto HostPath = UcPtr((PWSTR)Path);
    Logger::Log("{CYN}\tRtlQueryRegistryValues: %ls{RESET}\n", HostPath);
    return STATUS_OBJECT_NAME_NOT_FOUND;
}
