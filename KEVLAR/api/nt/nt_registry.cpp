#include "nt_registry.h"
#include "core/registry/virtual_fs.h"
#include <algorithm>
#include <cwctype>

static std::wstring ResolveRegPath(OBJECT_ATTRIBUTES* UcOa, const wchar_t* ObjectNameBuf) {
    if (!UcOa) return ObjectNameBuf ? std::wstring(ObjectNameBuf) : L"";

    auto HostOa = UcPtr(UcOa);
    HANDLE RootDir = HostOa->RootDirectory;

    if (RootDir && VRegHandleManager::IsVRegHandle(RootDir)) {
        std::wstring ParentVregPath = VRegHandleManager::GetPath(RootDir);
        if (!ParentVregPath.empty()) {
            std::wstring VregRoot = VirtualFs::GetVregRoot();
            std::wstring NtPath;
            if (ParentVregPath.size() > VregRoot.size()) {
                std::wstring Relative = ParentVregPath.substr(VregRoot.size());
                if (_wcsnicmp(Relative.c_str(), L"HKEY_LOCAL_MACHINE\\", 19) == 0) {
                    NtPath = L"\\Registry\\Machine\\" + Relative.substr(19);
                } else if (_wcsnicmp(Relative.c_str(), L"HKEY_USERS\\", 11) == 0) {
                    NtPath = L"\\Registry\\User\\" + Relative.substr(11);
                }
            }
            if (!NtPath.empty() && ObjectNameBuf && ObjectNameBuf[0]) {
                if (NtPath.back() != L'\\') NtPath += L'\\';
                NtPath += ObjectNameBuf;
                return NtPath;
            }
        }
    }

    return ObjectNameBuf ? std::wstring(ObjectNameBuf) : L"";
}

static bool VRegHasValues(const std::wstring& LocalRegPath) {
    if (LocalRegPath.empty()) return false;
    std::error_code Ec;
    for (auto& Entry : std::filesystem::directory_iterator(LocalRegPath, Ec)) {
        if (!Entry.is_directory()) {
            std::wstring Fn = Entry.path().filename().wstring();
            if (Fn.size() > 7 && Fn.substr(Fn.size() - 7) == L".regval")
                return true;
        }
    }
    return false;
}

static void AutoPopulateBcdElement(const std::wstring& LocalRegPath, const wchar_t* NtPath) {
    if (!NtPath) return;
    std::wstring Path(NtPath);
    std::transform(Path.begin(), Path.end(), Path.begin(), ::towlower);

    auto ElementsPos = Path.find(L"\\elements\\");
    if (ElementsPos == std::wstring::npos) return;

    std::wstring ElementIdStr = Path.substr(ElementsPos + 10);
    auto SlashPos = ElementIdStr.find(L'\\');
    if (SlashPos != std::wstring::npos) ElementIdStr = ElementIdStr.substr(0, SlashPos);
    if (ElementIdStr.size() != 8) return;

    uint32_t ElementId = 0;
    try { ElementId = (uint32_t)std::stoul(ElementIdStr, nullptr, 16); } catch (...) { return; }

    uint32_t Format = (ElementId >> 24) & 0xF;

    if (Format == 6) {
        BYTE Val = 0;
        VirtualReg::WriteValueToFile(LocalRegPath, L"Element", 3, &Val, 1);
        Logger::Log("{GRN}\tBCD auto-populate: %ls Element=false (boolean){RESET}\n", ElementIdStr.c_str());
    } else if (Format == 5) {
        DWORD Val = 0;
        VirtualReg::WriteValueToFile(LocalRegPath, L"Element", 4, &Val, sizeof(Val));
        Logger::Log("{GRN}\tBCD auto-populate: %ls Element=0 (integer){RESET}\n", ElementIdStr.c_str());
    } else if (Format == 2) {
        wchar_t Val[] = L"";
        VirtualReg::WriteValueToFile(LocalRegPath, L"Element", 1, Val, sizeof(Val));
        Logger::Log("{GRN}\tBCD auto-populate: %ls Element=\"\" (string){RESET}\n", ElementIdStr.c_str());
    }
}

NTSTATUS h_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {
    auto HostHandle = UcPtr(KeyHandle);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    std::wstring FullPath = ResolveRegPath(ObjectAttributes, PathStr);
    const wchar_t* ResolvedPath = FullPath.empty() ? PathStr : FullPath.c_str();

    if (ResolvedPath) {
        std::wstring PreCheckPath = VirtualReg::NtRegPathToLocalW(ResolvedPath);
        if (!PreCheckPath.empty() && VRegHasValues(PreCheckPath)) {
            *HostHandle = VRegHandleManager::AllocateHandle(PreCheckPath);
            Logger::Log("  {GRN}VReg: preferring local key with values %ls{RESET}\n", PreCheckPath.c_str());
            Logger::Log("  {YEL}Open key: {WHT}%ls {GRY}: {WHT}%08x{RESET}\n", ResolvedPath, 0);
            return 0;
        }
    }

    ACCESS_MASK HostAccess = DesiredAccess | KEY_READ;
    auto Ret = __NtRoutine("NtOpenKey", HostHandle, HostAccess, &LocalOa);

    if (Ret != 0 && ResolvedPath) {
        std::wstring LocalRegPath = VirtualReg::NtRegPathToLocalW(ResolvedPath);
        if (!LocalRegPath.empty()) {
            if (VirtualReg::KeyExistsLocally(LocalRegPath)) {
                Logger::Log("  {GRN}VReg: found local key %ls{RESET}\n", LocalRegPath.c_str());
                *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                Ret = 0;
            } else if (Ret == 0xC0000022) {
                std::error_code Ec;
                std::filesystem::create_directories(LocalRegPath, Ec);
                Logger::Log("  {GRN}VReg: created key for access-denied fallback %ls{RESET}\n", LocalRegPath.c_str());
                AutoPopulateBcdElement(LocalRegPath, ResolvedPath);
                *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                Ret = 0;
            } else if (Ret == (NTSTATUS)0xC0000034 && _wcsnicmp(ResolvedPath, L"\\Registry\\Machine\\BCD", 21) == 0) {
                std::error_code Ec;
                std::filesystem::create_directories(LocalRegPath, Ec);
                if (!Ec) {
                    Logger::Log("  {GRN}VReg: auto-created BCD key %ls{RESET}\n", LocalRegPath.c_str());
                    AutoPopulateBcdElement(LocalRegPath, ResolvedPath);
                    *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                    Ret = 0;
                }
            } else if (Ret == (NTSTATUS)0xC0000034 && _wcsnicmp(ResolvedPath, L"\\Registry\\User\\", 15) == 0) {
                std::error_code Ec;
                std::filesystem::create_directories(LocalRegPath, Ec);
                if (!Ec) {
                    Logger::Log("  {GRN}VReg: auto-created User key %ls{RESET}\n", LocalRegPath.c_str());
                    *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                    Ret = 0;
                }
            }
        }
    }

    Logger::Log("  {YEL}Open key: {WHT}%ls {GRY}: {WHT}%08x{RESET}\n", ResolvedPath ? ResolvedPath : L"(null)", Ret);
    return Ret;
}

NTSTATUS h_ZwFlushKey(PHANDLE KeyHandle) {
    if (VRegHandleManager::IsVRegHandle((HANDLE)KeyHandle))
        return 0;
    auto Ret = __NtRoutine("NtFlushKey", KeyHandle);
    return Ret;
}

NTSTATUS h_ZwSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {
    auto HostValName = UcPtr(ValueName);
    UNICODE_STRING LocalValName = *HostValName;
    LocalValName.Buffer = UcPtr(LocalValName.Buffer);
    auto HostData = UcPtr(Data);
    Logger::Log("{CYN}\tZwSetValueKey: %ls{RESET}\n", LocalValName.Buffer);

    if (VRegHandleManager::IsVRegHandle(KeyHandle)) {
        std::wstring RegPath = VRegHandleManager::GetPath(KeyHandle);
        if (!RegPath.empty()) {
            std::wstring ValNameStr(LocalValName.Buffer, LocalValName.Length / sizeof(wchar_t));
            VirtualReg::WriteValueToFile(RegPath, ValNameStr.c_str(), Type, HostData, DataSize);
            return 0;
        }
    }

    return (NTSTATUS)__NtRoutine("NtSetValueKey", KeyHandle, &LocalValName, TitleIndex, Type, HostData, DataSize);
}

NTSTATUS h_ZwDeleteKey(HANDLE KeyHandle) {
    if (VRegHandleManager::IsVRegHandle(KeyHandle))
        return 0;
    return (NTSTATUS)__NtRoutine("NtDeleteKey", KeyHandle);
}

NTSTATUS h_ZwEnumerateKey(HANDLE KeyHandle, ULONG Index, uint32_t KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    if (VRegHandleManager::IsVRegHandle(KeyHandle)) {
        auto HostResLen = UcPtr(ResultLength);
        if (HostResLen) *HostResLen = 0;
        return (NTSTATUS)0xC0000008;
    }
    auto HostInfo = UcPtr(KeyInformation);
    auto HostResLen = UcPtr(ResultLength);
    return (NTSTATUS)__NtRoutine("NtEnumerateKey", KeyHandle, Index, KeyInformationClass, HostInfo, Length, HostResLen);
}

NTSTATUS h_ZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, uint32_t KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    if (VRegHandleManager::IsVRegHandle(KeyHandle)) {
        auto HostInfo = UcPtr(KeyValueInformation);
        auto HostResLen = UcPtr(ResultLength);
        std::wstring RegPath = VRegHandleManager::GetPath(KeyHandle);
        if (RegPath.empty()) {
            if (HostResLen) *HostResLen = 0;
            return (NTSTATUS)0x8000001A;
        }

        std::vector<std::wstring> ValFiles;
        std::error_code Ec;
        for (auto& Entry : std::filesystem::directory_iterator(RegPath, Ec)) {
            if (!Entry.is_directory()) {
                std::wstring Fn = Entry.path().filename().wstring();
                if (Fn.size() > 7 && Fn.substr(Fn.size() - 7) == L".regval")
                    ValFiles.push_back(Entry.path().wstring());
            }
        }
        std::sort(ValFiles.begin(), ValFiles.end());

        if (Index >= (ULONG)ValFiles.size()) {
            if (HostResLen) *HostResLen = 0;
            return (NTSTATUS)0x8000001A;
        }

        std::wstring ValPath = ValFiles[Index];
        std::wstring ValName = std::filesystem::path(ValPath).stem().wstring();

        HANDLE HFile = CreateFileW(ValPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (HFile == INVALID_HANDLE_VALUE) {
            if (HostResLen) *HostResLen = 0;
            return (NTSTATUS)0x8000001A;
        }

        ULONG StoredType = 0, StoredDataSize = 0;
        DWORD BytesRead = 0;
        ReadFile(HFile, &StoredType, sizeof(StoredType), &BytesRead, nullptr);
        ReadFile(HFile, &StoredDataSize, sizeof(StoredDataSize), &BytesRead, nullptr);

        BYTE TempBuf[4096] = {};
        ULONG ActualDataSize = min(StoredDataSize, (ULONG)sizeof(TempBuf));
        if (ActualDataSize > 0)
            ReadFile(HFile, TempBuf, ActualDataSize, &BytesRead, nullptr);
        CloseHandle(HFile);

        ULONG NameBytes = (ULONG)(ValName.size() * sizeof(wchar_t));

        if (KeyValueInformationClass == 2) {
            ULONG Required = 12 + ActualDataSize;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required) return (NTSTATUS)0xC0000023;
            BYTE* Out = (BYTE*)HostInfo;
            memset(Out, 0, Required);
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = ActualDataSize;
            memcpy(Out + 12, TempBuf, ActualDataSize);
            return 0;
        } else if (KeyValueInformationClass == 1) {
            ULONG DataOffset = 20 + NameBytes;
            DataOffset = (DataOffset + 3) & ~3;
            ULONG Required = DataOffset + ActualDataSize;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required) return (NTSTATUS)0xC0000023;
            BYTE* Out = (BYTE*)HostInfo;
            memset(Out, 0, Required);
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = DataOffset;
            *(ULONG*)(Out + 12) = ActualDataSize;
            *(ULONG*)(Out + 16) = NameBytes;
            memcpy(Out + 20, ValName.c_str(), NameBytes);
            memcpy(Out + DataOffset, TempBuf, ActualDataSize);
            return 0;
        } else if (KeyValueInformationClass == 0) {
            ULONG Required = 12 + NameBytes;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required) return (NTSTATUS)0xC0000023;
            BYTE* Out = (BYTE*)HostInfo;
            memset(Out, 0, Required);
            *(ULONG*)(Out + 0) = 0;
            *(ULONG*)(Out + 4) = StoredType;
            *(ULONG*)(Out + 8) = NameBytes;
            memcpy(Out + 12, ValName.c_str(), NameBytes);
            return 0;
        }

        if (HostResLen) *HostResLen = 0;
        return (NTSTATUS)0x8000001A;
    }
    auto HostInfo = UcPtr(KeyValueInformation);
    auto HostResLen = UcPtr(ResultLength);
    return (NTSTATUS)__NtRoutine("NtEnumerateValueKey", KeyHandle, Index, KeyValueInformationClass, HostInfo, Length, HostResLen);
}

NTSTATUS h_ZwDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    auto HostValName = UcPtr(ValueName);
    UNICODE_STRING LocalValName = *HostValName;
    LocalValName.Buffer = UcPtr(LocalValName.Buffer);
    Logger::Log("{CYN}\tZwDeleteValueKey: %ls{RESET}\n", LocalValName.Buffer);
    if (VRegHandleManager::IsVRegHandle(KeyHandle))
        return 0;
    return (NTSTATUS)__NtRoutine("NtDeleteValueKey", KeyHandle, &LocalValName);
}

NTSTATUS h_ZwCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
    ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    auto HostHandle = UcPtr(KeyHandle);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);
    PUNICODE_STRING HostClass = nullptr;
    UNICODE_STRING LocalClass = {};
    if (Class) {
        auto Uc = UcPtr(Class);
        LocalClass = *Uc;
        LocalClass.Buffer = UcPtr(LocalClass.Buffer);
        HostClass = &LocalClass;
    }
    auto HostDisp = UcPtr(Disposition);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    std::wstring FullPath = ResolveRegPath(ObjectAttributes, PathStr);
    const wchar_t* ResolvedPath = FullPath.empty() ? PathStr : FullPath.c_str();

    ACCESS_MASK HostAccess = DesiredAccess | KEY_READ | KEY_WRITE;
    auto Ret = __NtRoutine("NtCreateKey", HostHandle, HostAccess, &LocalOa, TitleIndex, HostClass, CreateOptions, HostDisp);

    if (Ret != 0 && ResolvedPath) {
        std::wstring LocalRegPath = VirtualReg::NtRegPathToLocalW(ResolvedPath);
        if (!LocalRegPath.empty()) {
            std::error_code Ec;
            std::filesystem::create_directories(LocalRegPath, Ec);
            if (!Ec) {
                *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                if (HostDisp) *HostDisp = 1;
                Logger::Log("  {GRN}VReg: created local key %ls{RESET}\n", LocalRegPath.c_str());
                Ret = 0;
            }
        }
    }

    Logger::Log("  {YEL}Create key: {WHT}%ls {GRY}: {WHT}%08x{RESET}\n", ResolvedPath ? ResolvedPath : L"(null)", Ret);
    return Ret;
}

NTSTATUS h_ZwOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, ULONG OpenOptions) {
    auto HostHandle = UcPtr(KeyHandle);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    std::wstring FullPath = ResolveRegPath(ObjectAttributes, PathStr);
    const wchar_t* ResolvedPath = FullPath.empty() ? PathStr : FullPath.c_str();

    if (ResolvedPath) {
        std::wstring PreCheckPath = VirtualReg::NtRegPathToLocalW(ResolvedPath);
        if (!PreCheckPath.empty() && VRegHasValues(PreCheckPath)) {
            *HostHandle = VRegHandleManager::AllocateHandle(PreCheckPath);
            Logger::Log("  {GRN}VReg: preferring local key with values %ls{RESET}\n", PreCheckPath.c_str());
            Logger::Log("  {YEL}Open key ex: {WHT}%ls {GRY}: {WHT}%08x{RESET}\n", ResolvedPath, 0);
            return 0;
        }
    }

    ACCESS_MASK HostAccess = DesiredAccess | KEY_READ;
    auto Ret = __NtRoutine("NtOpenKeyEx", HostHandle, HostAccess, &LocalOa, OpenOptions);

    if (Ret != 0 && ResolvedPath) {
        std::wstring LocalRegPath = VirtualReg::NtRegPathToLocalW(ResolvedPath);
        if (!LocalRegPath.empty()) {
            if (VirtualReg::KeyExistsLocally(LocalRegPath)) {
                Logger::Log("  {GRN}VReg: found local key %ls{RESET}\n", LocalRegPath.c_str());
                *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                Ret = 0;
            } else if (Ret == (NTSTATUS)0xC0000034 && _wcsnicmp(ResolvedPath, L"\\Registry\\User\\", 15) == 0) {
                std::error_code Ec;
                std::filesystem::create_directories(LocalRegPath, Ec);
                if (!Ec) {
                    Logger::Log("  {GRN}VReg: auto-created User key %ls{RESET}\n", LocalRegPath.c_str());
                    *HostHandle = VRegHandleManager::AllocateHandle(LocalRegPath);
                    Ret = 0;
                }
            }
        }
    }

    Logger::Log("  {YEL}Open key ex: {WHT}%ls {GRY}: {WHT}%08x{RESET}\n", ResolvedPath ? ResolvedPath : L"(null)", Ret);
    return Ret;
}

NTSTATUS h_ZwQueryKey(HANDLE KeyHandle, uint32_t KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    auto HostInfo = UcPtr(KeyInformation);
    auto HostResLen = UcPtr(ResultLength);

    if (VRegHandleManager::IsVRegHandle(KeyHandle)) {
        std::wstring RegPath = VRegHandleManager::GetPath(KeyHandle);
        std::wstring KeyName;
        auto Pos = RegPath.find_last_of(L"\\/");
        if (Pos != std::wstring::npos)
            KeyName = RegPath.substr(Pos + 1);
        else
            KeyName = RegPath;

        if (KeyInformationClass == 0) {
            ULONG NameBytes = (ULONG)(KeyName.size() * sizeof(wchar_t));
            ULONG Required = 16 + NameBytes;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required)
                return (NTSTATUS)0xC0000023;
            BYTE* Out = (BYTE*)HostInfo;
            memset(Out, 0, Required);
            *(ULONG*)(Out + 12) = NameBytes;
            memcpy(Out + 16, KeyName.c_str(), NameBytes);
            return 0;
        } else if (KeyInformationClass == 2) {
            ULONG Required = 44;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required)
                return (NTSTATUS)0xC0000023;
            memset(HostInfo, 0, Required);
            std::error_code Ec;
            ULONG SubKeyCount = 0;
            ULONG ValueCount = 0;
            for (auto& Entry : std::filesystem::directory_iterator(RegPath, Ec)) {
                if (Entry.is_directory())
                    SubKeyCount++;
                else {
                    std::wstring Fn = Entry.path().filename().wstring();
                    if (Fn.size() > 7 && Fn.substr(Fn.size() - 7) == L".regval")
                        ValueCount++;
                }
            }
            BYTE* Out = (BYTE*)HostInfo;
            *(ULONG*)(Out + 8) = SubKeyCount;
            *(ULONG*)(Out + 16) = 255;
            *(ULONG*)(Out + 20) = ValueCount;
            *(ULONG*)(Out + 28) = 255;
            *(ULONG*)(Out + 36) = 0;
            return 0;
        } else if (KeyInformationClass == 4) {
            ULONG Required = 36;
            if (HostResLen) *HostResLen = Required;
            if (Length < Required)
                return (NTSTATUS)0xC0000023;
            memset(HostInfo, 0, Required);
            return 0;
        }
        if (HostResLen) *HostResLen = 0;
        return (NTSTATUS)0xC0000034;
    }

    auto Ret = __NtRoutine("NtQueryKey", KeyHandle, KeyInformationClass, HostInfo, Length, HostResLen);
    Logger::Log("{GRY}\tZwQueryKey: class=%d len=%d ret=0x%08x{RESET}\n", KeyInformationClass, Length, Ret);
    return Ret;
}
