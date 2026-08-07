#include "virtual_fs.h"
#include "include/common.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <mutex>

namespace fs = std::filesystem;

static std::wstring VfsRootW;
static std::wstring VregRootW;
static std::mutex VfsMutex;

static std::wstring ToWide(const std::string& S) {
    if (S.empty()) return L"";
    int Len = MultiByteToWideChar(CP_ACP, 0, S.c_str(), -1, nullptr, 0);
    std::wstring W(Len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, S.c_str(), -1, &W[0], Len);
    return W;
}

static void EnsureDirectoryExists(const std::wstring& Path) {
    fs::path P(Path);
    if (P.has_filename() && P.has_extension())
        P = P.parent_path();
    if (!P.empty()) {
        std::error_code Ec;
        fs::create_directories(P, Ec);
    }
}

static std::wstring NormalizeSeparators(std::wstring S) {
    for (auto& Ch : S) {
        if (Ch == L'/') Ch = L'\\';
    }
    while (S.size() > 1 && S.back() == L'\\')
        S.pop_back();
    return S;
}

void VirtualFs::Initialize(const std::string& ExeDir, const std::string& DriverName) {
    std::string DrvNoExt = DriverName;
    auto Dot = DrvNoExt.find_last_of('.');
    if (Dot != std::string::npos)
        DrvNoExt = DrvNoExt.substr(0, Dot);

    std::string VfsBase = ExeDir + DrvNoExt + "\\";

    VfsRootW = ToWide(VfsBase + "vfs\\");
    VregRootW = ToWide(VfsBase + "vreg\\");

    std::error_code Ec;
    fs::create_directories(fs::path(VfsRootW) / L"C" / L"Windows" / L"System32" / L"drivers" / L"Logs", Ec);
    fs::create_directories(fs::path(VfsRootW) / L"C" / L"Windows" / L"System32" / L"config", Ec);
    fs::create_directories(fs::path(VfsRootW) / L"C" / L"ProgramData", Ec);

    fs::create_directories(fs::path(VregRootW) / L"HKEY_LOCAL_MACHINE" / L"SYSTEM" / L"CurrentControlSet" / L"Services", Ec);
    fs::create_directories(fs::path(VregRootW) / L"HKEY_LOCAL_MACHINE" / L"SOFTWARE" / L"Microsoft" / L"Windows NT" / L"CurrentVersion", Ec);
    fs::create_directories(fs::path(VregRootW) / L"HKEY_LOCAL_MACHINE" / L"HARDWARE" / L"DESCRIPTION" / L"System", Ec);

    std::wstring BootStatusPath = VfsRootW + L"C\\Windows\\vgkbootstatus.dat";
    {
        HANDLE BsFile = CreateFileW(BootStatusPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (BsFile != INVALID_HANDLE_VALUE) {
            BYTE BootByte = 0x01;
            DWORD Written;
            WriteFile(BsFile, &BootByte, 1, &Written, nullptr);
            CloseHandle(BsFile);
        }
    }

    Logger::Log("{GRN}VirtualFs initialized: {WHT}%ls{RESET}\n", VfsRootW.c_str());
    Logger::Log("{GRN}VirtualReg initialized: {WHT}%ls{RESET}\n", VregRootW.c_str());
}

std::wstring VirtualFs::GetVfsRoot() { return VfsRootW; }
std::wstring VirtualFs::GetVregRoot() { return VregRootW; }

std::wstring VirtualFs::NtPathToLocalW(const wchar_t* NtPath) {
    if (!NtPath || !NtPath[0]) return L"";

    std::wstring Path(NtPath);

    if (Path.substr(0, 4) == L"\\??\\")
        Path = Path.substr(4);
    else if (Path.substr(0, 4) == L"\\\\?\\")
        Path = Path.substr(4);
    else if (Path.substr(0, 8) == L"\\Device\\")
        return L"";

    if (_wcsnicmp(Path.c_str(), L"SystemRoot\\", 11) == 0 || _wcsnicmp(Path.c_str(), L"SystemRoot/", 11) == 0) {
        Path = L"C:\\Windows\\" + Path.substr(11);
    } else if (_wcsnicmp(Path.c_str(), L"\\SystemRoot\\", 12) == 0 || _wcsnicmp(Path.c_str(), L"\\SystemRoot/", 12) == 0) {
        Path = L"C:\\Windows\\" + Path.substr(12);
    }

    if (Path.size() >= 2 && Path[1] == L':') {
        wchar_t Drive = towupper(Path[0]);
        std::wstring Rest = Path.substr(2);
        if (!Rest.empty() && Rest[0] == L'\\')
            Rest = Rest.substr(1);
        Rest = NormalizeSeparators(Rest);

        std::wstring Local = VfsRootW + Drive + L"\\" + Rest;
        return Local;
    }

    return L"";
}

bool VirtualFs::LocalExists(const std::wstring& LocalPath) {
    if (LocalPath.empty()) return false;
    DWORD Attrs = GetFileAttributesW(LocalPath.c_str());
    return Attrs != INVALID_FILE_ATTRIBUTES;
}

HANDLE VirtualFs::CreateLocalFile(const std::wstring& LocalPath, ACCESS_MASK DesiredAccess,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions) {
    if (LocalPath.empty()) return INVALID_HANDLE_VALUE;

    std::lock_guard<std::mutex> Lock(VfsMutex);

    EnsureDirectoryExists(LocalPath);

    bool IsDir = (CreateOptions & 0x00000001) != 0;

    if (IsDir) {
        std::error_code Ec;
        fs::create_directories(LocalPath, Ec);
        HANDLE H = CreateFileW(LocalPath.c_str(),
            DesiredAccess & 0x001F01FF,
            ShareAccess,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        return H;
    }

    DWORD Win32Access = 0;
    if (DesiredAccess & 0x80000000) Win32Access |= GENERIC_READ;
    if (DesiredAccess & 0x40000000) Win32Access |= GENERIC_WRITE;
    if (DesiredAccess & 0x20000000) Win32Access |= GENERIC_EXECUTE;
    if (DesiredAccess & 0x10000000) Win32Access |= GENERIC_ALL;
    if (DesiredAccess & 0x0001) Win32Access |= FILE_READ_DATA;
    if (DesiredAccess & 0x0002) Win32Access |= FILE_WRITE_DATA;
    if (DesiredAccess & 0x0004) Win32Access |= FILE_APPEND_DATA;
    if (Win32Access == 0) Win32Access = GENERIC_READ | GENERIC_WRITE;

    DWORD Win32Disp;
    switch (CreateDisposition) {
    case 0: Win32Disp = CREATE_NEW; break;
    case 1: Win32Disp = OPEN_EXISTING; break;
    case 2: Win32Disp = CREATE_ALWAYS; break;
    case 3: Win32Disp = OPEN_ALWAYS; break;
    case 4: Win32Disp = TRUNCATE_EXISTING; break;
    case 5: Win32Disp = OPEN_ALWAYS; break;
    default: Win32Disp = OPEN_ALWAYS; break;
    }

    DWORD Attrs = FILE_ATTRIBUTE_NORMAL;
    if (FileAttributes) Attrs = FileAttributes;

    HANDLE H = CreateFileW(LocalPath.c_str(),
        Win32Access, ShareAccess, nullptr, Win32Disp, Attrs, nullptr);
    return H;
}

void VirtualReg::Initialize(const std::string& ExeDir, const std::string& DriverName) {
}

std::wstring VirtualReg::NtRegPathToLocalW(const wchar_t* NtPath) {
    if (!NtPath || !NtPath[0]) return L"";

    std::wstring Path(NtPath);

    if (_wcsnicmp(Path.c_str(), L"\\Registry\\Machine\\", 18) == 0) {
        std::wstring Sub = Path.substr(18);
        for (auto& Ch : Sub) { if (Ch == L'\\') Ch = L'/'; }
        for (auto& Ch : Sub) { if (Ch == L'/') Ch = L'\\'; }
        return VregRootW + L"HKEY_LOCAL_MACHINE\\" + Sub;
    }
    if (_wcsnicmp(Path.c_str(), L"\\REGISTRY\\MACHINE\\", 18) == 0) {
        std::wstring Sub = Path.substr(18);
        return VregRootW + L"HKEY_LOCAL_MACHINE\\" + Sub;
    }
    if (_wcsnicmp(Path.c_str(), L"\\Registry\\User\\", 15) == 0) {
        std::wstring Sub = Path.substr(15);
        return VregRootW + L"HKEY_USERS\\" + Sub;
    }
    if (_wcsnicmp(Path.c_str(), L"\\REGISTRY\\USER\\", 15) == 0) {
        std::wstring Sub = Path.substr(15);
        return VregRootW + L"HKEY_USERS\\" + Sub;
    }

    return L"";
}

bool VirtualReg::KeyExistsLocally(const std::wstring& LocalPath) {
    if (LocalPath.empty()) return false;
    DWORD Attrs = GetFileAttributesW(LocalPath.c_str());
    return (Attrs != INVALID_FILE_ATTRIBUTES) && (Attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool VirtualReg::WriteValueToFile(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG Type, const void* Data, ULONG DataSize) {
    if (LocalPath.empty()) return false;

    std::error_code Ec;
    fs::create_directories(LocalPath, Ec);

    std::wstring ValName = ValueName ? ValueName : L"(Default)";
    std::wstring FilePath = LocalPath + L"\\" + ValName + L".regval";

    HANDLE H = CreateFileW(FilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (H == INVALID_HANDLE_VALUE) return false;

    DWORD Written;
    WriteFile(H, &Type, sizeof(Type), &Written, nullptr);
    WriteFile(H, &DataSize, sizeof(DataSize), &Written, nullptr);
    if (Data && DataSize > 0)
        WriteFile(H, Data, DataSize, &Written, nullptr);
    CloseHandle(H);

    Logger::Log("{GRN}\tVReg: wrote %ls\\%ls (type=%d size=%d){RESET}\n", LocalPath.c_str(), ValName.c_str(), Type, DataSize);
    return true;
}

bool VirtualReg::ReadValueFromFile(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG Type, void* Data, ULONG DataSize, ULONG* ResultSize) {
    if (LocalPath.empty()) return false;

    std::wstring ValName = ValueName ? ValueName : L"(Default)";
    std::wstring FilePath = LocalPath + L"\\" + ValName + L".regval";

    HANDLE H = CreateFileW(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (H == INVALID_HANDLE_VALUE) return false;

    DWORD BytesRead;
    ULONG StoredType, StoredSize;
    ReadFile(H, &StoredType, sizeof(StoredType), &BytesRead, nullptr);
    ReadFile(H, &StoredSize, sizeof(StoredSize), &BytesRead, nullptr);

    if (ResultSize) *ResultSize = StoredSize;

    if (Data && DataSize >= StoredSize && StoredSize > 0) {
        ReadFile(H, Data, StoredSize, &BytesRead, nullptr);
    }

    CloseHandle(H);
    return true;
}

bool VirtualReg::ReadValueRaw(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG* OutType, void* Data, ULONG DataSize, ULONG* OutDataSize) {
    if (LocalPath.empty()) return false;

    std::wstring ValName = ValueName ? ValueName : L"(Default)";
    std::wstring FilePath = LocalPath + L"\\" + ValName + L".regval";

    HANDLE H = CreateFileW(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (H == INVALID_HANDLE_VALUE) return false;

    DWORD BytesRead;
    ULONG StoredType, StoredSize;
    ReadFile(H, &StoredType, sizeof(StoredType), &BytesRead, nullptr);
    ReadFile(H, &StoredSize, sizeof(StoredSize), &BytesRead, nullptr);

    if (OutType) *OutType = StoredType;
    if (OutDataSize) *OutDataSize = StoredSize;

    if (Data && DataSize >= StoredSize && StoredSize > 0) {
        ReadFile(H, Data, StoredSize, &BytesRead, nullptr);
    }

    CloseHandle(H);
    return true;
}

static std::mutex VRegHandleMutex;
static std::unordered_map<uint64_t, std::wstring> VRegHandleMap;
static uint64_t VRegHandleCounter = 0xFACE0001;

HANDLE VRegHandleManager::AllocateHandle(const std::wstring& RegistryPath) {
    std::lock_guard<std::mutex> Lock(VRegHandleMutex);
    uint64_t Handle = VRegHandleCounter++;
    VRegHandleMap[Handle] = RegistryPath;
    return (HANDLE)Handle;
}

std::wstring VRegHandleManager::GetPath(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(VRegHandleMutex);
    auto It = VRegHandleMap.find((uint64_t)Handle);
    if (It != VRegHandleMap.end())
        return It->second;
    return L"";
}

bool VRegHandleManager::IsVRegHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(VRegHandleMutex);
    return VRegHandleMap.count((uint64_t)Handle) != 0;
}

void VRegHandleManager::FreeHandle(HANDLE Handle) {
    std::lock_guard<std::mutex> Lock(VRegHandleMutex);
    VRegHandleMap.erase((uint64_t)Handle);
}
