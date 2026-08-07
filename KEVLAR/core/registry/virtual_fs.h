#pragma once

#include <string>
#include <Windows.h>
#include <unordered_map>
#include <mutex>

namespace VirtualFs {

void Initialize(const std::string& ExeDir, const std::string& DriverName);

std::wstring NtPathToLocalW(const wchar_t* NtPath);

bool LocalExists(const std::wstring& LocalPath);

HANDLE CreateLocalFile(const std::wstring& LocalPath, ACCESS_MASK DesiredAccess,
    ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions);

std::wstring GetVfsRoot();
std::wstring GetVregRoot();

}

namespace VirtualReg {

void Initialize(const std::string& ExeDir, const std::string& DriverName);

std::wstring NtRegPathToLocalW(const wchar_t* NtPath);

bool ReadValueFromFile(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG Type, void* Data, ULONG DataSize, ULONG* ResultSize);

bool ReadValueRaw(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG* OutType, void* Data, ULONG DataSize, ULONG* OutDataSize);

bool WriteValueToFile(const std::wstring& LocalPath, const wchar_t* ValueName,
    ULONG Type, const void* Data, ULONG DataSize);

bool KeyExistsLocally(const std::wstring& LocalPath);

}

namespace VRegHandleManager {

HANDLE AllocateHandle(const std::wstring& RegistryPath);
std::wstring GetPath(HANDLE Handle);
bool IsVRegHandle(HANDLE Handle);
void FreeHandle(HANDLE Handle);

}
