#pragma once

#include <PEMapper/pefile.h>

#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/provider.h"
#include "host/providers/static_export_provider.h"
#include "host/config/config.h"

#include "core/object/handle_manager.h"
#include "include/nt_define.h"
#include <Logger/Logger.h>

#include "core/loader/environment.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"

using fnFreeCall = uint64_t(__fastcall*)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
    auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
    return fn(std::forward<Params>(params)...);
}

template<typename T>
static T* UcPtr(T* MaybeUcPtr) {
    if (!MaybeUcPtr) return nullptr;
    auto Host = (T*)UnicornMem::UcToHost((uint64_t)MaybeUcPtr);
    return Host ? Host : MaybeUcPtr;
}

template<typename T>
static T* UcPtrSafe(T* MaybeUcPtr, T& LocalBuf) {
    if (!MaybeUcPtr) return nullptr;
    auto Host = (T*)UnicornMem::UcToHost((uint64_t)MaybeUcPtr);
    if (Host) return Host;
    if (uc_mem_read((uc_engine*)0x1, (uint64_t)MaybeUcPtr, &LocalBuf, sizeof(T)) == UC_ERR_OK)
        return &LocalBuf;
    return nullptr;
}

static OBJECT_ATTRIBUTES TranslateObjAttr(OBJECT_ATTRIBUTES* UcOa, OBJECT_ATTRIBUTES& LocalOa, UNICODE_STRING& LocalName) {
    auto HostOa = UcPtr(UcOa);
    LocalOa = *HostOa;
    LocalOa.RootDirectory = nullptr;
    LocalOa.Attributes &= ~0x200;
    LocalOa.SecurityDescriptor = nullptr;
    LocalOa.SecurityQualityOfService = nullptr;
    if (HostOa->ObjectName) {
        auto HostName = UcPtr(HostOa->ObjectName);
        LocalName = *HostName;
        LocalName.Buffer = UcPtr(LocalName.Buffer);
        LocalOa.ObjectName = &LocalName;
    }
    return LocalOa;
}

static void RewriteSystemRootPath(OBJECT_ATTRIBUTES& Oa, UNICODE_STRING& Name, std::wstring& Storage) {
    if (!Oa.ObjectName || !Oa.ObjectName->Buffer) return;
    std::wstring Path(Oa.ObjectName->Buffer, Oa.ObjectName->Length / sizeof(wchar_t));
    bool Changed = false;
    if (_wcsnicmp(Path.c_str(), L"\\SystemRoot\\", 12) == 0) {
        Storage = L"\\??\\C:\\Windows\\" + Path.substr(12);
        Changed = true;
    } else if (_wcsnicmp(Path.c_str(), L"SystemRoot\\", 11) == 0) {
        Storage = L"\\??\\C:\\Windows\\" + Path.substr(11);
        Changed = true;
    }
    if (Changed) {
        Name.Buffer = (PWSTR)Storage.c_str();
        Name.Length = (USHORT)(Storage.size() * sizeof(wchar_t));
        Name.MaximumLength = Name.Length + sizeof(wchar_t);
        Oa.ObjectName = &Name;
    }
}

#define NtQuerySystemInformation(...) __NtRoutine("NtQuerySystemInformation", __VA_ARGS__)
