#include "include/common.h"
#include "ob_object.h"
#include "api/nt/nt_memory.h"

uint64_t h_ObfDereferenceObject(PVOID obj) { //TODO

    return 0;
}

LONG_PTR h_ObfReferenceObject(PVOID Object) {
    if (!Object)
        return -1;
    if (Object == (PVOID)EPROCESS_BASE_UC) {
        Logger::Log("{GRY}\tIncreasing ref by 1{RESET}\n");
        return (LONG_PTR)EPROCESS_BASE_UC;
    } else {
        Logger::Log("{RED}\tFailed - {RESET}");
        Logger::Log("{RED}%llx{RESET}\n", Object);
    }

    return 0;
}

NTSTATUS h_ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType,
    uint64_t AccessMode, PHANDLE Handle) {
    return STATUS_SUCCESS;
}

NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength) {
    Logger::Log("{YEL}\tUnimplemented function call detected{RESET}\n");
    return STATUS_SUCCESS;
}

NTSTATUS h_ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint64_t AccessMode, PVOID* Object,
    void* HandleInformation) {

    auto HostObject = UcPtr(Object);

    if (ObjectType == PsThreadType) {
        *HostObject = (PVOID)&FakeKernelThread;

        std::lock_guard<std::mutex> TmGuard(Environment::ThreadManager::ThreadManagerLock);
        if (Environment::ThreadManager::environment_threads.contains((uintptr_t)handle)) {
            *(_ETHREAD**)HostObject = Environment::ThreadManager::environment_threads[(uintptr_t)handle];
        }
    }
    else if (ObjectType == PsProcessType) {
        *HostObject = (PVOID)handle;
    }
    else if (!ObjectType)
    {
        *HostObject = (PVOID)handle;
    }
    else {
        *HostObject = (PVOID)handle;
    }


    return 0;
}

//todo more logic required
NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle) {
    auto HostRegHandle = UcPtr(RegistrationHandle);
    *HostRegHandle = (PVOID)0xDEADBEEFCAFE;
    return STATUS_SUCCESS;
}

void h_ObUnRegisterCallbacks(PVOID RegistrationHandle) {

}

void* h_ObGetFilterVersion(void* arg) { return 0; }

NTSTATUS h_ObDereferenceObjectDeferDelete(PVOID Object) {
    return 0;
}

void h_ObDereferenceObjectWithTag(PVOID Object, ULONG Tag) {}

NTSTATUS h_ObOpenObjectByName(
    OBJECT_ATTRIBUTES* ObjectAttributes,
    void* ObjectType,
    uint8_t AccessMode,
    void* AccessState,
    ACCESS_MASK DesiredAccess,
    void* ParseContext,
    PHANDLE Handle)
{
    auto HostHandle = UcPtr(Handle);
    OBJECT_ATTRIBUTES LocalOa;
    UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* NameStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    Logger::Log("{CYN}\tObOpenObjectByName: %ls access=%08x mode=%u{RESET}\n",
        NameStr ? NameStr : L"(null)",
        DesiredAccess, (unsigned)AccessMode);

    if (NameStr && _wcsicmp(NameStr, L"\\Device\\PhysicalMemory") == 0) {
        *HostHandle = SectionHandleManager::AllocateHandle();
        Logger::Log("{GRN}\t-> PhysicalMemory fake handle %p{RESET}\n", *HostHandle);
        return STATUS_SUCCESS;
    }

    _IO_STATUS_BLOCK Isb = {};
    NTSTATUS Ret = __NtRoutine("NtOpenFile", HostHandle,
        DesiredAccess | SYNCHRONIZE, &LocalOa, &Isb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0x00000020);

    if (Ret < 0) {
        NTSTATUS SecRet = __NtRoutine("ZwOpenSection", HostHandle, DesiredAccess, &LocalOa);
        if (SecRet >= 0)
            Ret = SecRet;
    }

    Logger::Log("{GRY}\t-> %08x{RESET}\n", Ret);
    return Ret;
}

NTSTATUS h_ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    void* AccessState,
    ACCESS_MASK DesiredAccess,
    void* ObjectType,
    uint8_t AccessMode,
    void* ParseContext,
    PVOID* Object)
{
    auto HostName = UcPtr(ObjectName);
    PWSTR Buf = nullptr;
    if (HostName && HostName->Buffer) {
        Buf = UcPtr(HostName->Buffer);
    }
    Logger::Log("{CYN}\tObReferenceObjectByName: %ls access=%08x{RESET}\n",
        Buf ? Buf : L"(null)", DesiredAccess);
    if (Object) {
        auto HostObj = UcPtr(Object);
        *HostObj = nullptr;
    }
    return 0xC0000034;
}

NTSTATUS h_ObOpenObjectByPointerWithTag(
    PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState,
    ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint8_t AccessMode,
    ULONG Tag, PHANDLE Handle)
{
    Logger::Log("{CYN}\tObOpenObjectByPointerWithTag: object=%p tag=%08x{RESET}\n", Object, Tag);
    if (Handle) {
        auto HostHandle = UcPtr(Handle);
        *HostHandle = nullptr;
    }
    return 0xC0000034;
}
