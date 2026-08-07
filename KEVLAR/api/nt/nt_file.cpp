#include "nt_file.h"
#include "core/registry/virtual_fs.h"
#include "core/object/handle_manager.h"
#include "nt_memory.h"

NTSTATUS h_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    Logger::Log("  {YEL}ZwCreateFile: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

    std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";

    if (!LocalPath.empty()) {
        bool IsCreate = (CreateDisposition == 0 || CreateDisposition == 2 || CreateDisposition == 3 || CreateDisposition == 5);
        bool Exists = VirtualFs::LocalExists(LocalPath);

        if (IsCreate || Exists) {
            HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, FileAttributes, ShareAccess, CreateDisposition, CreateOptions);
            if (H != INVALID_HANDLE_VALUE) {
                *HostHandle = H;
                if (HostIsb) {
                    auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                    Isb->Status = 0;
                    Isb->Information = Exists ? 1 : 2;
                }
                Logger::Log("  {GRN}VFS: created/opened {WHT}%ls {GRN}-> handle {WHT}%p{RESET}\n", LocalPath.c_str(), H);
                return 0;
            }
            Logger::Log("  {YEL}VFS: CreateFile failed for %ls (err=%d), falling through{RESET}\n", LocalPath.c_str(), GetLastError());
        }

        if (CreateDisposition == 1 || CreateDisposition == 4) {
            std::wstring RewrittenStorage;
            UNICODE_STRING RewrittenName = {};
            RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
            ULONG SafeOptions = CreateOptions & ~(0x00010000);
            ACCESS_MASK SafeAccess = DesiredAccess;
            if (SafeOptions & (0x10 | 0x20))
                SafeAccess |= SYNCHRONIZE;
            auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocationSize, FileAttributes, ShareAccess,
                CreateDisposition, SafeOptions, EaBuffer, EaLength);
            Logger::Log("  {GRY}OS fallback return: {WHT}%08x{RESET}\n", Ret);
            return Ret;
        }
    }

    std::wstring RewrittenStorage;
    UNICODE_STRING RewrittenName = {};
    RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);
    ULONG SafeOptions = CreateOptions & ~(0x00010000);
    ACCESS_MASK SafeAccess = DesiredAccess;
    if (SafeOptions & (0x10 | 0x20))
        SafeAccess |= SYNCHRONIZE;
    auto Ret = __NtRoutine("NtCreateFile", HostHandle, SafeAccess, &LocalOa, HostIsb, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, SafeOptions, EaBuffer, EaLength);
    Logger::Log("  {GRY}Return: {WHT}%08x{RESET}\n", Ret);
    return Ret;
}

NTSTATUS h_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) {
    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostBuf = UcPtr(Buffer);
    auto HostOffset = UcPtr(ByteOffset);
    auto HostKey = UcPtr(Key);
    auto Ret = __NtRoutine("NtReadFile", FileHandle, Event, ApcRoutine, ApcContext, HostIsb, HostBuf, Length, HostOffset, HostKey);
    Logger::Log("{CYN}\tNtReadFile: handle=%p len=%u ret=%08x{RESET}\n", FileHandle, Length, Ret);
    return Ret;
}

NTSTATUS h_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) {
    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostBuf = UcPtr(Buffer);
    auto HostOffset = UcPtr(ByteOffset);
    auto HostKey = UcPtr(Key);
    auto Ret = __NtRoutine("NtWriteFile", FileHandle, Event, ApcRoutine, ApcContext, HostIsb, HostBuf, Length, HostOffset, HostKey);
    return Ret;
}

NTSTATUS h_ZwFlushBuffersFile(HANDLE FileHandle, PVOID IoStatusBlock) {
    auto HostIsb = UcPtr(IoStatusBlock);
    return __NtRoutine("NtFlushBuffersFile", FileHandle, HostIsb);
}

NTSTATUS h_ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
    PVOID IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    auto HostHandle = UcPtr(FileHandle);
    auto HostIsb = UcPtr(IoStatusBlock);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    Logger::Log("{CYN}\tZwOpenFile: %ls{RESET}\n", PathStr ? PathStr : L"(null)");

    std::wstring LocalPath = PathStr ? VirtualFs::NtPathToLocalW(PathStr) : L"";

    if (!LocalPath.empty() && VirtualFs::LocalExists(LocalPath)) {
        HANDLE H = VirtualFs::CreateLocalFile(LocalPath, DesiredAccess, 0, ShareAccess, 1, OpenOptions);
        if (H != INVALID_HANDLE_VALUE) {
            *HostHandle = H;
            if (HostIsb) {
                auto Isb = (_IO_STATUS_BLOCK*)HostIsb;
                Isb->Status = 0;
                Isb->Information = 1;
            }
            Logger::Log("  {GRN}VFS: opened {WHT}%ls {GRN}-> handle {WHT}%p{RESET}\n", LocalPath.c_str(), H);
            return 0;
        }
    }

    std::wstring RewrittenStorage;
    UNICODE_STRING RewrittenName = {};
    RewriteSystemRootPath(LocalOa, RewrittenName, RewrittenStorage);

    ULONG SafeOptions = OpenOptions & ~(0x00010000);
    ACCESS_MASK SafeAccess = DesiredAccess;
    if (SafeOptions & (0x10 | 0x20))
        SafeAccess |= SYNCHRONIZE;

    auto Ret = __NtRoutine("NtOpenFile", HostHandle, SafeAccess, &LocalOa, HostIsb, ShareAccess, SafeOptions);
    Logger::Log("{GRY}\tReturn: %08x{RESET}\n", Ret);
    return Ret;
}

NTSTATUS h_ZwSetInformationFile(HANDLE FileHandle, PVOID IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass) {
    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostInfo = UcPtr(FileInformation);
    return (NTSTATUS)__NtRoutine("NtSetInformationFile", FileHandle, HostIsb, HostInfo, Length, FileInformationClass);
}

NTSTATUS h_ZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {
    auto HostHandle = UcPtr(SectionHandle);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* NameStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;

    if (NameStr && _wcsicmp(NameStr, L"\\Device\\PhysicalMemory") == 0) {
        *HostHandle = SectionHandleManager::AllocateHandle();
        Logger::Log("{GRN}\tZwOpenSection: %ls -> fake handle %p{RESET}\n", NameStr, *HostHandle);
        return STATUS_SUCCESS;
    }

    auto Ret = __NtRoutine("ZwOpenSection", HostHandle, DesiredAccess, &LocalOa);
    Logger::Log("{CYN}\tSection name : %ls, access : %llx, ret : %08x{RESET}\n", NameStr ? NameStr : L"(null)", DesiredAccess, Ret);
    return Ret;
}

NTSTATUS h_ZwDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID  ApcRoutine,
     PVOID            ApcContext,
     PVOID IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
   ULONG            InputBufferLength,
    PVOID            OutputBuffer,
   ULONG            OutputBufferLength
) {
    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostInBuf = UcPtr(InputBuffer);
    auto HostOutBuf = UcPtr(OutputBuffer);
    auto Ret = __NtRoutine("NtDeviceIoControlFile", FileHandle, Event, ApcRoutine, ApcContext, HostIsb, IoControlCode, HostInBuf, InputBufferLength, HostOutBuf, OutputBufferLength);
    Logger::Log("{CYN}\tHandle : %llx{RESET}\n", FileHandle);
    Logger::Log("{CYN}\tEvent : %llx{RESET}\n", Event);
    Logger::Log("{CYN}\tAPC Routine : %llx{RESET}\n", ApcRoutine);
    Logger::Log("{CYN}\tIOCTL : %llx{RESET}\n", IoControlCode);
    Logger::Log("{CYN}\tLen : %d Buffer : {RESET}\n\t", InputBufferLength);
    Logger::Log("{GRY}\tRet : %llx{RESET}\n", Ret);

    return Ret;
}

NTSTATUS h_ZwClose(HANDLE Handle) {
    Logger::Log("{CYN}\tClosing Kernel Handle : %llx{RESET}\n", Handle);
    if (!Handle)
        return STATUS_SUCCESS;
    if (VRegHandleManager::IsVRegHandle(Handle)) {
        VRegHandleManager::FreeHandle(Handle);
        return STATUS_SUCCESS;
    }
    if (SectionHandleManager::IsSectionHandle(Handle)) {
        SectionHandleManager::FreeHandle(Handle);
        return STATUS_SUCCESS;
    }
    if ((uintptr_t)Handle >= 0xFFFF000000000000ULL) {
        Logger::Log("{GRY}\tZwClose: skipping UC-space handle 0x%llx{RESET}\n", Handle);
        return STATUS_SUCCESS;
    }
    if (HandleManager::GetHandle((uintptr_t)Handle)) {
        Logger::Log("{GRY}\tZwClose: skipping HandleManager-tracked handle 0x%llx{RESET}\n", Handle);
        return STATUS_SUCCESS;
    }
    __try {
        NTSTATUS Ret = __NtRoutine("NtClose", Handle);
        if (Ret >= 0)
            return STATUS_SUCCESS;
        if (Ret == (NTSTATUS)0xC0000008 || Ret == (NTSTATUS)0xC000008A)
            return STATUS_SUCCESS;
        return Ret;
    }
    __except (1) {
        return STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}

NTSTATUS h_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PVOID IoStatusBlock, PVOID FileInformation, ULONG Length, uint32_t FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {

    auto HostIsb = UcPtr(IoStatusBlock);
    auto HostInfo = UcPtr(FileInformation);
    PUNICODE_STRING HostFileName = nullptr;
    UNICODE_STRING LocalFileName = {};

    if (FileName) {
        auto UcFileName = UcPtr(FileName);
        if (UcFileName && UcFileName->Buffer) {
            LocalFileName.Buffer = UcPtr(UcFileName->Buffer);
            LocalFileName.Length = UcFileName->Length;
            LocalFileName.MaximumLength = UcFileName->MaximumLength;
            HostFileName = &LocalFileName;
        }
    }

    Logger::Log("  {GRY}NtQueryDirectoryFile: handle=%p class=%u len=%u{RESET}\n",
        FileHandle, FileInformationClass, Length);

    auto Ret = __NtRoutine("NtQueryDirectoryFile", FileHandle, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        HostIsb, HostInfo, Length, FileInformationClass, ReturnSingleEntry, HostFileName, RestartScan);
    return Ret;
}

NTSTATUS h_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes) {
    auto HostHandle = UcPtr(DirectoryHandle);
    OBJECT_ATTRIBUTES LocalOa; UNICODE_STRING LocalName;
    TranslateObjAttr(ObjectAttributes, LocalOa, LocalName);

    const wchar_t* PathStr = LocalOa.ObjectName ? LocalOa.ObjectName->Buffer : nullptr;
    Logger::Log("  {GRY}NtOpenDirectoryObject: {WHT}%ls{RESET}\n", PathStr ? PathStr : L"(null)");

    auto Ret = __NtRoutine("NtOpenDirectoryObject", HostHandle, DesiredAccess, &LocalOa);
    return Ret;
}
