#include <cstring>

#include <PEMapper/pefile.h>

#include <Logger/Logger.h>

#include "core/loader/kernel_structs.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/loader/environment.h"
#include "include/kernel_layout_consume.h"

#include "host/providers/ntoskrnl_provider.h"

const wchar_t* DriverName = L"\\Driver\\MyDriver";
const wchar_t* RegistryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\MyDriver";
std::wstring DriverBaseName;
std::wstring DriverFullPath;

void PopulateKernelStructs() {
    drvObj.Type = 4;
    drvObj.Size = sizeof(drvObj);
    drvObj.Flags = 0x12;
    drvObj.DriverName.Buffer = (WCHAR*)DriverName;
    drvObj.DriverName.Length = (USHORT)(lstrlenW(DriverName) * 2);
    drvObj.DriverName.MaximumLength = drvObj.DriverName.Length + 2;

    RegistryPath.Buffer = (WCHAR*)RegistryBuffer;
    RegistryPath.Length = (USHORT)(lstrlenW(RegistryPath.Buffer) * 2);
    RegistryPath.MaximumLength = RegistryPath.Length + 2;

    memset(&FakeKernelThread, 0, sizeof(FakeKernelThread));
    memset(&FakeSystemProcess, 0, sizeof(FakeSystemProcess));
    memset(&FakeKPCR, 0, sizeof(FakeKPCR));
    memset(&FakeCPU, 0, sizeof(FakeCPU));

    uint64_t ThreadWlhUcAddr = ETHREAD_BASE_UC + offsetof(_ETHREAD, Tcb.Header.WaitListHead);
    FakeKernelThread.Tcb.Header.WaitListHead.Flink = (PLIST_ENTRY)ThreadWlhUcAddr;
    FakeKernelThread.Tcb.Header.WaitListHead.Blink = (PLIST_ENTRY)ThreadWlhUcAddr;
    uint64_t ApcList0Uc = ETHREAD_BASE_UC + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[0]);
    FakeKernelThread.Tcb.ApcState.ApcListHead[0].Flink = (PLIST_ENTRY)ApcList0Uc;
    FakeKernelThread.Tcb.ApcState.ApcListHead[0].Blink = (PLIST_ENTRY)ApcList0Uc;
    uint64_t ApcList1Uc = ETHREAD_BASE_UC + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[1]);
    FakeKernelThread.Tcb.ApcState.ApcListHead[1].Flink = (PLIST_ENTRY)ApcList1Uc;
    FakeKernelThread.Tcb.ApcState.ApcListHead[1].Blink = (PLIST_ENTRY)ApcList1Uc;
    uint64_t ProcWlhUcAddr = EPROCESS_BASE_UC + offsetof(_EPROCESS, Pcb.Header.WaitListHead);
    FakeSystemProcess.Pcb.Header.WaitListHead.Flink = (PLIST_ENTRY)ProcWlhUcAddr;
    FakeSystemProcess.Pcb.Header.WaitListHead.Blink = (PLIST_ENTRY)ProcWlhUcAddr;

    FakeKernelThread.Tcb.Process = (_KPROCESS*)EPROCESS_BASE_UC;
    FakeKernelThread.Tcb.ApcState.Process = (_KPROCESS*)EPROCESS_BASE_UC;

    EthreadCid(&FakeKernelThread)->UniqueProcess = (void*)4;
    EthreadCid(&FakeKernelThread)->UniqueThread = (void*)0x8;

    FakeKernelThread.Tcb.PreviousMode = 0;
    FakeKernelThread.Tcb.State = 1;
    FakeKernelThread.Tcb.InitialStack = (void*)(STACK_BASE_UC + STACK_SIZE_UC);
    FakeKernelThread.Tcb.StackBase = (void*)(STACK_BASE_UC + STACK_SIZE_UC);
    FakeKernelThread.Tcb.StackLimit = (void*)STACK_BASE_UC;
    FakeKernelThread.Tcb.ThreadLock = 11;
    FakeKernelThread.Tcb.LockEntries = (_KLOCK_ENTRY*)22;
    FakeKernelThread.Tcb.MiscFlags |= 0x400;

    *EprocUniqueProcessId(&FakeSystemProcess) = (void*)4;
    *EprocProtection(&FakeSystemProcess) = 7;
    *EprocWow64Process(&FakeSystemProcess) = nullptr;
    EprocCreateTime(&FakeSystemProcess)->QuadPart = GetTickCount64();

    FakeCPU.CurrentThread = (_KTHREAD*)ETHREAD_BASE_UC;
    FakeCPU.IdleThread = (_KTHREAD*)ETHREAD_BASE_UC;
    FakeCPU.CoresPerPhysicalProcessor = 2;
    FakeCPU.LogicalProcessorsPerCore = 2;
    FakeCPU.MajorVersion = 10;
    FakeCPU.MinorVersion = 0;
    FakeCPU.RspBase = STACK_BASE_UC + STACK_SIZE_UC;

    if (UnicornEmu::IntelCpuSpoofEnabled) {
        FakeCPU.CpuType = 6;
        FakeCPU.CpuStepping = 1;
        FakeCPU.CpuModel = 0xB7;
        FakeCPU.MHz = 3000;
        FakeCPU.CpuVendor = 1;
        FakeCPU.CoresPerPhysicalProcessor = 8;
        FakeCPU.LogicalProcessorsPerCore = 2;
        FakeCPU.ProcessorSignature = 0x000B0671;
    }

    FakeKPCR.CurrentPrcb = (_KPRCB*)(KPCR_BASE_UC + KPCR_PRCB_OFFSET);
    FakeKPCR.NtTib.StackBase = (PVOID)(STACK_BASE_UC + STACK_SIZE_UC);
    FakeKPCR.NtTib.StackLimit = (PVOID)STACK_BASE_UC;
    FakeKPCR.MajorVersion = 10;
    FakeKPCR.MinorVersion = 0;
    FakeKPCR.Self = (_KPCR*)KPCR_BASE_UC;
}

void SetupDriverLdrEntry(PEFile* MainModule) {
    uint64_t LdrEntryUcAddr = UnicornMem::AllocateVariable(
        UnicornEmu::PrimaryEngine, sizeof(KLDR_DATA_TABLE_ENTRY) + 0x400, "DriverKldrEntry");
    auto KldrEntryHost = (PKLDR_DATA_TABLE_ENTRY)UnicornMem::UcToHost(LdrEntryUcAddr);

    memset(KldrEntryHost, 0, sizeof(KLDR_DATA_TABLE_ENTRY));

    const wchar_t* FullDllPath = DriverFullPath.empty() ? L"\\SystemRoot\\system32\\drivers\\MyDriver.sys" : DriverFullPath.c_str();
    const wchar_t* BaseName = DriverBaseName.empty() ? L"MyDriver.sys" : DriverBaseName.c_str();
    size_t PathBytes = (wcslen(FullDllPath) + 1) * sizeof(wchar_t);

    uint64_t StringBufOffset = sizeof(KLDR_DATA_TABLE_ENTRY);
    StringBufOffset = (StringBufOffset + 0xF) & ~0xFULL;

    memcpy((uint8_t*)KldrEntryHost + StringBufOffset, FullDllPath, PathBytes);

    uint64_t StringBufUcAddr = LdrEntryUcAddr + StringBufOffset;
    KldrEntryHost->FullDllName.Buffer = (wchar_t*)StringBufUcAddr;
    KldrEntryHost->FullDllName.Length = (USHORT)(wcslen(FullDllPath) * sizeof(wchar_t));
    KldrEntryHost->FullDllName.MaximumLength = KldrEntryHost->FullDllName.Length + sizeof(wchar_t);

    const wchar_t* BaseDllName = BaseName;
    size_t BasePathBytes = (wcslen(BaseDllName) + 1) * sizeof(wchar_t);
    uint64_t BaseStrOffset = StringBufOffset + PathBytes;
    BaseStrOffset = (BaseStrOffset + 0xF) & ~0xFULL;
    memcpy((uint8_t*)KldrEntryHost + BaseStrOffset, BaseDllName, BasePathBytes);
    KldrEntryHost->BaseDllName.Buffer = (wchar_t*)(LdrEntryUcAddr + BaseStrOffset);
    KldrEntryHost->BaseDllName.Length = (USHORT)(wcslen(BaseDllName) * sizeof(wchar_t));
    KldrEntryHost->BaseDllName.MaximumLength = KldrEntryHost->BaseDllName.Length + sizeof(wchar_t);

    KldrEntryHost->DllBase = (PVOID)DRIVER_BASE_UC;
    KldrEntryHost->SizeOfImage = (ULONG)MainModule->GetVirtualSize();
    KldrEntryHost->SizeOfImageNotRounded = (ULONG)MainModule->GetVirtualSize();
    KldrEntryHost->EntryPoint = (PVOID)(DRIVER_BASE_UC + MainModule->GetEP());
    KldrEntryHost->LoadCount = 1;
    KldrEntryHost->u1.EntireField = 0x0026;

    auto HostBase = (uint8_t*)MainModule->GetMappedImageBase();
    auto Dos = (PIMAGE_DOS_HEADER)HostBase;
    auto Nt = (PIMAGE_NT_HEADERS)(HostBase + Dos->e_lfanew);
    auto& ExcDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ExcDir.VirtualAddress && ExcDir.Size) {
        KldrEntryHost->ExceptionTable = (PVOID)(DRIVER_BASE_UC + ExcDir.VirtualAddress);
        KldrEntryHost->ExceptionTableSize = ExcDir.Size;
    }
    KldrEntryHost->CheckSum = Nt->OptionalHeader.CheckSum;
    KldrEntryHost->TimeDateStamp = Nt->FileHeader.TimeDateStamp;

    uint64_t SentinelUc = (uint64_t)Environment::PsLoadedModuleList;
    if (SentinelUc) {
        auto SentinelHost = (LIST_ENTRY*)UnicornMem::UcToHost(SentinelUc);
        if (SentinelHost) {
            uint64_t LastUc = (uint64_t)SentinelHost->Blink;
            auto LastHost = (LIST_ENTRY*)UnicornMem::UcToHost(LastUc);

            KldrEntryHost->InLoadOrderLinks.Flink = (LIST_ENTRY*)SentinelUc;
            KldrEntryHost->InLoadOrderLinks.Blink = (LIST_ENTRY*)LastUc;

            if (LastHost)
                LastHost->Flink = (LIST_ENTRY*)LdrEntryUcAddr;
            SentinelHost->Blink = (LIST_ENTRY*)LdrEntryUcAddr;

            Logger::Log("{GRY}SetupDriverLdrEntry: inserted at UC {WHT}0x%llx {GRY}into PsLoadedModuleList{RESET}\n", LdrEntryUcAddr);
        } else {
            uint64_t LdrLinkUcAddr = LdrEntryUcAddr + offsetof(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            KldrEntryHost->InLoadOrderLinks.Flink = (LIST_ENTRY*)LdrLinkUcAddr;
            KldrEntryHost->InLoadOrderLinks.Blink = (LIST_ENTRY*)LdrLinkUcAddr;
            Logger::Log("{YEL}SetupDriverLdrEntry: sentinel host lookup failed, isolated entry{RESET}\n");
        }
    } else {
        uint64_t LdrLinkUcAddr = LdrEntryUcAddr + offsetof(KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        KldrEntryHost->InLoadOrderLinks.Flink = (LIST_ENTRY*)LdrLinkUcAddr;
        KldrEntryHost->InLoadOrderLinks.Blink = (LIST_ENTRY*)LdrLinkUcAddr;
        Logger::Log("{YEL}SetupDriverLdrEntry: no PsLoadedModuleList, isolated entry{RESET}\n");
    }

    drvObj.DriverSection = (PVOID)LdrEntryUcAddr;
}
