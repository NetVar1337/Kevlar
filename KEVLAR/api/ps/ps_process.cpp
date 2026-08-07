#include "include/common.h"
#include "include/kernel_layout_consume.h"
#include "ps_process.h"
#include <unordered_map>
#include <mutex>

_ETHREAD* h_KeGetCurrentThread();

static std::mutex FakeProcessLock;
static std::unordered_map<uint64_t, uint64_t> FakeProcessMap;

PVOID h_PsGetProcessWow64Process(_EPROCESS* Process) {
    auto HostProc = UcPtr(Process);
    Logger::Log("{CYN}\tRequesting WoW64 for process : %llx (id : %llx){RESET}\n", (const PVOID)Process, *EprocUniqueProcessId(HostProc));
    return *EprocWow64Process(HostProc);
}

static std::unordered_map<uint64_t, uint64_t> FakeThreadMap;
static constexpr uint64_t THREAD_MAP_MISS = (uint64_t)-1;

NTSTATUS h_PsLookupThreadByThreadId(HANDLE ThreadId, PVOID* Thread) {
    auto HostThread = UcPtr(Thread);

    if (ThreadId == (HANDLE)4) {
        *HostThread = (PVOID)ETHREAD_BASE_UC;
        return 0;
    }

    uint64_t Tid = (uint64_t)(uintptr_t)ThreadId;

    {
        std::lock_guard<std::mutex> Lock(FakeProcessLock);
        auto It = FakeThreadMap.find(Tid);
        if (It != FakeThreadMap.end()) {
            if (It->second == THREAD_MAP_MISS) {
                *HostThread = nullptr;
                return (NTSTATUS)0xC000000B;
            }
            *HostThread = (PVOID)It->second;
            return 0;
        }
    }

    HANDLE OsHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)Tid);
    if (!OsHandle && GetLastError() != ERROR_ACCESS_DENIED) {
        std::lock_guard<std::mutex> Lock(FakeProcessLock);
        FakeThreadMap[Tid] = THREAD_MAP_MISS;
        *HostThread = nullptr;
        return (NTSTATUS)0xC000000B;
    }
    if (OsHandle)
        CloseHandle(OsHandle);

    auto Uc = UnicornThread::GetCurrentEngine();
    uint64_t UcAddr = UnicornMem::AllocateVariable(Uc, sizeof(_ETHREAD), "FakeETHREAD");
    if (!UcAddr) {
        *HostThread = nullptr;
        return STATUS_INVALID_PARAMETER;
    }

    auto HostEthread = (_ETHREAD*)UnicornMem::UcToHost(UcAddr);
    memset(HostEthread, 0, sizeof(_ETHREAD));
    EthreadCid(HostEthread)->UniqueProcess = (HANDLE)4;
    EthreadCid(HostEthread)->UniqueThread = (HANDLE)(uintptr_t)Tid;
    *(void**)((uint8_t*)HostEthread + ETHREAD_Tcb_Process) = (void*)EPROCESS_BASE_UC;
    *(void**)((uint8_t*)HostEthread + ETHREAD_Tcb_ApcState_Process) = (void*)EPROCESS_BASE_UC;

    uint64_t ThreadWlh = UcAddr + offsetof(_ETHREAD, Tcb.Header.WaitListHead);
    HostEthread->Tcb.Header.WaitListHead.Flink = (PLIST_ENTRY)ThreadWlh;
    HostEthread->Tcb.Header.WaitListHead.Blink = (PLIST_ENTRY)ThreadWlh;
    uint64_t ApcList0 = UcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[0]);
    HostEthread->Tcb.ApcState.ApcListHead[0].Flink = (PLIST_ENTRY)ApcList0;
    HostEthread->Tcb.ApcState.ApcListHead[0].Blink = (PLIST_ENTRY)ApcList0;
    uint64_t ApcList1 = UcAddr + offsetof(_ETHREAD, Tcb.ApcState.ApcListHead[1]);
    HostEthread->Tcb.ApcState.ApcListHead[1].Flink = (PLIST_ENTRY)ApcList1;
    HostEthread->Tcb.ApcState.ApcListHead[1].Blink = (PLIST_ENTRY)ApcList1;

    {
        std::lock_guard<std::mutex> Lock(FakeProcessLock);
        FakeThreadMap[Tid] = UcAddr;
    }

    *HostThread = (PVOID)UcAddr;
    Logger::Log("{GRY}\tPsLookupThreadByThreadId: TID %llu -> fake ETHREAD 0x%llx{RESET}\n", Tid, UcAddr);
    return 0;
}

HANDLE h_PsGetThreadId(_ETHREAD* Thread) {
    if (Thread) {
        auto HostThread = UcPtr(Thread);
        return EthreadCid(HostThread)->UniqueThread;
    }
    return 0;
}

_PEB* h_PsGetProcessPeb(_EPROCESS* process) {
    auto HostProc = UcPtr(process);
    return HostProc->Peb;
}

HANDLE h_PsGetProcessInheritedFromUniqueProcessId(_EPROCESS* Process) {
    auto HostProc = UcPtr(Process);
    return HostProc->InheritedFromUniqueProcessId;
}

LONGLONG h_PsGetProcessCreateTimeQuadPart(_EPROCESS* process) {
    auto HostProc = UcPtr(process);
    Logger::Log("{GRY}\t\tTrying to get creation time for %llx{RESET}\n", (const void*)process);
    return EprocCreateTime(HostProc)->QuadPart;
}

NTSTATUS h_PsLookupProcessByProcessId(HANDLE ProcessId, _EPROCESS** Process) {

    auto HostProcess = UcPtr(Process);
    if (ProcessId == (HANDLE)4) {
        *HostProcess = (_EPROCESS*)EPROCESS_BASE_UC;
        return 0;
    }

    uint64_t Pid = (uint64_t)ProcessId;

    {
        std::lock_guard<std::mutex> Lock(FakeProcessLock);
        auto It = FakeProcessMap.find(Pid);
        if (It != FakeProcessMap.end()) {
            *HostProcess = (_EPROCESS*)It->second;
            return 0;
        }
    }

    auto Uc = UnicornThread::GetCurrentEngine();
    uint64_t UcAddr = UnicornMem::AllocateVariable(Uc, sizeof(_EPROCESS), "FakeEPROCESS");
    if (!UcAddr) {
        *HostProcess = nullptr;
        return 0xC000000B;
    }

    auto HostEproc = (_EPROCESS*)UnicornMem::UcToHost(UcAddr);
    memset(HostEproc, 0, sizeof(_EPROCESS));
    *EprocUniqueProcessId(HostEproc) = (void*)Pid;
    *EprocProtection(HostEproc) = 0;
    *EprocWow64Process(HostEproc) = nullptr;
    EprocCreateTime(HostEproc)->QuadPart = GetTickCount64();
    memcpy(EprocImageFileName(HostEproc), "svchost.exe", 12);
    uint64_t ProcWlhUcAddr = UcAddr + offsetof(_EPROCESS, Pcb.Header.WaitListHead);
    HostEproc->Pcb.Header.WaitListHead.Flink = (PLIST_ENTRY)ProcWlhUcAddr;
    HostEproc->Pcb.Header.WaitListHead.Blink = (PLIST_ENTRY)ProcWlhUcAddr;

    {
        std::lock_guard<std::mutex> Lock(FakeProcessLock);
        FakeProcessMap[Pid] = UcAddr;
    }

    *HostProcess = (_EPROCESS*)UcAddr;
    Logger::Log("{GRY}\tPsLookupProcessByProcessId: PID %llu -> fake EPROCESS 0x%llx{RESET}\n", Pid, UcAddr);
    return 0;
}

HANDLE h_PsGetProcessId(_EPROCESS* Process) {

    if (!Process)
        return 0;

    auto HostProc = UcPtr(Process);
    return *EprocUniqueProcessId(HostProc);
}

_EPROCESS* h_PsGetCurrentProcess() {
    auto Thread = h_KeGetCurrentThread();
    auto Val = (_EPROCESS*)Thread->Tcb.ApcState.Process;
    Logger::Log("{GRY}\tReturning : %llx{RESET}\n", Val);
    return Val;
}

_EPROCESS* h_PsGetCurrentThreadProcess() { return (_EPROCESS*)h_KeGetCurrentThread()->Tcb.Process; }

HANDLE h_PsGetCurrentThreadId() { return EthreadCid(h_KeGetCurrentThread())->UniqueThread; }

HANDLE h_PsGetCurrentThreadProcessId() {
    //Logger::Log("About to do stuff\n");
    auto meh = EthreadCid(h_KeGetCurrentThread())->UniqueProcess;
    //Logger::Log("Done\n");
    return meh;
}

bool h_PsIsProtectedProcess(_EPROCESS* process) {
    auto HostProc = UcPtr(process);
    if (*EprocUniqueProcessId(HostProc) == (PVOID)4) {
        return true;
    }
    return (*EprocProtection(HostProc) & 7) != 0;
}

PACCESS_TOKEN h_PsReferencePrimaryToken(_EPROCESS* Process) {
    auto HostProc = UcPtr(Process);
    _EX_FAST_REF* a1 = &HostProc->Token;
    auto Value = a1->Value;
    signed __int64 v3;
    signed __int64 v4; // rdi
    unsigned int v5; // r8d
    unsigned __int64 v6; // rdi

    if ((a1->Value & 0xF) != 0) {
        do {
            v3 = _InterlockedCompareExchange64((volatile long long*)a1, Value - 1, Value);
            if (Value == v3)
                break;
            Value = v3;
        } while ((v3 & 0xF) != 0);
    }
    v4 = Value;
    v5 = Value & 0xF;
    v6 = v4 & 0xFFFFFFFFFFFFFFF0ui64;
    if (v5 > 1)
        a1 = (_EX_FAST_REF*)v6;

    Logger::Log("{GRY}\tReturning Token : %llx{RESET}\n", (const void*)a1);
    return a1;
}

NTSTATUS h_PsRemoveLoadImageNotifyRoutine(void* NotifyRoutine) { return STATUS_PROCEDURE_NOT_FOUND; }

NTSTATUS h_PsSetCreateProcessNotifyRoutineEx(void* NotifyRoutine, BOOLEAN Remove) {
    if (Remove) {
        return STATUS_INVALID_PARAMETER;
    } else {
        return STATUS_SUCCESS;
    }
}

NTSTATUS h_PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, HANDLE ProcessHandle, void* ClientId,
    void* StartRoutine, PVOID StartContext) {
    ThreadContext* Ctx = nullptr;
    __try {
        Ctx = UnicornThread::Create((uint64_t)StartRoutine, (uint64_t)StartContext, ThreadHandle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}PsCreateSystemThread: exception 0x%08x creating thread for routine 0x%llx{RESET}\n",
            GetExceptionCode(), (uint64_t)StartRoutine);
        return STATUS_NO_MEMORY;
    }
    if (!Ctx)
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}

//todo impl
NTSTATUS h_PsTerminateSystemThread(NTSTATUS exitstatus) {
    Logger::Log("{MAG}\tthread boom{RESET}\n");

    ExitThread(exitstatus);
}

NTSTATUS h_PsSetCreateThreadNotifyRoutine(PVOID NotifyRoutine) { return STATUS_SUCCESS; }

NTSTATUS h_PsSetLoadImageNotifyRoutine(PVOID NotifyRoutine) { return STATUS_SUCCESS; }

HANDLE h_PsGetThreadProcessId(_ETHREAD* Thread) {
    if (Thread) {
        auto HostThread = UcPtr(Thread);
        return EthreadCid(HostThread)->UniqueProcess;
    }
    return 0;
}

HANDLE h_PsGetThreadProcess(_ETHREAD* Thread) {
    if (Thread) {
        auto HostThread = UcPtr(Thread);
        return (HANDLE)HostThread->Tcb.Process;
    }
    return 0;
}

char* h_PsGetProcessImageFileName(_EPROCESS* Process) {
    static char FakeImageName[16] = "System";
    auto HostProc = UcPtr(Process);
    if (*EprocUniqueProcessId(HostProc) == (HANDLE)4) {
        return FakeImageName;
    }
    return FakeImageName;
}

BOOLEAN h_PsIsSystemThread(_ETHREAD* Thread) {
    auto HostThread = UcPtr(Thread);
    return (HostThread->Tcb.MiscFlags & 0x400) != 0;
}

static BOOLEAN ExfAcquireRundownProtectionImpl(volatile LONG64* Count) {
    LONG64 cur = *Count;
    if (cur & 1)
        return FALSE;

    while (true) {
        LONG64 prev = _InterlockedCompareExchange64(Count, cur + 2, cur);
        if (prev == cur)
            return TRUE;
        cur = prev;
        if (cur & 1)
            return FALSE;
    }
}

static BOOLEAN ExAcquireRundownProtectionImpl(volatile LONG64* Count) {
    _mm_prefetch((const char*)Count, _MM_HINT_T0);

    LONG64 expected = *Count & ~1LL;
    if (_InterlockedCompareExchange64(Count, expected + 2, expected) == expected)
        return TRUE;

    return ExfAcquireRundownProtectionImpl(Count);
}

static void ExReleaseRundownProtectionImpl(volatile LONG64* Count) {
    LONG64 cur = *Count;
    while (true) {
        LONG64 prev = _InterlockedCompareExchange64(Count, cur - 2, cur);
        if (prev == cur)
            break;
        cur = prev;
    }
}

NTSTATUS h_PsAcquireProcessExitSynchronization(_EPROCESS* Process) {
    auto HostProc = UcPtr(Process);
    if (!HostProc)
        return STATUS_PROCESS_IS_TERMINATING;

    auto RunRef = reinterpret_cast<volatile LONG64*>((uint8_t*)HostProc + EPROCESS_RUNDOWN_PROTECT);

    return ExAcquireRundownProtectionImpl(RunRef) ? STATUS_SUCCESS : STATUS_PROCESS_IS_TERMINATING; // 0xC000010A
}

void h_PsReleaseProcessExitSynchronization(_EPROCESS* Process) {
    auto HostProc = UcPtr(Process);
    if (!HostProc)
        return;

    auto RunRef = reinterpret_cast<volatile LONG64*>((uint8_t*)HostProc + EPROCESS_RUNDOWN_PROTECT);

    ExReleaseRundownProtectionImpl(RunRef);
}

NTSTATUS h_PsSetCreateProcessNotifyRoutineEx2(uint32_t NotifyType, PVOID NotifyInformation, BOOLEAN Remove) {
    return STATUS_SUCCESS;
}

NTSTATUS h_PsSuspendProcess(void* Process) {
    Logger::Log("{MAG}\tPsSuspendProcess: process=%p{RESET}\n", Process);
    return 0;
}

NTSTATUS h_PsResumeProcess(void* Process) {
    Logger::Log("{MAG}\tPsResumeProcess: process=%p{RESET}\n", Process);
    return 0;
}

void* h_PsGetProcessSectionBaseAddress(void* Process) {
    Logger::Log("{CYN}\tPsGetProcessSectionBaseAddress: process=%p{RESET}\n", Process);
    return nullptr;
}

NTSTATUS h_PsGetProcessExitStatus(void* Process) {
    Logger::Log("{CYN}\tPsGetProcessExitStatus: process=%p{RESET}\n", Process);
    return 0x103;
}

void* h_PsGetProcessWin32Process(void* Process) {
    Logger::Log("{CYN}\tPsGetProcessWin32Process: process=%p{RESET}\n", Process);
    return nullptr;
}
