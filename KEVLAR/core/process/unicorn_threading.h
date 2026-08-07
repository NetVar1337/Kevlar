#pragma once

#include <unicorn/unicorn.h>
#include <windows.h>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <string>
#include <vector>

struct _ETHREAD;
struct _KAPC;

#define THREAD_STACK_SIZE_UC 0x40000ULL

struct ThreadContext {
    uc_engine* Engine;
    HANDLE HostThread;
    uint64_t ThreadId;
    uint64_t StackBase;
    uint64_t StackSize;
    uint64_t EthreadUcAddr;
    _ETHREAD* EthreadHostPtr;
    uint8_t* KpcrHostPtr;
    bool Running;
    std::vector<_KAPC*> PendingApcs;  // ponytail: host queue, not the guest ApcListHead; add guest-list walking when a driver is seen doing it
};

struct ThreadStartInfo {
    uc_engine* Engine;
    uint64_t StartRoutine;
    uint64_t StartContext;
    ThreadContext* Context;
    uint64_t Arg2;
    uint64_t Arg3;
    uint64_t Arg4;
    uint64_t Arg5;
    bool UseArg5;
    int NumArgs;
};

namespace UnicornThread {

extern std::unordered_map<DWORD, ThreadContext*> ThreadMap;
extern std::mutex ThreadLock;
extern uint64_t NextThreadId;
extern uint64_t NextEthreadAddr;
extern uint64_t NextStackAddr;

ThreadContext* Create(uint64_t StartRoutine, uint64_t StartContext, PHANDLE OutHandle);
ThreadContext* CreateEx(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, PHANDLE OutHandle);
// CreateEx + a 5th __fastcall argument written to [RSP+0x28] (kernel APC KernelRoutine).
ThreadContext* CreateEx5(uint64_t StartRoutine, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, uint64_t Arg5, PHANDLE OutHandle);
void Terminate(ThreadContext* Ctx, NTSTATUS ExitStatus);
ThreadContext* GetCurrent();
_ETHREAD* GetCurrentEthread();
uc_engine* GetCurrentEngine();
uint8_t* GetCurrentKpcr();

}
