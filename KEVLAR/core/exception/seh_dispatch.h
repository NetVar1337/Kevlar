#pragma once

#include <unicorn/unicorn.h>
#include <cstdint>

#pragma pack(push, 1)
struct RUNTIME_FUNCTION_ENTRY {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindInfoAddress;
};

struct UNWIND_CODE {
    uint8_t CodeOffset;
    uint8_t UnwindOp : 4;
    uint8_t OpInfo : 4;
};

struct UNWIND_INFO_HEADER {
    uint8_t VersionFlags;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegisterOffset;
};

struct SCOPE_TABLE_ENTRY {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t HandlerAddress;
    uint32_t JumpTarget;
};
#pragma pack(pop)

#define UNW_FLAG_NHANDLER  0x00
#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

#define SEH_EXCEPTION_EXECUTE_HANDLER  1
#define SEH_EXCEPTION_CONTINUE_SEARCH  0

#define STATUS_INTEGER_DIVIDE_BY_ZERO  0xC0000094
#define STATUS_ACCESS_VIOLATION_EX     0xC0000005
#define STATUS_ILLEGAL_INSTRUCTION_EX  0xC000001D
#define STATUS_PRIVILEGED_INSTRUCTION  0xC0000096
#define STATUS_BREAKPOINT_EX           0x80000003
#define STATUS_SINGLE_STEP_EX          0x80000004
#define STATUS_INTEGER_OVERFLOW_EX     0xC0000095
#define STATUS_STACK_OVERFLOW_EX       0xC00000FD
#define STATUS_GUARD_PAGE_VIOLATION_EX 0x80000001
#define STATUS_ASSERTION_FAILURE       0xC0000420
#define STATUS_DATATYPE_MISALIGNMENT   0x80000002

namespace SehDispatch {

struct ModuleRange {
    uint64_t UcBase;
    uint64_t Size;
    uint8_t* HostBase;
};

bool Initialize();

bool DispatchException(uc_engine* Uc, uint32_t ExceptionCode, uint64_t FaultAddress = 0);

RUNTIME_FUNCTION_ENTRY* FindRuntimeFunction(uint8_t* HostImageBase, uint64_t ImageSize, uint32_t FaultRva);

uint64_t CalculateEstablishedFrame(uc_engine* Uc, uint8_t* HostImageBase, UNWIND_INFO_HEADER* UnwindInfo, UNWIND_CODE* Codes);

bool ProcessScopeTable(uint8_t* HostImageBase, uint64_t UcImageBase, uint32_t ScopeTableRva, uint32_t FaultRva, uint64_t& OutJumpTarget);

uint32_t IntNoToExceptionCode(uint32_t IntNo);

bool CompleteFilterDispatch(uc_engine* Uc);
bool IsPendingFilterDispatch();

}
