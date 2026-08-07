#pragma once
#include "include/common.h"
#include "dbg_render.h"
#include "dbg_bugcheck_table.h"

void h_KeBugCheck2(ULONG BugCheckCode, uint64_t Param1, uint64_t Param2, uint64_t Param3, uint64_t Param4, uint64_t TrapFrame);
void h_KeBugCheckEx(ULONG BugCheckCode, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4);
void h_KeBugCheck(ULONG BugCheckCode);
void h___security_check_cookie(uint64_t StackCookie);
void h___report_gsbufferoverrun();
BOOLEAN h_KeRegisterBugCheckReasonCallback(PVOID CallbackRecord, PVOID CallbackRoutine, ULONG Component, PUCHAR ComponentId);
BOOLEAN h_KeDeregisterBugCheckReasonCallback(PVOID CallbackRecord);
void ResetBugCheckState();
