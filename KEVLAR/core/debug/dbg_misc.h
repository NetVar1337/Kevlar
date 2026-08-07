#pragma once
#include "include/common.h"

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length);
NTSTATUS h_KdChangeOption(ULONG Option, ULONG InBufferBytes, PVOID InBuffer, ULONG OutBufferBytes, PVOID OutBuffer, PULONG OutBufferNeeded);
NTSTATUS h_KdSystemDebugControl(int Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength,
    /*KPROCESSOR_MODE*/ int PreviousMode);
