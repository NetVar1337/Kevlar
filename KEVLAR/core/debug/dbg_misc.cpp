#include "include/common.h"
#include "dbg_misc.h"

ULONG h_DbgPrompt(PCCH Prompt, PCH Response, ULONG Length) {
    auto HostPrompt = UcPtr(Prompt);
    Logger::Log("{MAG}\tDbgPrompt: \"%s\"{RESET}\n", HostPrompt ? HostPrompt : "(null)");
    return 0;
}

NTSTATUS h_KdChangeOption(ULONG Option, ULONG InBufferBytes, PVOID InBuffer, ULONG OutBufferBytes, PVOID OutBuffer, PULONG OutBufferNeeded) {
    return 0xC0000354; // STATUS_DEBUGGER_INACTIVE
}

// DBGKD_GET_VERSION64 returned for SysDbgQueryVersion (cmd 0). A driver probing the
// debugger interface reads these fields; all-zeros reads as an invalid/no-kd state.
static void FillDbgkdVersion(uint8_t* Out) {
    memset(Out, 0, 0x40);
    *(uint32_t*)(Out + 0x00) = 0x0000000F;              // MajorVersion (Windows 11)
    *(uint32_t*)(Out + 0x04) = 0x000065F4;              // MinorVersion (build 26100)
    *(uint32_t*)(Out + 0x08) = 0x00000010;              // ProtocolVersion
    *(uint32_t*)(Out + 0x0C) = 0x00000000;              // Flags
    *(uint32_t*)(Out + 0x10) = 0x00008664;              // MachineType (AMD64)
    *(uint32_t*)(Out + 0x14) = 0x00000014;              // MaxPacketType
    *(uint32_t*)(Out + 0x18) = 0x0000000D;              // MaxStateChange
    *(uint32_t*)(Out + 0x1C) = 0x0000000E;              // MaxManipulate
    *(uint32_t*)(Out + 0x20) = 0x00000000;              // Simulation
    *(uint64_t*)(Out + 0x30) = 0xFFFFF80300000000ULL;   // KernBase (ntoskrnl)
}

NTSTATUS h_KdSystemDebugControl(int Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength,
    /*KPROCESSOR_MODE*/ int PreviousMode) {
    Logger::Log("{MAG}\tKdSystemDebugControl: cmd=%d inLen=%u outLen=%u{RESET}\n", Command, InputBufferLength, OutputBufferLength);
    auto HostRetLen = UcPtr(ReturnLength);
    auto HostOutBuf = UcPtr(OutputBuffer);
    if (HostRetLen) *HostRetLen = 0;
    if (HostOutBuf && OutputBufferLength > 0)
        memset(HostOutBuf, 0, OutputBufferLength);

    if (Command == 0 && HostOutBuf && OutputBufferLength >= 0x40) {
        // SysDbgQueryVersion: report a coherent no-debugger kd version.
        FillDbgkdVersion((uint8_t*)HostOutBuf);
        if (HostRetLen) *HostRetLen = 0x40;
        return 0;
    }
    return 0;
}
