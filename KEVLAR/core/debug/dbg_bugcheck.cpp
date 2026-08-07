#include "include/common.h"
#include "dbg_bugcheck.h"
#include "dbg_render.h"

// ================================================================
// KeBugCheck state
// ================================================================

static volatile LONG KiBugCheckActive = 0;
static volatile LONG KiHardwareTrigger = 0;
static uint64_t KiBugCheckDataArr[5] = {};
static uint64_t KiBugCheckDriver = 0;
static int BugCheckCount = 0;
static bool InBugCheck = false;
static ULONG LastBugCheckCode = 0;

void KiDumpProcessorState(uc_engine* uc) {
    uint64_t regs[17];
    int reg_ids[] = { UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_RIP };
    const char* reg_names[] = { "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15", "RIP" };

    for (int i = 0; i < 17; i++)
        uc_reg_read(uc, reg_ids[i], &regs[i]);

    uint64_t rflags = 0, cr0 = 0, cr3 = 0, cr4 = 0, cr8 = 0;
    uc_reg_read(uc, UC_X86_REG_RFLAGS, &rflags);
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    uc_reg_read(uc, UC_X86_REG_CR3, &cr3);
    uc_reg_read(uc, UC_X86_REG_CR4, &cr4);
    uc_reg_read(uc, UC_X86_REG_CR8, &cr8);

    putchar('\n');
    Bc(kCy);
    puts("  Processor State:");
    Bc(kGr);
    printf("  ");
    for (int i = 0; i < NB_IW; i++)
        putchar('-');
    putchar('\n');

    for (int i = 0; i < 17; i += 3) {
        int left = 17 - i;
        if (left >= 3) {
            Bc(kGr);
            printf("    %s : ", reg_names[i]);
            Bc(kW);
            printf("0x%016llX    ", regs[i]);
            Bc(kGr);
            printf("%s : ", reg_names[i + 1]);
            Bc(kW);
            printf("0x%016llX    ", regs[i + 1]);
            Bc(kGr);
            printf("%s : ", reg_names[i + 2]);
            Bc(kW);
            printf("0x%016llX\n", regs[i + 2]);
        } else if (left == 2) {
            Bc(kGr);
            printf("    %s : ", reg_names[i]);
            Bc(kW);
            printf("0x%016llX    ", regs[i]);
            Bc(kGr);
            printf("%s : ", reg_names[i + 1]);
            Bc(kW);
            printf("0x%016llX\n", regs[i + 1]);
        } else {
            Bc(kGr);
            printf("    %s : ", reg_names[i]);
            Bc(kW);
            printf("0x%016llX\n", regs[i]);
        }
    }

    char flags[64] = "";
    if (rflags & 0x0001)
        strcat_s(flags, "CF ");
    if (rflags & 0x0040)
        strcat_s(flags, "ZF ");
    if (rflags & 0x0080)
        strcat_s(flags, "SF ");
    if (rflags & 0x0200)
        strcat_s(flags, "IF ");
    if (rflags & 0x0400)
        strcat_s(flags, "DF ");
    if (rflags & 0x0800)
        strcat_s(flags, "OF ");
    int fl = (int)strlen(flags);
    if (fl > 0 && flags[fl - 1] == ' ')
        flags[fl - 1] = '\0';

    Bc(kGr);
    printf("    RFLAGS : ");
    Bc(kW);
    printf("0x%016llX  ", rflags);
    Bc(kYe);
    printf("[ %s ]\n", fl ? flags : "none");

    Bc(kGr);
    printf("    CR0    : ");
    Bc(kW);
    printf("0x%016llX    ", cr0);
    Bc(kGr);
    printf("CR3 : ");
    Bc(kW);
    printf("0x%016llX\n", cr3);
    Bc(kGr);
    printf("    CR4    : ");
    Bc(kW);
    printf("0x%016llX    ", cr4);
    Bc(kGr);
    printf("CR8 : ");
    Bc(kW);
    printf("0x%016llX", cr8);
    Bc(kGr);
    printf("  (IRQL = %llu)\n", cr8);
}

void KiDumpStack(uc_engine* uc, int maxFrames = 32) {
    uint64_t rsp = 0, rbp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_RBP, &rbp);

    putchar('\n');
    Bc(kCy);
    printf("  Raw Stack  ( RSP = ");
    Bc(kW);
    printf("0x%016llX", rsp);
    Bc(kCy);
    puts(" ) :");

    for (int i = 0; i < 24; i++) {
        uint64_t val = 0, addr = rsp + (i * 8);
        if (uc_mem_read(uc, addr, &val, 8) == UC_ERR_OK) {
            Bc(kGr);
            printf("    [RSP+0x%03X]  0x%016llX  :  ", i * 8, addr);
            Bc(kW);
            printf("0x%016llX\n", val);
        } else {
            Bc(kGr);
            printf("    [RSP+0x%03X]  0x%016llX  :  ", i * 8, addr);
            Bc(kRe);
            puts("<inaccessible>");
            break;
        }
    }

    putchar('\n');
    Bc(kCy);
    puts("  Call Stack  ( RBP chain ) :");

    uint64_t frame = rbp;
    bool any = false;
    for (int depth = 0; depth < maxFrames && frame != 0; depth++) {
        uint64_t retAddr = 0, nextFrame = 0;
        if (uc_mem_read(uc, frame + 8, &retAddr, 8) != UC_ERR_OK)
            break;
        if (uc_mem_read(uc, frame, &nextFrame, 8) != UC_ERR_OK)
            break;
        if (retAddr == 0)
            break;
        Bc(kGr);
        printf("    #%02d   RBP = ", depth);
        Bc(kW);
        printf("0x%016llX", frame);
        Bc(kGr);
        printf("   Ret = ");
        Bc(kW);
        printf("0x%016llX\n", retAddr);
        any = true;
        if (nextFrame <= frame)
            break;
        frame = nextFrame;
    }
    if (!any) {
        Bc(kGr);
        puts("    (no frames available)");
    }
}

ULONG KiReclassifyBugCheck(ULONG Code, uint64_t P1, uint64_t P2, uint64_t P3, uint64_t P4) {
    switch (Code) {
    case 0x0A:
        return Code;
    case 0x50:
        return Code;
    case 0xC0000011:
        return 0xC3;
    default:
        return Code;
    }
}

void h_KeBugCheck2(ULONG BugCheckCode, uint64_t Param1, uint64_t Param2, uint64_t Param3, uint64_t Param4, uint64_t TrapFrame) {
    uc_engine* Uc = UnicornThread::GetCurrentEngine();

    uint64_t Cr8Val = 0xF;
    uc_reg_write(Uc, UC_X86_REG_CR8, &Cr8Val);

    LONG NewVal = 3;
    LONG Old;
    LONG Prev;
    bool PrimaryOwner = false;

    for (;;) {
        Prev = KiBugCheckActive;
        if ((Prev & 3) == 3)
            break;
        Old = Prev;
        Prev = _InterlockedCompareExchange(&KiBugCheckActive, NewVal, Old);
        if (Prev == Old) {
            PrimaryOwner = true;
            break;
        }
    }

    if (!PrimaryOwner) {
        bool Triple = (KiBugCheckActive & 0xC) >= 8;
        if (!Triple)
            _InterlockedExchangeAdd(&KiBugCheckActive, 4u);

        putchar('\n');
        Bc(kRe); printf("*** %s FAULT ***\n", Triple ? "TRIPLE" : "DOUBLE");
        Bc(kGr); printf("  Original   : "); Bc(kW); printf("0x%08X  ", LastBugCheckCode); Bc(kYe); printf("%s\n", KiGetBugCheckName(LastBugCheckCode));
        Bc(kGr); printf("  %s : ", Triple ? "Current " : "Nested  "); Bc(kW); printf("0x%08X  ", BugCheckCode); Bc(kYe); printf("%s\n", KiGetBugCheckName(BugCheckCode));
        Bc(kGr); printf("  P1: "); Bc(kW); printf("0x%016llX\n", Param1);
        Bc(kGr); printf("  P2: "); Bc(kW); printf("0x%016llX\n", Param2);
        Bc(kGr); printf("  P3: "); Bc(kW); printf("0x%016llX\n", Param3);
        Bc(kGr); printf("  P4: "); Bc(kW); printf("0x%016llX\n", Param4);

        if (!Triple) {
            KiDumpProcessorState(Uc);
            KiDumpStack(Uc);
        }

        putchar('\n'); Bc(kRe);
        printf("*** %s - emulation halted ***\n", Triple ? "Triple fault" : "Double fault");
        Bc(kW); fflush(stdout);
        uc_emu_stop(Uc);
        return;
    }

    InBugCheck = true;
    LastBugCheckCode = BugCheckCode;

    ULONG Reclassified = KiReclassifyBugCheck(BugCheckCode, Param1, Param2, Param3, Param4);
    if (Reclassified != BugCheckCode) {
        Bc(kYe); printf("\n  [BUGCHECK] Code reclassified: 0x%08X -> 0x%08X\n", BugCheckCode, Reclassified);
        BugCheckCode = Reclassified;
    }

    KiBugCheckDataArr[0] = BugCheckCode;
    KiBugCheckDataArr[1] = Param1;
    KiBugCheckDataArr[2] = Param2;
    KiBugCheckDataArr[3] = Param3;
    KiBugCheckDataArr[4] = Param4;
    KiBugCheckData = BugCheckCode;
    KiBugCheckDriver = 0;

    const char* Name = KiGetBugCheckName(BugCheckCode);

    putchar('\n');
    NbSep();
    NbBlank();
    {
        char Stop[64];
        snprintf(Stop, sizeof(Stop), "  *** STOP: 0x%08X", BugCheckCode);
        int Len = (int)strlen(Stop), Pad = NB_IW - Len;
        if (Pad < 0) Pad = 0;
        Bc(kCy); putchar('|'); Bc(kYe); printf("%s", Stop);
        for (int I = 0; I < Pad; I++) putchar(' ');
        Bc(kCy); puts("|");
    }
    NbLine(kW, "");
    {
        char Nbuf[128];
        snprintf(Nbuf, sizeof(Nbuf), "  %s", Name);
        NbLine(kW, Nbuf);
    }
    NbBlank();
    NbSep();

    putchar('\n');
    Bc(kCy); puts("  Parameters:");
    Bc(kGr); printf("    Param1 : "); Bc(kW); printf("0x%016llX\n", Param1);
    Bc(kGr); printf("    Param2 : "); Bc(kW); printf("0x%016llX\n", Param2);
    Bc(kGr); printf("    Param3 : "); Bc(kW); printf("0x%016llX\n", Param3);
    Bc(kGr); printf("    Param4 : "); Bc(kW); printf("0x%016llX\n", Param4);

    KiPrintBugCheckAnalysis(BugCheckCode, Param1, Param2, Param3, Param4);

    if (TrapFrame) {
        putchar('\n');
        Bc(kGr); printf("  Trap Frame : "); Bc(kW); printf("0x%016llX\n", TrapFrame);
    }

    KiDumpProcessorState(Uc);
    KiDumpStack(Uc);

    _InterlockedIncrement(&KiHardwareTrigger);

    putchar('\n'); Bc(kRe);
    puts("*** Emulation halted by KeBugCheck ***");
    Bc(kW); fflush(stdout);
    uc_emu_stop(Uc);
}

void h_KeBugCheckEx(ULONG BugCheckCode, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4) {
    uc_engine* Uc = UnicornThread::GetCurrentEngine();

    __try {
        uint64_t Rflags = 0;
        uc_reg_read(Uc, UC_X86_REG_RFLAGS, &Rflags);
        uint64_t RflagsCli = Rflags & ~0x200ULL;
        uc_reg_write(Uc, UC_X86_REG_RFLAGS, &RflagsCli);
        uint64_t Cr8 = 0;
        uc_reg_read(Uc, UC_X86_REG_CR8, &Cr8);
        if (Cr8 < 2) {
            uint64_t V = 2;
            uc_reg_write(Uc, UC_X86_REG_CR8, &V);
        }
        if (Rflags & 0x200) {
            uint64_t V = RflagsCli | 0x200ULL;
            uc_reg_write(Uc, UC_X86_REG_RFLAGS, &V);
        }
        _InterlockedIncrement(&KiHardwareTrigger);
        h_KeBugCheck2(BugCheckCode, P1, P2, P3, P4, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}KeBugCheckEx CRASHED internally (0x%08x) — forcing emu stop{RESET}\n", GetExceptionCode());
    }

    uc_emu_stop(Uc);
}

void h_KeBugCheck(ULONG BugCheckCode) {
    uc_engine* Uc = UnicornThread::GetCurrentEngine();
    __try {
        h_KeBugCheck2(BugCheckCode, 0, 0, 0, 0, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}KeBugCheck CRASHED internally (0x%08x) — forcing emu stop{RESET}\n", GetExceptionCode());
    }
    uc_emu_stop(Uc);
}

void h___security_check_cookie(uint64_t StackCookie) {
}

void h___report_gsbufferoverrun() {
    Logger::Log("{RED}__report_gsbufferoverrun: GS buffer overrun detected — stopping emulation{RESET}\n");
    uc_engine* Uc = UnicornThread::GetCurrentEngine();
    uc_emu_stop(Uc);
}

BOOLEAN h_KeRegisterBugCheckReasonCallback(PVOID CallbackRecord, PVOID CallbackRoutine, ULONG Component, PUCHAR ComponentId) {
    auto HostId = UcPtr(ComponentId);
    Logger::Log("{CYN}\tKeRegisterBugCheckReasonCallback: component=%d id=%s{RESET}\n", Component, HostId ? (char*)HostId : "(null)");
    return TRUE;
}

BOOLEAN h_KeDeregisterBugCheckReasonCallback(PVOID CallbackRecord) {
    Logger::Log("{CYN}\tKeDeregisterBugCheckReasonCallback{RESET}\n");
    return TRUE;
}

void ResetBugCheckState() {
    KiBugCheckActive = 0;
    KiHardwareTrigger = 0;
    memset(KiBugCheckDataArr, 0, sizeof(KiBugCheckDataArr));
    KiBugCheckData = 0;
    KiBugCheckDriver = 0;
    BugCheckCount = 0;
    InBugCheck = false;
    LastBugCheckCode = 0;
}
