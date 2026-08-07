#include "include/common.h"
#include "dbg_render.h"
#include "dbg_bugcheck_table.h"

static HANDLE s_BcH = INVALID_HANDLE_VALUE;
HANDLE BcH() {
    if (s_BcH == INVALID_HANDLE_VALUE)
        s_BcH = GetStdHandle(STD_OUTPUT_HANDLE);
    return s_BcH;
}
void Bc(WORD a) { SetConsoleTextAttribute(BcH(), a); }

const WORD kW = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // bright white
const WORD kGr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // gray
const WORD kCy = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // cyan
const WORD kYe = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // yellow
const WORD kRe = FOREGROUND_RED | FOREGROUND_INTENSITY; // red
const WORD kBsod = BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // white on blue

int BcW() {
    CONSOLE_SCREEN_BUFFER_INFO c;
    return GetConsoleScreenBufferInfo(BcH(), &c) ? c.srWindow.Right - c.srWindow.Left + 1 : 80;
}
int BcHt() {
    CONSOLE_SCREEN_BUFFER_INFO c;
    return GetConsoleScreenBufferInfo(BcH(), &c) ? c.srWindow.Bottom - c.srWindow.Top + 1 : 25;
}

void BcFill(WORD attr) {
    CONSOLE_SCREEN_BUFFER_INFO c;
    if (!GetConsoleScreenBufferInfo(BcH(), &c))
        return;
    DWORD w = (DWORD)(c.srWindow.Right - c.srWindow.Left + 1);
    DWORD h = (DWORD)(c.srWindow.Bottom - c.srWindow.Top + 1);
    COORD o = { c.srWindow.Left, c.srWindow.Top };
    DWORD n;
    FillConsoleOutputAttribute(BcH(), attr, w * h, o, &n);
    FillConsoleOutputCharacterA(BcH(), ' ', w * h, o, &n);
    SetConsoleCursorPosition(BcH(), o);
    SetConsoleTextAttribute(BcH(), attr);
}

// ---- Normal bugcheck box (inner=70, total=72) ------------------

void NbSep() {
    Bc(kCy);
    putchar('+');
    for (int i = 0; i < NB_IW; i++)
        putchar('-');
    puts("+");
}

void NbBlank() {
    Bc(kCy);
    putchar('|');
    for (int i = 0; i < NB_IW; i++)
        putchar(' ');
    puts("|");
}

void NbLine(WORD a, const char* s) {
    int len = (int)strlen(s), pad = NB_IW - len;
    if (pad < 0)
        pad = 0;
    Bc(kCy);
    putchar('|');
    Bc(a);
    printf("%s", s);
    for (int i = 0; i < pad; i++)
        putchar(' ');
    Bc(kCy);
    puts("|");
}

// ---- BSOD box (inner=58, total=60, centered on blue screen) ----

void BbSep(int lp) {
    Bc(kBsod);
    for (int i = 0; i < lp; i++)
        putchar(' ');
    putchar('+');
    for (int i = 0; i < BB_IW; i++)
        putchar('-');
    puts("+");
}

void BbLine(int lp, const char* s) {
    int len = (int)strlen(s), pad = BB_IW - len;
    if (pad < 0)
        pad = 0;
    Bc(kBsod);
    for (int i = 0; i < lp; i++)
        putchar(' ');
    putchar('|');
    printf("%s", s);
    for (int i = 0; i < pad; i++)
        putchar(' ');
    puts("|");
}

void BbBlank(int lp) { BbLine(lp, ""); }

void BbCenter(int lp, const char* s) {
    int len = (int)strlen(s), sp = (BB_IW - len) / 2;
    if (sp < 0)
        sp = 0;
    char buf[128];
    snprintf(buf, sizeof(buf), "%*s%s", sp, "", s);
    buf[BB_IW] = '\0';
    BbLine(lp, buf);
}

void KiShowBsodBox(ULONG orig, ULONG nested, uint64_t P1, uint64_t P2, uint64_t P3, uint64_t P4, bool triple) {
    BcFill(kBsod);

    int cw = BcW(), ch = BcHt();
    int lp = (cw - (BB_IW + 2)) / 2;
    if (lp < 0)
        lp = 0;

    COORD pos = { 0, (SHORT)(ch / 3) };
    SetConsoleCursorPosition(BcH(), pos);

    char buf[128];

    BbSep(lp);
    BbBlank(lp);
    BbCenter(lp, triple ? "*** TRIPLE FAULT  -  SYSTEM HALTED ***" : "*** DOUBLE FAULT DETECTED ***");
    BbCenter(lp, triple ? "Recursive bugcheck - unrecoverable" : "BugCheck occurred during BugCheck processing");
    BbBlank(lp);

    snprintf(buf, sizeof(buf), "  Original : 0x%08X  %.30s", orig, KiGetBugCheckName(orig));
    BbLine(lp, buf);
    snprintf(buf, sizeof(buf), "  %s   : 0x%08X  %.30s", triple ? "Current " : "Nested  ", nested, KiGetBugCheckName(nested));
    BbLine(lp, buf);

    BbBlank(lp);

    snprintf(buf, sizeof(buf), "  P1 : 0x%016llX", P1);
    BbLine(lp, buf);
    snprintf(buf, sizeof(buf), "  P2 : 0x%016llX", P2);
    BbLine(lp, buf);
    snprintf(buf, sizeof(buf), "  P3 : 0x%016llX", P3);
    BbLine(lp, buf);
    snprintf(buf, sizeof(buf), "  P4 : 0x%016llX", P4);
    BbLine(lp, buf);

    BbBlank(lp);
    BbSep(lp);

    printf("\n\n");
    Bc(kW);
    fflush(stdout);
}

void KiPrintBugCheckAnalysis(ULONG BugCheckCode, uint64_t Param1, uint64_t Param2, uint64_t Param3, uint64_t Param4) {
    switch (BugCheckCode) {
    case 0x0A:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Faulting Address : "); Bc(kW); printf("0x%016llX\n", Param1);
        Bc(kGr); printf("    IRQL             : "); Bc(kW); printf("%llu\n", Param2);
        Bc(kGr); printf("    Access Type      : "); Bc(kW); puts(Param3 ? "WRITE" : "READ");
        Bc(kGr); printf("    Faulting IP      : "); Bc(kW); printf("0x%016llX\n", Param4);
        break;
    case 0x50:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Faulting Address : "); Bc(kW); printf("0x%016llX\n", Param1);
        Bc(kGr); printf("    Access Type      : "); Bc(kW); puts(Param2 ? "WRITE" : "READ");
        Bc(kGr); printf("    Faulting IP      : "); Bc(kW); printf("0x%016llX\n", Param3);
        break;
    case 0xD1:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Memory Ref       : "); Bc(kW); printf("0x%016llX\n", Param1);
        Bc(kGr); printf("    IRQL             : "); Bc(kW); printf("%llu\n", Param2);
        Bc(kGr); printf("    Access Type      : "); Bc(kW); puts(Param3 ? "WRITE" : "READ");
        Bc(kGr); printf("    Faulting IP      : "); Bc(kW); printf("0x%016llX\n", Param4);
        break;
    case 0x139: {
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Failure Type     : "); Bc(kW); printf("%llu  ->  ", Param1);
        const char* Sub = "Unknown failure subtype";
        switch ((ULONG)Param1) {
        case 0:  Sub = "Stack buffer overrun"; break;
        case 1:  Sub = "VTGuard check failure"; break;
        case 2:  Sub = "Stack cookie mismatch (/GS)"; break;
        case 3:  Sub = "Corrupt LIST_ENTRY"; break;
        case 4:  Sub = "Out-of-bounds stack variable access"; break;
        case 5:  Sub = "Invalid parameter passed to function"; break;
        case 6:  Sub = "Uninitialized stack variable used"; break;
        case 8:  Sub = "Illegal ICall target"; break;
        case 9:  Sub = "Write to read-only exception handler"; break;
        case 13: Sub = "Invalid fiber context switch"; break;
        case 14: Sub = "Invalid registry callback"; break;
        case 18: Sub = "CFG violation"; break;
        case 19: Sub = "Return flow guard violation"; break;
        case 21: Sub = "CET shadow stack mismatch"; break;
        }
        Bc(kYe); puts(Sub);
        break;
    }
    case 0x3B:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Exception Code   : "); Bc(kW); printf("0x%08X\n", (ULONG)Param1);
        Bc(kGr); printf("    Faulting IP      : "); Bc(kW); printf("0x%016llX\n", Param2);
        Bc(kGr); printf("    Exception Record : "); Bc(kW); printf("0x%016llX\n", Param3);
        break;
    case 0x1E:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Exception Code   : "); Bc(kW); printf("0x%08X\n", (ULONG)Param1);
        Bc(kGr); printf("    Faulting IP      : "); Bc(kW); printf("0x%016llX\n", Param2);
        Bc(kGr); printf("    Exception Param  : "); Bc(kW); printf("0x%016llX\n", Param3);
        break;
    case 0xC4:
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Violation Type   : "); Bc(kW); printf("0x%X\n", (ULONG)Param1);
        break;
    case 0x7F: {
        putchar('\n');
        Bc(kYe); puts("  Analysis:");
        Bc(kGr); printf("    Trap Number      : "); Bc(kW); printf("%llu", Param1);
        const char* Trap = nullptr;
        switch ((ULONG)Param1) {
        case 0x00: Trap = "Divide by Zero"; break;
        case 0x04: Trap = "Overflow"; break;
        case 0x05: Trap = "Bound Check"; break;
        case 0x06: Trap = "Invalid Opcode"; break;
        case 0x08: Trap = "Double Fault"; break;
        case 0x0D: Trap = "General Protection Fault"; break;
        case 0x0E: Trap = "Page Fault"; break;
        }
        if (Trap) { Bc(kGr); printf("  ->  "); Bc(kYe); puts(Trap); }
        else putchar('\n');
        break;
    }
    }
}
