#pragma once
#include "include/common.h"

extern const WORD kW;
extern const WORD kGr;
extern const WORD kCy;
extern const WORD kYe;
extern const WORD kRe;
extern const WORD kBsod;

#define NB_IW 70
#define BB_IW 58

HANDLE BcH();
void Bc(WORD a);
int BcW();
int BcHt();
void BcFill(WORD attr);

void NbSep();
void NbBlank();
void NbLine(WORD a, const char* s);

void BbSep(int lp);
void BbLine(int lp, const char* s);
void BbBlank(int lp);
void BbCenter(int lp, const char* s);

void KiShowBsodBox(ULONG orig, ULONG nested, uint64_t P1, uint64_t P2, uint64_t P3, uint64_t P4, bool triple);
void KiPrintBugCheckAnalysis(ULONG BugCheckCode, uint64_t Param1, uint64_t Param2, uint64_t Param3, uint64_t Param4);
