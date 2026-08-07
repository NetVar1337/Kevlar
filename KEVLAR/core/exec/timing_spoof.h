#pragma once

#include <cstdint>
#include <windows.h>

extern thread_local uint64_t TlsLastRdtscValue;
extern thread_local int64_t TlsLastRdtscQpc;
extern thread_local bool TlsCpuidBetweenRdtsc;
extern thread_local int TlsShortIntervalCount;

static constexpr double EmulationSpeedRatio = 500.0;
static constexpr double ShortIntervalThreshold = 0.002;
static constexpr int BusyWaitThreshold = 50;

uint64_t TscFastRand();
int64_t TscGaussianJitter(double Stddev);
int64_t GetEmulatedQpcElapsed();
DWORD WINAPI KusdUpdaterThread(LPVOID Param);
