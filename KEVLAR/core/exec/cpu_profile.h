#pragma once

// Coherent, deterministic bare-metal CPU profile.
//
// Replaces host-CPU passthrough in the CPUID hook. Every leaf returns
// profile-defined values so a run is independent of the machine hosting the
// emulator: no host vendor/brand/feature/leaf leaks, hypervisor leaves are
// empty (CPUID.1:ECX.31 = 0). Data models a Raptor Lake (i9-13900K class)
// CPU, with the TSC/crystal (0x15) and frequency (0x16) leaves coherent
// with the RDTSC emulation in timing_spoof.cpp.
//
// ponytail: hardcoded reference profile, not dump-driven. Add a capture/
// import path when a second target platform is needed.

#include <cstdint>
#include <cstring>

namespace CpuProfile {

// TSC derived from leaf 0x15: 38.4MHz crystal * 168 / 2 = 3.2256 GHz.
inline constexpr uint64_t kProfileTscHz = 3225600000ULL;
// Plausible post-boot TSC value (~10 min uptime at 3.226 GHz); fixed so runs
// are reproducible instead of seeding from the host RDTSC.
inline constexpr uint64_t kInitialVirtualTsc = 0x1C0000000000ULL;
// KUSER_SHARED_DATA SystemTime (100ns since 1601), fixed ~2024-07 value.
inline constexpr int64_t kEmulatedSystemTimeBase = 0x01DB2E7F4B7A0000LL;

inline void Query(uint32_t Leaf, uint32_t SubLeaf, uint32_t Out[4]) {
    memset(Out, 0, 16);

    switch (Leaf) {
    case 0x00: // vendor + max standard leaf
        Out[0] = 0x20;
        Out[1] = 0x756E6547; // Genu
        Out[3] = 0x49656E69; // ineI
        Out[2] = 0x6C65746E; // ntel
        break;
    case 0x01: // version + features, bare metal (ECX.31 hypervisor = 0)
        Out[0] = 0x000B0671;   // Raptor Lake: family 6, model 0xB7, stepping 1
        Out[1] = 0x00100800;   // CLFLUSH 64B, 16 logical CPUs, brand index 0
        Out[2] = 0x7FFAB7FF;   // SSE3..RDRAND, AVX, AES, XSAVE; hypervisor bit clear
        Out[3] = 0xBFEBFBFF;   // classic FPU..HTT bits, IA64 clear
        break;
    case 0x04: { // deterministic cache, subleaf-indexed
        switch (SubLeaf) {
        case 0: Out[0] = 0x00000021; Out[1] = 0x2C000040; break; // L1D, 12-way, 64B
        case 1: Out[0] = 0x00000021; Out[1] = 0x2C000040; break; // L1I
        case 2: Out[0] = 0x00000041; Out[1] = 0x3C000040; break; // L2, 16-way, 64B
        case 3: Out[0] = 0x00000061; Out[1] = 0x4C000040; break; // L3, 20-way, 64B
        }
        break;
    }
    case 0x07:
        if (SubLeaf == 0) { // extended features
            Out[0] = 0x00000001;     // max subleaf
            Out[1] = 0x2000FFBB;     // FSGSBASE..AVX2, BMI1/2, ERMS, INVPCID, SHA; no AVX-512
            Out[2] = 0x04C05700;     // GFNI, VAES, VPCLMULQDQ, RDPID, SERIALIZE, MOVDIRI/64B, CLDEMOTE
            Out[3] = 0;              // no AVX-512_FP16/AMX/HRESET
        }
        break;
    case 0x0B: // extended topology (V1)
        if (SubLeaf == 0) { Out[1] = 1; Out[2] = 0x00000001; }               // 1 SMT
        else if (SubLeaf == 1) { Out[0] = 15; Out[1] = 16; Out[2] = 0x00000002; } // 16 P-core
        break;
    case 0x0D: // XSAVE: x87+SSE+AVX only, no AVX-512
        if (SubLeaf == 0) { Out[0] = 0x00000007; Out[1] = 0x340; Out[2] = 0x340; }
        else if (SubLeaf == 1) { Out[0] = 0x00000007; Out[1] = 0x340; Out[2] = 0x340; }
        else if (SubLeaf == 2) { Out[0] = 0x100; Out[1] = 0x240; }
        break;
    case 0x14: // Intel PT
        if (SubLeaf == 0) { Out[0] = 1; Out[1] = 0xF; Out[2] = 0x6; }
        else if (SubLeaf == 1) { Out[0] = 0x02490002; }
        break;
    case 0x15: // TSC / core crystal clock
        Out[0] = 2; Out[1] = 168; Out[2] = 38400000;
        break;
    case 0x16: // processor frequency
        Out[0] = 3000; Out[1] = 5800; Out[2] = 100;
        break;
    case 0x1A: // hybrid present (Raptor Lake)
        Out[0] = 1;
        break;
    case 0x1F: // extended topology (V2)
        if (SubLeaf == 0) { Out[1] = 1; Out[2] = 0x00000000; }
        else if (SubLeaf == 1) { Out[0] = 15; Out[1] = 16; Out[2] = 0x00000001; }
        break;
    // 0x40000000..0x4FFFFFFF: no hypervisor -> all zeros (already memset).

    case 0x80000000:
        Out[0] = 0x80000008;
        break;
    case 0x80000001: // extended feature bits
        Out[0] = 0x000B0671;
        Out[2] = 0x00000121; // LAHF/SAHF, LZCNT, PREFETCHW
        Out[3] = 0x20100000; // NX, long mode
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004: { // brand string, 16 bytes per leaf, zero padded
        static const char Brand[] = "13th Gen Intel(R) Core(TM) i9-13900K";
        static const size_t BrandLen = sizeof(Brand) - 1;
        size_t Off = (size_t)(Leaf - 0x80000002) * 16;
        size_t Rem = (BrandLen > Off) ? (BrandLen - Off) : 0;
        if (Rem > 16) Rem = 16;
        if (Rem) memcpy(Out, Brand + Off, Rem);
        break;
    }
    case 0x80000005: // L1 cache
        Out[1] = 0x00080040; Out[2] = 0x00080040;
        break;
    case 0x80000006: // L2 cache, 2MB
        Out[0] = 0x00200000; Out[1] = 0x00010040;
        break;
    case 0x80000007: // APM: invariant TSC
        Out[3] = 0x00000100;
        break;
    case 0x80000008: // virtual/phys address sizes
        Out[0] = 0x302E; // 48-bit virtual, 46-bit physical
        break;
    }
}

} // namespace CpuProfile
