// Self-check for cpu_profile.h: asserts the coherence invariants the profile
// promises (deterministic bare-metal Intel). Compile+run: clang++ -std=c++17
#include <cassert>
#include <cstdio>
#include <cstring>
#include "core/exec/cpu_profile.h"

int main() {
    uint32_t R[4];

    // Leaf 0: GenuineIntel, max std leaf 0x20.
    CpuProfile::Query(0, 0, R);
    assert(R[0] == 0x20);
    assert(R[1] == 0x756E6547 && R[2] == 0x6C65746E && R[3] == 0x49656E69);

    // Leaf 1: bare metal -> hypervisor bit (ECX.31) clear.
    CpuProfile::Query(1, 0, R);
    assert((R[2] & (1u << 31)) == 0);
    assert(R[2] & (1u << 28)); // AVX
    assert(R[2] & (1u << 25)); // AES
    assert(R[3] & (1u << 26)); // SSE2
    assert(R[3] & (1u << 28)); // HTT

    // Leaf 7.0: AVX2 + SHA present, no AVX-512 (F/DQ/CD/BW/VL bits clear).
    CpuProfile::Query(7, 0, R);
    assert(R[1] & (1u << 5));  // AVX2
    assert(R[1] & (1u << 29)); // SHA
    assert(R[1] & (1u << 3));  // BMI1
    // AVX-512 region of EBX (16..28, SHA=29) must be clear; no AVX-512 VNNI
    // group (bits 1-5) or PREFETCHWT1 (bit 0) in ECX.
    assert((R[1] & 0x1FFF0000u) == 0);
    assert((R[2] & 0x3F) == 0);

    // Leaf 0x15 must be coherent with kProfileTscHz.
    CpuProfile::Query(0x15, 0, R);
    assert(R[0] == 2 && R[1] == 168 && R[2] == 38400000);
    assert((uint64_t)R[2] * R[1] / R[0] == CpuProfile::kProfileTscHz);

    // Leaf 0x16 nominal base == 3000 MHz.
    CpuProfile::Query(0x16, 0, R);
    assert((R[0] & 0xFFFF) == 3000);

    // Hypervisor range: fully empty (no hypervisor).
    CpuProfile::Query(0x40000000, 0, R);
    assert(R[0] == 0 && R[1] == 0 && R[2] == 0 && R[3] == 0);
    CpuProfile::Query(0x40000003, 0, R);
    assert(R[0] == 0 && R[1] == 0 && R[2] == 0 && R[3] == 0);

    // Extended range.
    CpuProfile::Query(0x80000000, 0, R);
    assert(R[0] == 0x80000008);
    CpuProfile::Query(0x80000001, 0, R);
    assert(R[3] & (1u << 20)); // NX
    assert(R[3] & (1u << 29)); // long mode
    CpuProfile::Query(0x80000007, 0, R);
    assert(R[3] & (1u << 8));  // invariant TSC
    CpuProfile::Query(0x80000008, 0, R);
    assert((R[0] & 0xFF) == 46 && ((R[0] >> 8) & 0xFF) == 48);

    // Brand string reassembles exactly.
    char Brand[49] = {};
    for (uint32_t L = 0x80000002; L <= 0x80000004; L++) {
        CpuProfile::Query(L, 0, R);
        memcpy(Brand + (L - 0x80000002) * 16, R, 16);
    }
    assert(strcmp(Brand, "13th Gen Intel(R) Core(TM) i9-13900K") == 0);

    // Unhandled leaf -> zeros (leaf-not-present), not host passthrough.
    CpuProfile::Query(0x12345678, 0, R);
    assert(R[0] == 0 && R[1] == 0 && R[2] == 0 && R[3] == 0);

    std::printf("cpu_profile selftest OK\n");
    return 0;
}
