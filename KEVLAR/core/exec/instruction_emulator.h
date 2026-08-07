#pragma once

#include <unicorn/unicorn.h>
#include <cstdint>

namespace InsnEmulator {

void Initialize();

bool TryEmulate(uc_engine* Uc, uint64_t Rip);

void PatchYmmInstructions(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);

}
