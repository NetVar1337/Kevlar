#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include <Logger/Logger.h>

uint64_t UnicornEmu::MapRegion(uc_engine* Uc, uint64_t UcAddr, uint64_t Size, uint32_t Perms, const char* Name) {
    uint64_t AlignedSize = (Size + 0xFFF) & ~0xFFFULL;

    uc_err Err = uc_mem_map(Uc, UcAddr, AlignedSize, Perms);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}MapRegion '%s' failed at 0x%llx size 0x%llx: %s{RESET}\n", Name, UcAddr, AlignedSize, uc_strerror(Err));
        return 0;
    }

    {
        std::unique_lock<std::shared_mutex> Guard(RegionsLock);
        MappedRegions.push_back({ UcAddr, AlignedSize, nullptr, std::string(Name), Perms });
    }
    Logger::Log("{BLU}MapRegion '%s': 0x%llx (size=0x%llx){RESET}\n", Name, UcAddr, AlignedSize);
    return UcAddr;
}

uint64_t UnicornEmu::MapRegionPtr(uc_engine* Uc, uint64_t UcAddr, uint64_t Size, uint32_t Perms, void* HostPtr, const char* Name) {
    uint64_t AlignedSize = (Size + 0xFFF) & ~0xFFFULL;

    uc_err Err = uc_mem_map_ptr(Uc, UcAddr, AlignedSize, Perms, HostPtr);
    if (Err != UC_ERR_OK) {
        Logger::Log("{RED}MapRegionPtr '%s' failed at 0x%llx size 0x%llx: %s{RESET}\n", Name, UcAddr, AlignedSize, uc_strerror(Err));
        return 0;
    }

    {
        std::unique_lock<std::shared_mutex> Guard(RegionsLock);
        MappedRegions.push_back({ UcAddr, AlignedSize, HostPtr, std::string(Name), Perms });
    }
    Logger::Log("{BLU}MapRegionPtr '%s': 0x%llx -> host %p (size=0x%llx){RESET}\n", Name, UcAddr, HostPtr, AlignedSize);
    return UcAddr;
}

void UnicornEmu::StopEmulation(uc_engine* Uc) {
    uc_emu_stop(Uc);
}

std::string UnicornEmu::DisassembleAt(uc_engine* Uc, uint64_t Addr) {
    uint8_t Buf[15] = { 0 };
    uc_err Err = uc_mem_read(Uc, Addr, Buf, 15);
    if (Err != UC_ERR_OK)
        return "<unreadable>";

    ZydisDecodedInstruction Instr;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus Status = ZydisDecoderDecodeFull(&Decoder, Buf, 15, &Instr, Operands);
    if (!ZYAN_SUCCESS(Status))
        return "<decode failed>";

    char FormattedBuf[256] = { 0 };
    ZydisFormatterFormatInstruction(&GlobalFormatter, &Instr, Operands,
        Instr.operand_count_visible, FormattedBuf, sizeof(FormattedBuf), Addr, ZYAN_NULL);

    return std::string(FormattedBuf);
}
