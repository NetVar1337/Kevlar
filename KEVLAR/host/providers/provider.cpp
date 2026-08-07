#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include <SymParser/symparser.hpp>

#include "host/providers/provider.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"

namespace Provider {
    std::unordered_map<std::string, PVOID> function_providers;
    std::unordered_map<std::string, PVOID> passthrough_provider_cache;
    std::unordered_map<std::string, PVOID> data_providers;
    std::unordered_map<std::string, size_t> data_export_sizes;
    std::vector<std::pair<uintptr_t, size_t>> export_data_range;
    std::shared_mutex ProviderLock;
} // namespace Provider

static auto ntdll = LoadLibraryA("ntdll.dll");

uintptr_t Provider::FindFuncImpl(uintptr_t ptr) {
    uintptr_t implPtr = 0;

    auto pe_file = PEFile::FindModule(ptr);
    if (!pe_file) {
        Logger::Log("{RED}FindFuncImpl: no module for ptr 0x%llx{RESET}\n", ptr);
        return (uintptr_t)unimplemented_stub;
    }

    std::string reserved_str = "";
    auto rva = ptr - pe_file->GetMappedImageBase();
    auto exported_func = pe_file->GetExport(rva);

    if (!exported_func) {
        auto sym = symparser::find_symbol(pe_file->filename, rva);
        if (!sym || !sym->rva) {
            Logger::Log("{RED}FindFuncImpl: no export/symbol for %s+0x%llx{RESET}\n", pe_file->name.c_str(), rva);
            return (uintptr_t)unimplemented_stub;
        }
        reserved_str = sym->name;
        exported_func = reserved_str.c_str();
    }

    {
        std::shared_lock<std::shared_mutex> Guard(ProviderLock);
        if (function_providers.contains(exported_func))
            return (uintptr_t)function_providers[exported_func];

        if (passthrough_provider_cache.contains(exported_func))
            return (uintptr_t)passthrough_provider_cache[exported_func];
    }

    implPtr = (uintptr_t)GetProcAddress(ntdll, exported_func);

    if (!implPtr)
        implPtr = (uintptr_t)unimplemented_stub;

    {
        std::unique_lock<std::shared_mutex> Guard(ProviderLock);
        passthrough_provider_cache.insert(std::pair(exported_func, (PVOID)implPtr));
    }

    return implPtr;
}

uintptr_t Provider::FindDataImpl(uintptr_t ptr) {

    auto pe_file = PEFile::FindModule(ptr);
    if (!pe_file)
        return 0;

    std::string reserved_str = "";
    auto rva = ptr - pe_file->GetMappedImageBase();
    auto exported_func = pe_file->GetExport(rva);

    if (!exported_func) {
        auto sym = symparser::find_symbol(pe_file->filename, rva);
        if (!sym || !sym->rva) {
            return 0;
        }
        reserved_str = sym->name;
        exported_func = reserved_str.c_str();
    }

    Logger::Log("{CYN}Getting data @ %s!%s{RESET}\n", pe_file->name.c_str(), exported_func);

    {
        std::shared_lock<std::shared_mutex> Guard(ProviderLock);
        if (data_providers.contains(exported_func))
            return (uintptr_t)data_providers[exported_func];
    }

    Logger::Log("{YEL}Exported Data %s!%s is not implemented{RESET}\n", pe_file->name.c_str(), exported_func);
    return 0;
}

uintptr_t Provider::AddFuncImpl(const char* nameFunc, PVOID hookFunc) {
    std::unique_lock<std::shared_mutex> Guard(ProviderLock);
    function_providers.insert(std::pair(nameFunc, hookFunc));
    return 1;
}

uintptr_t Provider::AddDataImpl(const char* nameExport, PVOID hookExport, size_t exportSize) {
    std::unique_lock<std::shared_mutex> Guard(ProviderLock);
    data_export_sizes[nameExport] = exportSize;

    if (!UnicornEmu::PrimaryEngine) {
        data_providers.insert(std::pair(nameExport, hookExport));
        export_data_range.push_back(std::pair((uintptr_t)hookExport, exportSize));
        return 1;
    }

    Guard.unlock();

    uint64_t UcAddr = UnicornMem::AllocateVariable(
        UnicornThread::GetCurrentEngine(), exportSize < 0x10 ? 0x10 : exportSize, nameExport);

    if (!UcAddr) {
        Logger::Log("{RED}AddDataImpl: failed to allocate UC memory for '%s'{RESET}\n", nameExport);
        return 0;
    }

    void* HostBuf = UnicornMem::UcToHost(UcAddr);
    if (HostBuf && hookExport) {
        memcpy(HostBuf, hookExport, exportSize);
    }

    Guard.lock();
    data_providers[nameExport] = (PVOID)UcAddr;
    export_data_range.push_back(std::pair((uintptr_t)UcAddr, exportSize));

    Logger::Log("{GRN}AddDataImpl: '%s' -> UC 0x%llx (size=%zu){RESET}\n", nameExport, UcAddr, exportSize);
    return 1;
}

uint64_t Provider::unimplemented_stub() {
    if (UnicornEmu::StrictExportsEnabled) {
        Logger::Log("\t\t{RED}INSIDE STUB (strict) -> STATUS_NOT_IMPLEMENTED{RESET}\n");
        return 0xC0000002ULL; // STATUS_NOT_IMPLEMENTED
    }
    Logger::Log("\t\t{RED}INSIDE STUB, RETURNING 0{RESET}\n");
    return 0;
}
