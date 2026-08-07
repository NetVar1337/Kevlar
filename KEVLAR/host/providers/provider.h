#pragma once

#include <string>
#include <unordered_map>
#include <shared_mutex>

namespace Provider {

    extern std::unordered_map<std::string, PVOID> function_providers;
    extern std::unordered_map<std::string, PVOID> passthrough_provider_cache;
    extern std::unordered_map<std::string, PVOID> data_providers;
    extern std::unordered_map<std::string, size_t> data_export_sizes;
    extern std::vector<std::pair<uintptr_t, size_t>> export_data_range;
    extern std::shared_mutex ProviderLock;

    uintptr_t FindFuncImpl(uintptr_t ptr);
    uintptr_t FindDataImpl(uintptr_t ptr);

    uintptr_t AddFuncImpl(const char* nameFunc, PVOID hookFunc);
    uintptr_t AddDataImpl(const char* nameExport, PVOID hookExport, size_t exportSize);

    uint64_t unimplemented_stub();
}; // namespace Provider