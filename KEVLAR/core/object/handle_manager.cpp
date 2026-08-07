#include "core/object/handle_manager.h"
#include <windows.h>

static std::unordered_map<uintptr_t, uintptr_t> HandleMap;
std::mutex HandleManager::HandleLock;

namespace TimerManager {
    std::unordered_map<_KTIMER*, uint64_t> timer_manager;
    std::mutex TimerLock;
}

namespace MutexManager {
    std::unordered_map<uintptr_t, uint64_t> mutex_manager;
    std::mutex MutexLock;
}

bool HandleManager::AddMap(uintptr_t kernelObject, uintptr_t umHandle) {
    std::lock_guard<std::mutex> Guard(HandleLock);
    if (HandleMap.contains(kernelObject))
        return false;
    HandleMap.insert(std::pair(kernelObject, umHandle));
    return true;
}

uintptr_t HandleManager::GetHandle(uintptr_t kernelObject) {
    std::lock_guard<std::mutex> Guard(HandleLock);
    if (!HandleMap.contains(kernelObject)) {
        return 0;
    }
    return HandleMap[kernelObject];
}
