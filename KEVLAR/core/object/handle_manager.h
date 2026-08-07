#include <unordered_map>
#include <mutex>
#include "include/ntoskrnl_struct.h"

namespace HandleManager {
    extern std::mutex HandleLock;
    bool AddMap(uintptr_t, uintptr_t);
    uintptr_t GetHandle(uintptr_t);
} // namespace HandleManager

#pragma comment(lib, "Onecore.lib")

namespace TimerManager {
    extern std::unordered_map<_KTIMER*, uint64_t> timer_manager;
    extern std::mutex TimerLock;
}

namespace MutexManager {
    extern std::unordered_map<uintptr_t, uint64_t> mutex_manager;
    extern std::mutex MutexLock;
}