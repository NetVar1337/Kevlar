#include "include/common.h"
#include "ex_pool.h"

void* hM_AllocPoolTag(uint32_t pooltype, size_t size, ULONG tag) {
    __try {
        return (void*)UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), size, tag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        char TagStr[5] = {};
        memcpy(TagStr, &tag, 4);
        Logger::Log("{RED}ExAllocatePoolWithTag EXCEPTION 0x%08x: size=0x%llx tag='%s'{RESET}\n",
            GetExceptionCode(), (uint64_t)size, TagStr);
        return nullptr;
    }
}

void* hM_AllocPool(uint32_t pooltype, size_t size) {
    __try {
        return (void*)UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}ExAllocatePool EXCEPTION 0x%08x: size=0x%llx{RESET}\n",
            GetExceptionCode(), (uint64_t)size);
        return nullptr;
    }
}

void h_DeAllocPoolTag(uintptr_t ptr, ULONG tag) {
    UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), (uint64_t)ptr);
    return;
}

void h_DeAllocPool(uintptr_t ptr) {
    UnicornMem::FreePool(UnicornThread::GetCurrentEngine(), (uint64_t)ptr);
    return;
}

void* h_ExAllocatePool2(uint64_t Flags, size_t NumberOfBytes, ULONG Tag) {
    __try {
        return (void*)UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), NumberOfBytes, Tag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}ExAllocatePool2 EXCEPTION 0x%08x: size=0x%llx{RESET}\n",
            GetExceptionCode(), (uint64_t)NumberOfBytes);
        return nullptr;
    }
}

void* h_ExAllocatePool3(uint64_t Flags, size_t NumberOfBytes, ULONG Tag, PVOID ExtendedParameters, ULONG ExtendedParametersCount) {
    __try {
        return (void*)UnicornMem::AllocatePoolWithTag(UnicornThread::GetCurrentEngine(), NumberOfBytes, Tag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}ExAllocatePool3 EXCEPTION 0x%08x: size=0x%llx{RESET}\n",
            GetExceptionCode(), (uint64_t)NumberOfBytes);
        return nullptr;
    }
}

PVOID h_ExAllocatePoolZero(uint32_t PoolType, size_t NumberOfBytes) {
    __try {
        return (void*)UnicornMem::AllocatePool(UnicornThread::GetCurrentEngine(), NumberOfBytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("{RED}ExAllocatePoolZero EXCEPTION 0x%08x: size=0x%llx{RESET}\n",
            GetExceptionCode(), (uint64_t)NumberOfBytes);
        return nullptr;
    }
}
