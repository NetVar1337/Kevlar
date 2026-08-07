#pragma once

#include <string>

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#endif

namespace KevlarGlobal {
    inline std::string ExeDir;

    inline std::string GetImportDir() { return ExeDir; }
    inline std::string GetCacheDir() { return ExeDir + "pdb_cache\\"; }
}
