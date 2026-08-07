#include "Logger.h"
#include <windows.h>
#include <mutex>
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <filesystem>

struct ColorTag {
    const char* Tag;
    WORD Attr;
};
static constexpr ColorTag kColorTags[] = {
    { "{RED}", 12 },
    { "{GRN}", 10 },
    { "{YEL}", 14 },
    { "{CYN}", 11 },
    { "{MAG}", 13 },
    { "{BLU}", 9 },
    { "{WHT}", 15 },
    { "{GRY}", 8 },
    { "{RESET}", 7 },
};

static HANDLE hConsole = INVALID_HANDLE_VALUE;
static FILE* hLogFile = nullptr;
static std::mutex logMutex;
static bool gPerThreadEnabled = false;
static std::string gPerThreadFolder;
static uint32_t gNextThreadIndex = 1;

struct ThreadLogFile {
    uint32_t Index = 0;
    bool Started = false;
    FILE* File = nullptr;
};

static std::unordered_map<DWORD, ThreadLogFile> gThreadLogs;

static void EnsureConsole() {
    if (hConsole == INVALID_HANDLE_VALUE)
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
}

static void SetColor(WORD attr) {
    EnsureConsole();
    SetConsoleTextAttribute(hConsole, attr);
}

static void ResetColor() { SetColor(7); }

static void StripColorTags(const char* src, char* dst, size_t dstSize) {
    size_t j = 0;
    while (*src && j + 1 < dstSize) {
        bool matched = false;
        for (auto& ct : kColorTags) {
            size_t tlen = strlen(ct.Tag);
            if (strncmp(src, ct.Tag, tlen) == 0) {
                src += tlen;
                matched = true;
                break;
            }
        }
        if (!matched) {
            dst[j++] = *src++;
        }
    }
    dst[j] = '\0';
}

static void PrintColored(const char* s) {
    EnsureConsole();
    while (*s) {
        bool matched = false;
        for (auto& ct : kColorTags) {
            size_t tlen = strlen(ct.Tag);
            if (strncmp(s, ct.Tag, tlen) == 0) {
                SetColor(ct.Attr);
                s += tlen;
                matched = true;
                break;
            }
        }
        if (!matched) {
            putchar(*s++);
        }
    }
}

static void BuildTimestamp(char* Out, size_t OutSize) {
    SYSTEMTIME St;
    GetLocalTime(&St);
    snprintf(Out, OutSize, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        St.wYear, St.wMonth, St.wDay, St.wHour, St.wMinute, St.wSecond, St.wMilliseconds);
}

static ThreadLogFile* GetOrCreateThreadLogLocked(DWORD Tid) {
    if (!gPerThreadEnabled || gPerThreadFolder.empty()) return nullptr;

    auto It = gThreadLogs.find(Tid);
    if (It != gThreadLogs.end()) return &It->second;

    ThreadLogFile Entry;
    Entry.Index = gNextThreadIndex++;

    char ThreadPath[MAX_PATH] = {};
    snprintf(ThreadPath, sizeof(ThreadPath), "%s\\thread%u.txt", gPerThreadFolder.c_str(), Entry.Index);
    fopen_s(&Entry.File, ThreadPath, "a");

    if (Entry.File) {
        char Ts[64] = {};
        BuildTimestamp(Ts, sizeof(Ts));
        fprintf(Entry.File, "=== THREAD LOG OPENED %s host_tid=%lu file_index=%u ===\n", Ts, (unsigned long)Tid, Entry.Index);
        fflush(Entry.File);
    }

    auto Inserted = gThreadLogs.emplace(Tid, Entry);
    return &Inserted.first->second;
}

static void EnsureThreadStartLocked(DWORD Tid, const char* Reason) {
    auto T = GetOrCreateThreadLogLocked(Tid);
    if (!T || !T->File || T->Started) return;

    char Ts[64] = {};
    BuildTimestamp(Ts, sizeof(Ts));
    fprintf(T->File, "[THREAD START] ts=%s host_tid=%lu", Ts, (unsigned long)Tid);
    if (Reason && Reason[0]) fprintf(T->File, " reason=%s", Reason);
    fprintf(T->File, "\n");
    fflush(T->File);
    T->Started = true;
}

static void WriteThreadLogLocked(const char* CleanLine) {
    if (!gPerThreadEnabled || !CleanLine || !CleanLine[0]) return;
    DWORD Tid = GetCurrentThreadId();
    EnsureThreadStartLocked(Tid, "first_log");
    auto T = GetOrCreateThreadLogLocked(Tid);
    if (!T || !T->File) return;
    fprintf(T->File, "%s", CleanLine);
    fflush(T->File);
}

static void MarkThreadEndLocked(DWORD Tid, const char* Reason) {
    auto T = GetOrCreateThreadLogLocked(Tid);
    if (!T || !T->File) return;
    if (!T->Started) EnsureThreadStartLocked(Tid, "implicit_before_end");

    char Ts[64] = {};
    BuildTimestamp(Ts, sizeof(Ts));
    fprintf(T->File, "[THREAD END] ts=%s host_tid=%lu", Ts, (unsigned long)Tid);
    if (Reason && Reason[0]) fprintf(T->File, " reason=%s", Reason);
    fprintf(T->File, "\n");
    fflush(T->File);
}

bool Logger::InitFile(const char* Path) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (hLogFile) {
        fclose(hLogFile);
        hLogFile = nullptr;
    }
    fopen_s(&hLogFile, Path, "a");
    if (hLogFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(hLogFile, "\n=== KEVLAR Log Started %04d-%02d-%02d %02d:%02d:%02d ===\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(hLogFile);
        return true;
    }
    return false;
}

bool Logger::EnablePerThreadFiles(const char* FolderPath) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (!FolderPath || !FolderPath[0]) return false;

    std::filesystem::create_directories(FolderPath);
    gPerThreadFolder = FolderPath;
    gPerThreadEnabled = true;

    for (auto& Kv : gThreadLogs) {
        if (Kv.second.File) {
            fclose(Kv.second.File);
            Kv.second.File = nullptr;
        }
    }
    gThreadLogs.clear();
    gNextThreadIndex = 1;
    return true;
}

void Logger::MarkThreadStart(const char* Reason) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (!gPerThreadEnabled) return;
    EnsureThreadStartLocked(GetCurrentThreadId(), Reason ? Reason : "manual");
}

void Logger::MarkThreadEnd(const char* Reason) {
    std::lock_guard<std::mutex> guard(logMutex);
    if (!gPerThreadEnabled) return;
    MarkThreadEndLocked(GetCurrentThreadId(), Reason ? Reason : "manual");
}

void Logger::CloseFile() {
    std::lock_guard<std::mutex> guard(logMutex);

    if (gPerThreadEnabled) {
        for (auto& Kv : gThreadLogs) {
            auto Tid = Kv.first;
            auto& T = Kv.second;
            if (!T.File) continue;
            if (T.Started) {
                char Ts[64] = {};
                BuildTimestamp(Ts, sizeof(Ts));
                fprintf(T.File, "[THREAD END] ts=%s host_tid=%lu reason=logger_close\n", Ts, (unsigned long)Tid);
            }
            fclose(T.File);
            T.File = nullptr;
        }
        gThreadLogs.clear();
    }

    if (hLogFile) {
        fclose(hLogFile);
        hLogFile = nullptr;
    }
}

void Logger::Log(const char* format, ...) {
    char buf[4096];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    if (n <= 0) return;

    std::lock_guard<std::mutex> guard(logMutex);
    PrintColored(buf);
    ResetColor();

    if (hLogFile) {
        char clean[4096];
        StripColorTags(buf, clean, sizeof(clean));
        fprintf(hLogFile, "%s", clean);
        fflush(hLogFile);
        WriteThreadLogLocked(clean);
    } else {
        char clean[4096];
        StripColorTags(buf, clean, sizeof(clean));
        WriteThreadLogLocked(clean);
    }
}

void Logger::Log(wchar_t* format, ...) {
    wchar_t wbuf[2048];
    va_list args;
    va_start(args, format);
    int n = vswprintf(wbuf, sizeof(wbuf) / sizeof(wchar_t), format, args);
    va_end(args);
    if (n <= 0) return;

    char narrow[4096];
    wcstombs_s(nullptr, narrow, wbuf, _TRUNCATE);

    std::lock_guard<std::mutex> guard(logMutex);
    PrintColored(narrow);
    ResetColor();

    if (hLogFile) {
        char clean[4096];
        StripColorTags(narrow, clean, sizeof(clean));
        fprintf(hLogFile, "%s", clean);
        fflush(hLogFile);
        WriteThreadLogLocked(clean);
    } else {
        char clean[4096];
        StripColorTags(narrow, clean, sizeof(clean));
        WriteThreadLogLocked(clean);
    }
}

void Logger::Log(LogColor color, const char* format, ...) {
    char buf[4096];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    if (n <= 0) return;

    std::lock_guard<std::mutex> guard(logMutex);
    SetColor(static_cast<WORD>(color));
    PrintColored(buf);
    ResetColor();

    if (hLogFile) {
        char clean[4096];
        StripColorTags(buf, clean, sizeof(clean));
        fprintf(hLogFile, "%s", clean);
        fflush(hLogFile);
        WriteThreadLogLocked(clean);
    } else {
        char clean[4096];
        StripColorTags(buf, clean, sizeof(clean));
        WriteThreadLogLocked(clean);
    }
}
