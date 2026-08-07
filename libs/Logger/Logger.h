#pragma once

#include <string>
enum class LogColor {
    Default = 7,
    Red = 12,
    Green = 10,
    Yellow = 14,
    Cyan = 11,
    Magenta = 13,
    Blue = 9,
    White = 15,
    Gray = 8,
};

class Logger {
public:
    static void Log(const char* format, ...);
    static void Log(wchar_t* format, ...);
    static void Log(LogColor color, const char* format, ...);
    static bool InitFile(const char* Path);
    static bool EnablePerThreadFiles(const char* FolderPath);
    static void MarkThreadStart(const char* Reason = nullptr);
    static void MarkThreadEnd(const char* Reason = nullptr);
    static void CloseFile();
};
