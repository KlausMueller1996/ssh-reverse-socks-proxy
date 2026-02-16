#pragma once
#include "config.h"
#include <cstdarg>

class Logger {
public:
    static void Init(LogLevel min_level);

    static void Debug(const char* fmt, ...);
    static void Info(const char* fmt, ...);
    static void Warn(const char* fmt, ...);
    static void Error(const char* fmt, ...);

private:
    static void Log(LogLevel level, const char* fmt, va_list args);

    static LogLevel       s_min_level;
    static CRITICAL_SECTION s_cs;
    static bool           s_initialized;
};
