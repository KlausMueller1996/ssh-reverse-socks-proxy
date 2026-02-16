#include "logger.h"
#include <cstdio>
#include <cstdarg>

LogLevel         Logger::s_min_level = LogLevel::Info;
CRITICAL_SECTION Logger::s_cs;
bool             Logger::s_initialized = false;

void Logger::Init(LogLevel min_level) {
    if (!s_initialized) {
        InitializeCriticalSection(&s_cs);
        s_initialized = true;
    }
    s_min_level = min_level;
}

void Logger::Debug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LogLevel::Debug, fmt, args);
    va_end(args);
}

void Logger::Info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LogLevel::Info, fmt, args);
    va_end(args);
}

void Logger::Warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LogLevel::Warn, fmt, args);
    va_end(args);
}

void Logger::Error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LogLevel::Error, fmt, args);
    va_end(args);
}

void Logger::Log(LogLevel level, const char* fmt, va_list args) {
    if (static_cast<int>(level) < static_cast<int>(s_min_level))
        return;

    static const char* level_tags[] = { "DBG", "INF", "WRN", "ERR" };

    SYSTEMTIME st;
    GetLocalTime(&st);

    DWORD tid = GetCurrentThreadId();

    EnterCriticalSection(&s_cs);

    fprintf(stderr, "%04u-%02u-%02u %02u:%02u:%02u.%03u [%s] [%05lu] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        level_tags[static_cast<int>(level)],
        static_cast<unsigned long>(tid));
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);

    LeaveCriticalSection(&s_cs);
}
