#pragma once
#include "common.h"
#include "../public/ssh_proxy.h"
#include <deque>
#include <mutex>
#include <string>
#include <vector>
#include <functional>

struct LogEntry {
    std::string          timestamp;  // "YYYY-MM-DD HH:MM:SS.mmm"
    ssh_proxy::LogLevel  level;
    std::string          message;
};

class Logger {
public:
    static void SetMinLevel(ssh_proxy::LogLevel level);

    static void Debug(const char* fmt, ...);
    static void Info (const char* fmt, ...);
    static void Warn (const char* fmt, ...);
    static void Error(const char* fmt, ...);

    // Optional real-time callback — fires on the calling thread for each entry
    // that passes the min-level filter. Used by the CLI to mirror entries to stderr.
    // Pass nullptr to clear.
    using LogCallback = std::function<void(const LogEntry&)>;
    static void SetCallback(LogCallback cb);

    // Snapshot the buffer for ssh_proxy::GetLog().
    static std::vector<LogEntry> Snapshot();

private:
    static void Log(ssh_proxy::LogLevel level, const char* fmt, va_list args);

    static std::mutex            s_mutex;
    static std::deque<LogEntry>  s_buffer;    // capped at k_max_entries
    static ssh_proxy::LogLevel   s_min_level;
    static LogCallback           s_callback;

    static constexpr size_t k_max_entries = 100;
};
