#include "logger.h"
#include <cstdarg>
#include <cstdio>
#include <sstream>
#include <iomanip>

// Static member definitions
std::mutex            Logger::s_mutex;
std::deque<LogEntry>  Logger::s_buffer;
ssh_proxy::LogLevel   Logger::s_min_level = ssh_proxy::LogLevel::Info;
Logger::LogCallback   Logger::s_callback;

void Logger::SetMinLevel(ssh_proxy::LogLevel level) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_min_level = level;
}

void Logger::SetCallback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_callback = std::move(cb);
}

std::vector<LogEntry> Logger::Snapshot() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return std::vector<LogEntry>(s_buffer.begin(), s_buffer.end());
}

void Logger::Debug(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    Log(ssh_proxy::LogLevel::Debug, fmt, args);
    va_end(args);
}
void Logger::Info(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    Log(ssh_proxy::LogLevel::Info, fmt, args);
    va_end(args);
}
void Logger::Warn(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    Log(ssh_proxy::LogLevel::Warn, fmt, args);
    va_end(args);
}
void Logger::Error(const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    Log(ssh_proxy::LogLevel::Error, fmt, args);
    va_end(args);
}

void Logger::Log(ssh_proxy::LogLevel level, const char* fmt, va_list args) {
    // Check level before formatting
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (static_cast<int>(level) < static_cast<int>(s_min_level))
            return;
    }

    // Format message
    char msg_buf[1024];
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);

    // Build timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts_buf[32];
    snprintf(ts_buf, sizeof(ts_buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    LogEntry entry;
    entry.timestamp = ts_buf;
    entry.level     = level;
    entry.message   = msg_buf;

    LogCallback cb_copy;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        if (s_buffer.size() >= k_max_entries)
            s_buffer.pop_front();
        s_buffer.push_back(entry);
        cb_copy = s_callback;
    }

    if (cb_copy)
        cb_copy(entry);
}

// ── ssh_proxy::GetLog() ───────────────────────────────────────────────────────

namespace ssh_proxy {

std::string GetLog() {
    static const char* level_tags[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };

    auto entries = Logger::Snapshot();
    std::string out;
    out.reserve(entries.size() * 80);
    for (const auto& e : entries) {
        int idx = static_cast<int>(e.level);
        if (idx < 0 || idx > 3) idx = 3;
        out += e.timestamp;
        out += " [";
        out += level_tags[idx];
        out += "] ";
        out += e.message;
        out += '\n';
    }
    return out;
}

} // namespace ssh_proxy
