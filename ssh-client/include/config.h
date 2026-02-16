#pragma once
#include "common.h"
#include <string>

enum class LogLevel : int {
    Debug = 0,
    Info,
    Warn,
    Error,
};

struct AppConfig {
    std::string server_host = "127.0.0.1";
    uint16_t    server_port = 8443;
    bool        verify_certificate = true;
    int         reconnect_delay_initial_ms = 1000;
    int         reconnect_delay_max_ms = 60000;
    int         keepalive_interval_ms = 30000;
    int         io_thread_count = 0;            // 0 = CPU count
    LogLevel    log_level = LogLevel::Info;
    uint32_t    channel_window_size = 256 * 1024; // 256 KB
};

// Parse command-line arguments into AppConfig.
// Returns Success, or InvalidArgument on bad input (msg printed to stderr).
ErrorCode ParseCommandLine(int argc, char* argv[], AppConfig& out);
