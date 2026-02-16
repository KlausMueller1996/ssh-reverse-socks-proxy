#include "config.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void PrintUsage(const char* exe) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --server HOST       Server hostname or IP (default: 127.0.0.1)\n"
        "  --port PORT         Server port (default: 8443)\n"
        "  --no-verify         Skip TLS certificate verification\n"
        "  --reconnect-ms N    Initial reconnect delay in ms (default: 1000)\n"
        "  --reconnect-max N   Max reconnect delay in ms (default: 60000)\n"
        "  --keepalive-ms N    Keepalive interval in ms (default: 30000)\n"
        "  --threads N         IOCP worker threads, 0=auto (default: 0)\n"
        "  --log-level LEVEL   debug|info|warn|error (default: info)\n"
        "  --help              Show this help\n",
        exe);
}

ErrorCode ParseCommandLine(int argc, char* argv[], AppConfig& out) {
    out = AppConfig{};

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            PrintUsage(argv[0]);
            return ErrorCode::Shutdown;
        }

        if (strcmp(arg, "--no-verify") == 0) {
            out.verify_certificate = false;
            continue;
        }

        // All remaining flags require a value
        if (i + 1 >= argc) {
            fprintf(stderr, "Error: %s requires a value\n", arg);
            return ErrorCode::InvalidArgument;
        }

        const char* val = argv[++i];

        if (strcmp(arg, "--server") == 0) {
            out.server_host = val;
        } else if (strcmp(arg, "--port") == 0) {
            int p = atoi(val);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "Error: invalid port %s\n", val);
                return ErrorCode::InvalidArgument;
            }
            out.server_port = static_cast<uint16_t>(p);
        } else if (strcmp(arg, "--reconnect-ms") == 0) {
            out.reconnect_delay_initial_ms = atoi(val);
        } else if (strcmp(arg, "--reconnect-max") == 0) {
            out.reconnect_delay_max_ms = atoi(val);
        } else if (strcmp(arg, "--keepalive-ms") == 0) {
            out.keepalive_interval_ms = atoi(val);
        } else if (strcmp(arg, "--threads") == 0) {
            out.io_thread_count = atoi(val);
        } else if (strcmp(arg, "--log-level") == 0) {
            if (strcmp(val, "debug") == 0)      out.log_level = LogLevel::Debug;
            else if (strcmp(val, "info") == 0)   out.log_level = LogLevel::Info;
            else if (strcmp(val, "warn") == 0)   out.log_level = LogLevel::Warn;
            else if (strcmp(val, "error") == 0)  out.log_level = LogLevel::Error;
            else {
                fprintf(stderr, "Error: unknown log level '%s'\n", val);
                return ErrorCode::InvalidArgument;
            }
        } else {
            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            return ErrorCode::InvalidArgument;
        }
    }

    return ErrorCode::Success;
}
