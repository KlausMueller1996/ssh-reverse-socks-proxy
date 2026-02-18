#include "config.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void PrintUsage(const char* exe) {
    fprintf(stderr,
        "Usage: %s --server HOST --username USER --password PASS [options]\n"
        "\n"
        "Required:\n"
        "  --server HOST           SSH server hostname or IP\n"
        "  --username / -u USER    SSH username\n"
        "  --password / -p PASS    SSH password\n"
        "\n"
        "Optional:\n"
        "  --port PORT             SSH port (default: 22)\n"
        "  --forward-port / -f N   Port to forward on server (default: 1080)\n"
        "  --connect-timeout N     TCP+SSH connect timeout in ms (default: 10000)\n"
        "  --keepalive-ms N        Keepalive interval in ms (default: 30000)\n"
        "  --log-level LEVEL       debug|info|warn|error (default: info)\n"
        "  --help                  Show this help\n",
        exe);
}

bool ParseCommandLine(int argc, char* argv[], CliArgs& args) {
    args = CliArgs{};

    bool have_server   = false;
    bool have_username = false;
    bool have_password = false;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            PrintUsage(argv[0]);
            args.server_host.clear();  // signal: --help
            return true;
        }

        // All remaining flags require a value argument
        if (i + 1 >= argc) {
            fprintf(stderr, "Error: %s requires a value\n", arg);
            return false;
        }
        const char* val = argv[++i];

        if (strcmp(arg, "--server") == 0) {
            args.server_host = val;
            have_server = true;
        } else if (strcmp(arg, "--port") == 0) {
            int p = atoi(val);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "Error: invalid port '%s'\n", val);
                return false;
            }
            args.server_port = static_cast<uint16_t>(p);
        } else if (strcmp(arg, "--username") == 0 || strcmp(arg, "-u") == 0) {
            args.username = val;
            have_username = true;
        } else if (strcmp(arg, "--password") == 0 || strcmp(arg, "-p") == 0) {
            args.password = val;
            have_password = true;
        } else if (strcmp(arg, "--forward-port") == 0 || strcmp(arg, "-f") == 0) {
            int p = atoi(val);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "Error: invalid forward-port '%s'\n", val);
                return false;
            }
            args.forward_port = static_cast<uint16_t>(p);
        } else if (strcmp(arg, "--connect-timeout") == 0) {
            args.connect_timeout_ms = static_cast<uint32_t>(atoi(val));
        } else if (strcmp(arg, "--keepalive-ms") == 0) {
            args.keepalive_interval_ms = static_cast<uint32_t>(atoi(val));
        } else if (strcmp(arg, "--log-level") == 0) {
            if      (strcmp(val, "debug") == 0) args.log_level = ssh_proxy::LogLevel::Debug;
            else if (strcmp(val, "info")  == 0) args.log_level = ssh_proxy::LogLevel::Info;
            else if (strcmp(val, "warn")  == 0) args.log_level = ssh_proxy::LogLevel::Warn;
            else if (strcmp(val, "error") == 0) args.log_level = ssh_proxy::LogLevel::Error;
            else {
                fprintf(stderr, "Error: unknown log level '%s'\n", val);
                return false;
            }
        } else {
            fprintf(stderr, "Error: unknown option '%s'\n", arg);
            return false;
        }
    }

    bool ok = true;
    if (!have_server)   { fprintf(stderr, "Error: --server is required\n");   ok = false; }
    if (!have_username) { fprintf(stderr, "Error: --username is required\n"); ok = false; }
    if (!have_password) { fprintf(stderr, "Error: --password is required\n"); ok = false; }
    return ok;
}
