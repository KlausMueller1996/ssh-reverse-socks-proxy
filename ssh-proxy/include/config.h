#pragma once
#include "../../ssh-proxy-lib/public/ssh_proxy.h"
#include <cstdint>
#include <string>

// CLI arguments parsed from the command line.
// Fields mirror the ssh_proxy::Connect constructor parameters.
struct CliArgs {
    std::string          server_host;
    uint16_t             server_port           = 22;
    std::string          username;
    std::string          password;
    uint16_t             forward_port          = 1080;
    uint32_t             connect_timeout_ms    = 10000;
    uint32_t             keepalive_interval_ms = 30000;
    ssh_proxy::LogLevel  log_level             = ssh_proxy::LogLevel::Info;
};

// Parse command-line arguments into CliArgs.
// Returns true on success, false on bad input (error printed to stderr).
// Sets args.server_host empty on --help (caller should exit 0).
bool ParseCommandLine(int argc, char* argv[], CliArgs& args);
