#pragma once
#include <cstdint>
#include <string>
#include "../public/ssh_proxy.h"

// Internal configuration struct — NOT part of the public API.
// ssh_proxy::Connect stores this internally after validating constructor args.
struct SshProxyConfig {
    std::string          server_host;
    uint16_t             server_port            = 22;
    std::string          username;
    std::string          password;
    uint32_t             connect_timeout_ms     = 10000;
    uint32_t             keepalive_interval_ms  = 30000;
    uint16_t             forward_port           = 1080;
    ssh_proxy::LogLevel  log_level              = ssh_proxy::LogLevel::Info;
};
