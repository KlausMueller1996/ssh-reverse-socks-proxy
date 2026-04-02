#pragma once
#include <cstdint>
#include <string>
#include <stdexcept>
#include "../public/ssh_proxy.h"

// Internal configuration struct — NOT part of the public API.
// ssh_proxy::Connect stores this internally after validating constructor args.
struct ConnectionConfig {
    std::string          server_host;
    uint16_t             server_port            = 22;
    std::string          username;
    std::string          password;
    uint32_t             connect_timeout_ms     = 10000;
    uint32_t             keepalive_interval_ms  = 30000;
    uint16_t             forward_port           = 1080;
    ssh_proxy::LogLevel  log_level              = ssh_proxy::LogLevel::Info;

    // Validate fields that would cause silent failures later.
    // Throws std::runtime_error with a descriptive message on bad input.
    void validate() const {
        if (server_host.empty())
            throw std::runtime_error("server_host must not be empty");
        if (server_port == 0)
            throw std::runtime_error("server_port must not be zero");
        if (username.empty())
            throw std::runtime_error("username must not be empty");
        if (forward_port == 0)
            throw std::runtime_error("forward_port must not be zero");
        if (connect_timeout_ms == 0)
            throw std::runtime_error("connect_timeout_ms must not be zero");
    }
};
