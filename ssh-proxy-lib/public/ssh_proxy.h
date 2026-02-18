#pragma once
#include <cstdint>
#include <string>

namespace ssh_proxy {

// ── Log level ──────────────────────────────────────────────────────────────────
enum class LogLevel { Debug, Info, Warn, Error };

// ── RAII connection handle ─────────────────────────────────────────────────────
// Constructor synchronously connects to the SSH server and starts an internal
// I/O thread that runs the channel-accept loop.
// Throws std::runtime_error with a descriptive message on failure.
// Destructor cancels the session and joins the I/O thread.
class Connect {
public:
    Connect(
        std::string  server_host,
        std::string  username,
        std::string  password,
        uint16_t     server_port           = 22,
        uint16_t     forward_port          = 1080,
        uint32_t     connect_timeout_ms    = 10000,
        uint32_t     keepalive_interval_ms = 30000,
        LogLevel     log_level             = LogLevel::Info
    );

    ~Connect();

    Connect(const Connect&)            = delete;
    Connect& operator=(const Connect&) = delete;

    // Signal the I/O thread to stop. Thread-safe. Returns immediately;
    // the destructor joins the thread.
    void Cancel();

    // True while the session is active. Becomes false after Cancel()
    // or an unexpected session drop.
    bool IsConnected() const;

private:
    struct Impl;
    Impl* m_impl;
};

// ── Utilities ──────────────────────────────────────────────────────────────────
// Returns the last ≤100 log entries as a formatted string (oldest first).
// Each line: "YYYY-MM-DD HH:MM:SS.mmm [LEVEL] message\n"
std::string GetLog();

} // namespace ssh_proxy
