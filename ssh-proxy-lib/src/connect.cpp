#include "../public/ssh_proxy.h"
#include "ssh_transport.h"
#include "socks5_session.h"
#include "logger.h"
#include "ssh_config.h"
#include "async_io.h"
#include <stdexcept>
#include <atomic>
#include <thread>

namespace ssh_proxy {

// ── Connect::Impl ─────────────────────────────────────────────────────────────

struct Connect::Impl {
    SshProxyConfig  config;
    SshTransport    transport;
    std::atomic<bool> connected{false};

    Impl() = default;
};

// ── Connect ───────────────────────────────────────────────────────────────────

Connect::Connect(
    std::string  server_host,
    std::string  username,
    std::string  password,
    uint16_t     server_port,
    uint16_t     forward_port,
    uint32_t     connect_timeout_ms,
    uint32_t     keepalive_interval_ms,
    LogLevel     log_level)
{
    m_impl = new Impl();

    m_impl->config.server_host           = std::move(server_host);
    m_impl->config.username              = std::move(username);
    m_impl->config.password              = std::move(password);
    m_impl->config.server_port           = server_port;
    m_impl->config.forward_port          = forward_port;
    m_impl->config.connect_timeout_ms    = connect_timeout_ms;
    m_impl->config.keepalive_interval_ms = keepalive_interval_ms;
    m_impl->config.log_level             = log_level;

    Logger::SetMinLevel(log_level);

    // Initialize IOCP engine (idempotent)
    ErrorCode ec = IoEngine::Init(0);
    if (ec != ErrorCode::Success) {
        delete m_impl;
        m_impl = nullptr;
        throw std::runtime_error(
            std::string("IoEngine init failed: ") + ErrorCodeToString(ec));
    }

    // Initialize libssh2 (idempotent)
    if (libssh2_init(0) != 0) {
        delete m_impl;
        m_impl = nullptr;
        throw std::runtime_error("libssh2_init failed");
    }

    const auto& cfg = m_impl->config;

    // Blocking connect (TCP + SSH handshake + auth + port-forward request)
    ec = m_impl->transport.Connect(
        cfg.server_host, cfg.server_port,
        cfg.username, cfg.password,
        cfg.forward_port,
        cfg.connect_timeout_ms,
        cfg.keepalive_interval_ms);

    if (ec != ErrorCode::Success) {
        delete m_impl;
        m_impl = nullptr;
        throw std::runtime_error(
            std::string("SSH connect failed: ") + ErrorCodeToString(ec));
    }

    m_impl->connected.store(true);

    // Start the channel-accept loop on the internal I/O thread
    m_impl->transport.StartAccepting(
        // on_channel: fired for each forwarded-tcpip channel
        [](std::unique_ptr<SshChannel> ch) {
            auto session = std::make_shared<Socks5Session>(std::move(ch));
            session->Start();
        },
        // on_disconnect: fired when the session drops unexpectedly
        [impl = m_impl](ErrorCode reason) {
            Logger::Warn("SSH session disconnected: %s", ErrorCodeToString(reason));
            impl->connected.store(false);
        });
}

Connect::~Connect() {
    if (m_impl) {
        m_impl->transport.Close();
        delete m_impl;
        m_impl = nullptr;
    }
}

void Connect::Cancel() {
    if (m_impl)
        m_impl->transport.Close();
}

bool Connect::IsConnected() const {
    return m_impl && m_impl->connected.load();
}

} // namespace ssh_proxy
