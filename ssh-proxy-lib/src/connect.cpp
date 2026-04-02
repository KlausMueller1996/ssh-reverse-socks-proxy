#include "../public/ssh_proxy.h"
#include "ssh_transport.h"
#include "socks5_session.h"
#include "logger.h"
#include "ssh_config.h"
#include "async_io.h"
#include <stdexcept>
#include <atomic>
#include <memory>
#include <thread>

namespace ssh_proxy {

    // ── Connect::Impl ─────────────────────────────────────────────────────────────

    struct Connect::Impl {
        ConnectionConfig  config;
        SshTransport      transport;
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
        std::unique_ptr<Impl> guard(new Impl());

        guard->config.server_host           = std::move(server_host);
        guard->config.username              = std::move(username);
        guard->config.password              = std::move(password);
        guard->config.server_port           = server_port;
        guard->config.forward_port          = forward_port;
        guard->config.connect_timeout_ms    = connect_timeout_ms;
        guard->config.keepalive_interval_ms = keepalive_interval_ms;
        guard->config.log_level             = log_level;

        // Validate before doing any I/O (throws std::runtime_error on bad input).
        guard->config.validate();

        Logger::SetMinLevel(log_level);

        // Initialize IOCP engine (idempotent)
        ErrorCode ec = IoEngine::Init(0);
        if (ec != ErrorCode::Success)
            throw std::runtime_error(std::string("IoEngine init failed: ") + ErrorCodeToString(ec));

        // Initialize libssh2 (idempotent)
        if (libssh2_init(0) != 0)
            throw std::runtime_error("libssh2_init failed");

        const auto& cfg = guard->config;

        // Blocking connect (TCP + SSH handshake + auth + port-forward request)
        auto connect_result = guard->transport.Connect(
            cfg.server_host,
            cfg.server_port,
            cfg.username,
            cfg.password,
            cfg.forward_port,
            cfg.connect_timeout_ms,
            cfg.keepalive_interval_ms);

        if (!connect_result.ok())
            throw std::runtime_error(connect_result.what());

        guard->connected.store(true);

        // Start the channel-accept loop on the internal I/O thread.
        // on_channel returns a pump function that the transport auto-registers.
        Impl* impl = guard.get();
        impl->transport.StartAccepting(
            [impl](std::unique_ptr<SshChannel> ch) -> SshTransport::SessionPumpFn {
                auto session = std::make_shared<Socks5Session>(std::move(ch));
                session->Start();
                return [session]() -> bool {
                    return session->PumpSshRead();
                };
            },
            [impl](ErrorCode reason) {
                Logger::Warn("SSH session disconnected: %s", ErrorCodeToString(reason));
                impl->connected.store(false);
            });

        m_impl = guard.release();
    }

    Connect::~Connect()
    {
        if (m_impl != nullptr)
        {
            m_impl->transport.Close();
            delete m_impl;
            m_impl = nullptr;
        }
    }

    void Connect::Cancel()
    {
        if (m_impl != nullptr)
            m_impl->transport.Close();
    }

    bool Connect::IsConnected() const
    {
        return m_impl && m_impl->connected.load();
    }

} // namespace ssh_proxy
