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
        if (ec != ErrorCode::Success) 
        {
            delete m_impl;
            m_impl = nullptr;
            throw std::runtime_error(std::string("IoEngine init failed: ") + ErrorCodeToString(ec));
        }

        // Initialize libssh2 (idempotent)
        if (libssh2_init(0) != 0) 
        {
            delete m_impl;
            m_impl = nullptr;
            throw std::runtime_error("libssh2_init failed");
        }

        const auto& cfg = m_impl->config;

        // Blocking connect (TCP + SSH handshake + auth + port-forward request)
        auto connect_result = m_impl->transport.Connect(
            cfg.server_host, 
            cfg.server_port,
            cfg.username, 
            cfg.password,
            cfg.forward_port,
            cfg.connect_timeout_ms,
            cfg.keepalive_interval_ms);

        if (!connect_result.ok()) 
        {
            delete m_impl;
            m_impl = nullptr;
            throw std::runtime_error(connect_result.what());
        }

        m_impl->connected.store(true);

        // Start the channel-accept loop on the internal I/O thread
        m_impl->transport.StartAccepting(
            // on_channel: fired on the SSH I/O thread for each forwarded-tcpip channel.
            [impl = m_impl](std::unique_ptr<SshChannel> ch) {
                auto session = std::make_shared<Socks5Session>(std::move(ch));

                // Register the SSH→TCP pump so the I/O thread drives it each
                // loop iteration instead of blocking an IOCP worker thread.
                impl->transport.RegisterSessionPump([session]() -> bool {
                    return session->PumpSshRead();
                });

                // Run the SOCKS5 handshake synchronously on the I/O thread.
                // Start() is non-blocking after this change: it reads the method
                // request and CONNECT request, then fires an async TCP connect and
                // returns. The relay is driven by the pump above.
                session->Start();
            },
            // on_disconnect: fired when the session drops unexpectedly
            [impl = m_impl](ErrorCode reason) {
                Logger::Warn("SSH session disconnected: %s", ErrorCodeToString(reason));
                impl->connected.store(false);
            });
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
        {
            m_impl->transport.Close();
        }
    }

    bool Connect::IsConnected() const 
    {
        return m_impl && m_impl->connected.load();
    }

} // namespace ssh_proxy