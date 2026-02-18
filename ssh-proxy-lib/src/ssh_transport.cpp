#include "ssh_transport.h"
#include "logger.h"
#include <cstring>
#include <stdexcept>

// ── SshChannel ────────────────────────────────────────────────────────────────

ErrorCode SshChannel::Read(uint8_t* buf, size_t len, size_t& bytes_read) {
    bytes_read = 0;
    if (!m_channel) return ErrorCode::ChannelClosed;

    for (;;) {
        ssize_t n = libssh2_channel_read(m_channel,
                                         reinterpret_cast<char*>(buf),
                                         len);
        if (n > 0) {
            bytes_read = static_cast<size_t>(n);
            return ErrorCode::Success;
        }
        if (n == 0 || libssh2_channel_eof(m_channel)) {
            return ErrorCode::ChannelClosed;
        }
        if (n == LIBSSH2_ERROR_EAGAIN) {
            // Caller should select/poll; for now yield and retry
            Sleep(1);
            continue;
        }
        Logger::Error("libssh2_channel_read failed: %d", static_cast<int>(n));
        return ErrorCode::ProtocolError;
    }
}

ErrorCode SshChannel::Write(const uint8_t* buf, size_t len) {
    if (!m_channel) return ErrorCode::ChannelClosed;

    size_t written = 0;
    while (written < len) {
        ssize_t n = libssh2_channel_write(m_channel,
                                          reinterpret_cast<const char*>(buf + written),
                                          len - written);
        if (n > 0) {
            written += static_cast<size_t>(n);
            continue;
        }
        if (n == LIBSSH2_ERROR_EAGAIN) {
            Sleep(1);
            continue;
        }
        Logger::Error("libssh2_channel_write failed: %d", static_cast<int>(n));
        return ErrorCode::ProtocolError;
    }
    return ErrorCode::Success;
}

void SshChannel::SendEof() {
    if (m_channel) libssh2_channel_send_eof(m_channel);
}

void SshChannel::Close() {
    if (m_channel) {
        libssh2_channel_close(m_channel);
        libssh2_channel_free(m_channel);
        m_channel = nullptr;
    }
}

bool SshChannel::IsEof() const {
    return m_channel ? libssh2_channel_eof(m_channel) != 0 : true;
}

// ── SshTransport ──────────────────────────────────────────────────────────────

SshTransport::SshTransport() = default;

SshTransport::~SshTransport() {
    Close();
}

ErrorCode SshTransport::Connect(const std::string& host, uint16_t port,
                                 const std::string& username,
                                 const std::string& password,
                                 uint16_t forward_port,
                                 uint32_t timeout_ms,
                                 uint32_t keepalive_interval_ms) {
    // ── TCP connect ───────────────────────────────────────────────────────────
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host.c_str(), port_str, &hints, &result) != 0 || !result) {
        Logger::Error("DNS resolve failed for %s", host.c_str());
        return ErrorCode::DnsResolutionFailed;
    }

    m_socket = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
        freeaddrinfo(result);
        Logger::Error("socket() failed: %d", WSAGetLastError());
        return ErrorCode::SocketError;
    }

    // Apply connect timeout via SO_RCVTIMEO/SO_SNDTIMEO on a blocking socket
    DWORD tv_ms = timeout_ms;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

    if (::connect(m_socket, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        int err = WSAGetLastError();
        freeaddrinfo(result);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        Logger::Error("TCP connect to %s:%u failed: %d", host.c_str(), port, err);
        return WsaToErrorCode(err);
    }
    freeaddrinfo(result);
    Logger::Info("TCP connected to %s:%u", host.c_str(), port);

    // ── libssh2 session ───────────────────────────────────────────────────────
    m_session = libssh2_session_init();
    if (!m_session) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        Logger::Error("libssh2_session_init failed");
        return ErrorCode::SshHandshakeFailed;
    }

    libssh2_session_set_blocking(m_session, 1);

    if (libssh2_session_handshake(m_session, m_socket) != 0) {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_session, &errmsg, nullptr, 0);
        Logger::Error("SSH handshake failed: %s", errmsg ? errmsg : "unknown");
        libssh2_session_free(m_session);
        m_session = nullptr;
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return ErrorCode::SshHandshakeFailed;
    }

    // Log host key fingerprint at DEBUG (trust-all policy — no verification)
    const char* fingerprint = libssh2_hostkey_hash(m_session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (fingerprint) {
        char fp_hex[65] = {};
        for (int i = 0; i < 32; ++i)
            snprintf(fp_hex + i * 2, 3, "%02x", static_cast<unsigned char>(fingerprint[i]));
        Logger::Debug("SSH host key SHA-256: %s", fp_hex);
    }

    // ── Password authentication ───────────────────────────────────────────────
    if (libssh2_userauth_password(m_session,
                                  username.c_str(),
                                  password.c_str()) != 0) {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_session, &errmsg, nullptr, 0);
        Logger::Error("SSH auth failed for user '%s': %s",
                      username.c_str(), errmsg ? errmsg : "unknown");
        libssh2_session_disconnect(m_session, "Auth failed");
        libssh2_session_free(m_session);
        m_session = nullptr;
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return ErrorCode::SshAuthFailed;
    }
    Logger::Info("SSH authenticated as '%s'", username.c_str());

    // ── Remote port forwarding ────────────────────────────────────────────────
    int bound_port = 0;
    m_listener = libssh2_channel_forward_listen_ex(
        m_session,
        "127.0.0.1",
        forward_port,
        &bound_port,
        /*queue_maxsize=*/16);

    if (!m_listener) {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_session, &errmsg, nullptr, 0);
        Logger::Error("tcpip-forward request failed (port %u): %s",
                      forward_port, errmsg ? errmsg : "unknown");
        libssh2_session_disconnect(m_session, "Forward failed");
        libssh2_session_free(m_session);
        m_session = nullptr;
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return ErrorCode::SshChannelOpenFailed;
    }
    Logger::Info("Remote port forwarding active: 127.0.0.1:%d → SOCKS5", bound_port);

    // Configure keepalives
    if (keepalive_interval_ms > 0) {
        libssh2_keepalive_config(m_session, 1,
            static_cast<unsigned>(keepalive_interval_ms / 1000));
    }

    // Switch to non-blocking for the accept loop
    libssh2_session_set_blocking(m_session, 0);

    m_connected.store(true);
    return ErrorCode::Success;
}

void SshTransport::StartAccepting(OnChannelAccepted on_channel,
                                   OnDisconnected on_disconnect) {
    m_io_thread = std::thread(&SshTransport::IoThreadProc, this,
                              std::move(on_channel), std::move(on_disconnect));
}

void SshTransport::IoThreadProc(OnChannelAccepted on_channel,
                                 OnDisconnected on_disconnect) {
    Logger::Debug("SSH I/O thread started");

    ErrorCode disconnect_reason = ErrorCode::Success;

    while (!m_cancel.load()) {
        // ── Send keepalives ───────────────────────────────────────────────────
        int next_keepalive = 0;
        libssh2_keepalive_send(m_session, &next_keepalive);

        // ── Drain per-channel write queues ────────────────────────────────────
        DrainWriteQueues();

        // ── Accept new channels ───────────────────────────────────────────────
        LIBSSH2_CHANNEL* ch = libssh2_channel_forward_accept(m_listener);
        if (ch) {
            Logger::Debug("Accepted forwarded-tcpip channel");
            auto ssh_ch = std::make_unique<SshChannel>(ch);
            on_channel(std::move(ssh_ch));
            continue;
        }

        int rc = libssh2_session_last_errno(m_session);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            // No channel yet — select on socket
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(m_socket, &fds);
            struct timeval tv{ 0, 100000 };  // 100 ms
            select(0, &fds, nullptr, nullptr, &tv);
            continue;
        }

        // Unexpected session error
        char* errmsg = nullptr;
        libssh2_session_last_error(m_session, &errmsg, nullptr, 0);
        Logger::Error("SSH session error: %s", errmsg ? errmsg : "unknown");
        disconnect_reason = ErrorCode::ProtocolError;
        break;
    }

    m_connected.store(false);
    Logger::Debug("SSH I/O thread exiting");

    if (on_disconnect)
        on_disconnect(disconnect_reason);
}

void SshTransport::DrainWriteQueues() {
    std::lock_guard<std::mutex> lock(m_queues_mutex);
    for (auto& q : m_write_queues) {
        while (!q.pending.empty()) {
            auto& buf = q.pending.front();
            ssize_t n = libssh2_channel_write(q.channel,
                reinterpret_cast<const char*>(buf.data()), buf.size());
            if (n == LIBSSH2_ERROR_EAGAIN) break;
            if (n <= 0) {
                q.pending.clear();
                break;
            }
            if (static_cast<size_t>(n) < buf.size()) {
                buf.erase(buf.begin(), buf.begin() + n);
                break;
            }
            q.pending.pop_front();
        }
    }
}

void SshTransport::PostChannelWrite(LIBSSH2_CHANNEL* ch, std::vector<uint8_t> data) {
    std::lock_guard<std::mutex> lock(m_queues_mutex);
    for (auto& q : m_write_queues) {
        if (q.channel == ch) {
            q.pending.push_back(std::move(data));
            return;
        }
    }
    // New channel — add a queue entry
    ChannelQueue q;
    q.channel = ch;
    q.pending.push_back(std::move(data));
    m_write_queues.push_back(std::move(q));
}

void SshTransport::Close() {
    m_cancel.store(true);
    if (m_io_thread.joinable())
        m_io_thread.join();

    if (m_listener) {
        libssh2_channel_forward_cancel(m_listener);
        m_listener = nullptr;
    }
    if (m_session) {
        libssh2_session_set_blocking(m_session, 1);
        libssh2_session_disconnect(m_session, "Normal shutdown");
        libssh2_session_free(m_session);
        m_session = nullptr;
    }
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    m_connected.store(false);
    Logger::Debug("SshTransport closed");
}

bool SshTransport::IsConnected() const {
    return m_connected.load();
}
