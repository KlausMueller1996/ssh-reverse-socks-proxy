#include "ssh_tunnel.h"
#include "common.h"
#include "logger.h"
#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>

namespace ssh_tunnel {

// ── Impl ──────────────────────────────────────────────────────────────────────

struct DirectForward::Impl {
    SOCKET            m_ssh_socket  = INVALID_SOCKET;
    LIBSSH2_SESSION*  m_session     = nullptr;
    LIBSSH2_CHANNEL*  m_channel     = nullptr;

    std::mutex        m_socket_mutex;
    SOCKET            m_listen_sock = INVALID_SOCKET;
    SOCKET            m_relay_sock  = INVALID_SOCKET;

    uint16_t          m_local_port  = 0;
    std::thread       m_relay_thread;
    std::atomic<bool> m_cancel{ false };
    std::atomic<bool> m_alive{ true };
};

// ── Relay thread proc ─────────────────────────────────────────────────────────

static void relay_proc(DirectForward::Impl* impl)
{
    static constexpr int BUF_SIZE = 16384;
    std::vector<char> buf(BUF_SIZE);

    // Step 1: accept one local connection
    SOCKET relay_sock = ::accept(impl->m_listen_sock, nullptr, nullptr);
    {
        std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
        if (impl->m_listen_sock != INVALID_SOCKET) {
            closesocket(impl->m_listen_sock);
            impl->m_listen_sock = INVALID_SOCKET;
        }
    }

    if (relay_sock == INVALID_SOCKET || impl->m_cancel.load()) {
        if (relay_sock != INVALID_SOCKET)
            closesocket(relay_sock);
        goto cleanup;
    }

    {
        std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
        impl->m_relay_sock = relay_sock;
    }

    // Step 2: relay loop
    {
        bool running = true;
        while (running && !impl->m_cancel.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(impl->m_ssh_socket, &rfds);
            FD_SET(relay_sock, &rfds);
            struct timeval tv{ 0, 50000 };  // 50 ms

            if (::select(0, &rfds, nullptr, nullptr, &tv) < 0)
                break;

            // SSH channel → relay_sock
            if (FD_ISSET(impl->m_ssh_socket, &rfds)) {
                while (running) {
                    ssize_t n = libssh2_channel_read(impl->m_channel, buf.data(), BUF_SIZE);
                    if (n > 0) {
                        if (::send(relay_sock, buf.data(), static_cast<int>(n), 0) <= 0) {
                            running = false;
                        }
                    } else if (n == LIBSSH2_ERROR_EAGAIN) {
                        break;
                    } else {
                        running = false;
                    }
                }
            }

            // relay_sock → SSH channel
            if (running && FD_ISSET(relay_sock, &rfds)) {
                int n = ::recv(relay_sock, buf.data(), BUF_SIZE, 0);
                if (n <= 0) {
                    running = false;
                } else {
                    int written = 0;
                    while (running && written < n) {
                        ssize_t w = libssh2_channel_write(
                            impl->m_channel,
                            buf.data() + written,
                            static_cast<size_t>(n - written));
                        if (w == LIBSSH2_ERROR_EAGAIN) { ::Sleep(1); continue; }
                        if (w <= 0) { running = false; break; }
                        written += static_cast<int>(w);
                    }
                }
            }

            if (running && libssh2_channel_eof(impl->m_channel))
                running = false;
        }
    }

    // Close relay socket
    {
        std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
        if (impl->m_relay_sock != INVALID_SOCKET) {
            closesocket(impl->m_relay_sock);
            impl->m_relay_sock = INVALID_SOCKET;
        }
    }

cleanup:
    // Channel cleanup — this thread is the sole libssh2 user now
    if (impl->m_channel) {
        libssh2_session_set_blocking(impl->m_session, 1);
        libssh2_channel_send_eof(impl->m_channel);
        libssh2_channel_wait_eof(impl->m_channel);
        libssh2_channel_close(impl->m_channel);
        libssh2_channel_free(impl->m_channel);
        impl->m_channel = nullptr;
    }

    impl->m_alive.store(false);
    Logger::Debug("DirectForward relay thread exited");
}

// ── Constructor ───────────────────────────────────────────────────────────────

DirectForward::DirectForward(
    std::string  ssh_host,
    std::string  username,
    std::string  password,
    uint16_t     target_port,
    std::string  target_host,
    uint16_t     ssh_port,
    uint32_t     connect_timeout_ms)
{
    m_impl = new Impl();

    // ── libssh2 init (idempotent) ─────────────────────────────────────────────
    if (libssh2_init(0) != 0) {
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: libssh2_init failed");
    }

    // ── TCP connect to SSH server ─────────────────────────────────────────────
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(ssh_port));

    if (getaddrinfo(ssh_host.c_str(), port_str, &hints, &result) != 0 || !result) {
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: DNS resolve failed for " + ssh_host);
    }

    m_impl->m_ssh_socket = ::socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (m_impl->m_ssh_socket == INVALID_SOCKET) {
        freeaddrinfo(result);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: socket() failed");
    }

    DWORD tv_ms = connect_timeout_ms;
    setsockopt(m_impl->m_ssh_socket, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    setsockopt(m_impl->m_ssh_socket, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

    if (::connect(m_impl->m_ssh_socket, result->ai_addr,
                  static_cast<int>(result->ai_addrlen)) != 0)
    {
        int err = WSAGetLastError();
        freeaddrinfo(result);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error(
            "DirectForward: TCP connect to " + ssh_host + " failed: " + std::to_string(err));
    }
    freeaddrinfo(result);
    Logger::Info("DirectForward: TCP connected to %s:%u", ssh_host.c_str(), ssh_port);

    // ── SSH handshake ─────────────────────────────────────────────────────────
    m_impl->m_session = libssh2_session_init();
    if (!m_impl->m_session) {
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: libssh2_session_init failed");
    }

    libssh2_session_set_blocking(m_impl->m_session, 1);

    if (libssh2_session_handshake(m_impl->m_session, m_impl->m_ssh_socket) != 0) {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_impl->m_session, &errmsg, nullptr, 0);
        Logger::Error("DirectForward: SSH handshake failed: %s", errmsg ? errmsg : "unknown");
        libssh2_session_free(m_impl->m_session);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: SSH handshake failed");
    }

    // ── Password authentication ───────────────────────────────────────────────
    if (libssh2_userauth_password(m_impl->m_session,
                                   username.c_str(), password.c_str()) != 0)
    {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_impl->m_session, &errmsg, nullptr, 0);
        Logger::Error("DirectForward: SSH auth failed for '%s': %s",
                      username.c_str(), errmsg ? errmsg : "unknown");
        libssh2_session_disconnect(m_impl->m_session, "Auth failed");
        libssh2_session_free(m_impl->m_session);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: SSH auth failed for user " + username);
    }
    Logger::Info("DirectForward: authenticated as '%s'", username.c_str());

    // ── Open direct_tcpip channel ─────────────────────────────────────────────
    m_impl->m_channel = libssh2_channel_direct_tcpip(
        m_impl->m_session, target_host.c_str(), static_cast<int>(target_port));
    if (!m_impl->m_channel) {
        char* errmsg = nullptr;
        libssh2_session_last_error(m_impl->m_session, &errmsg, nullptr, 0);
        Logger::Error("DirectForward: channel_direct_tcpip(%s:%u) failed: %s",
                      target_host.c_str(), target_port, errmsg ? errmsg : "unknown");
        libssh2_session_disconnect(m_impl->m_session, "Channel open failed");
        libssh2_session_free(m_impl->m_session);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error(
            "DirectForward: channel_direct_tcpip to " + target_host + ":" +
            std::to_string(target_port) + " failed: " + (errmsg ? errmsg : "unknown"));
    }
    Logger::Info("DirectForward: channel open to %s:%u", target_host.c_str(), target_port);

    // ── Local TCP listener on 127.0.0.1:0 (ephemeral port) ───────────────────
    SOCKET listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        libssh2_channel_close(m_impl->m_channel);
        libssh2_channel_free(m_impl->m_channel);
        libssh2_session_disconnect(m_impl->m_session, "Local bind failed");
        libssh2_session_free(m_impl->m_session);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: local socket() failed");
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;  // OS assigns

    if (::bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(listen_sock, 1) != 0)
    {
        closesocket(listen_sock);
        libssh2_channel_close(m_impl->m_channel);
        libssh2_channel_free(m_impl->m_channel);
        libssh2_session_disconnect(m_impl->m_session, "Local bind failed");
        libssh2_session_free(m_impl->m_session);
        closesocket(m_impl->m_ssh_socket);
        delete m_impl; m_impl = nullptr;
        throw std::runtime_error("DirectForward: local bind/listen failed");
    }

    sockaddr_in bound{};
    int bound_len = sizeof(bound);
    getsockname(listen_sock, reinterpret_cast<sockaddr*>(&bound), &bound_len);
    m_impl->m_local_port  = ntohs(bound.sin_port);
    m_impl->m_listen_sock = listen_sock;

    Logger::Info("DirectForward: local listener on 127.0.0.1:%u", m_impl->m_local_port);

    // Switch session to non-blocking before starting relay thread
    libssh2_session_set_blocking(m_impl->m_session, 0);

    // ── Start relay thread ────────────────────────────────────────────────────
    m_impl->m_relay_thread = std::thread(relay_proc, m_impl);
}

// ── Destructor ────────────────────────────────────────────────────────────────

DirectForward::~DirectForward()
{
    if (!m_impl) return;

    m_impl->m_cancel.store(true);

    // Close sockets to unblock accept()/select()/recv() in relay thread
    {
        std::lock_guard<std::mutex> lock(m_impl->m_socket_mutex);
        if (m_impl->m_listen_sock != INVALID_SOCKET) {
            closesocket(m_impl->m_listen_sock);
            m_impl->m_listen_sock = INVALID_SOCKET;
        }
        if (m_impl->m_relay_sock != INVALID_SOCKET) {
            closesocket(m_impl->m_relay_sock);
            m_impl->m_relay_sock = INVALID_SOCKET;
        }
    }

    if (m_impl->m_relay_thread.joinable())
        m_impl->m_relay_thread.join();

    // Session cleanup (relay thread already freed the channel, or it was never started)
    if (m_impl->m_channel) {
        libssh2_session_set_blocking(m_impl->m_session, 1);
        libssh2_channel_close(m_impl->m_channel);
        libssh2_channel_free(m_impl->m_channel);
        m_impl->m_channel = nullptr;
    }
    if (m_impl->m_session) {
        libssh2_session_set_blocking(m_impl->m_session, 1);
        libssh2_session_disconnect(m_impl->m_session, "Shutdown");
        libssh2_session_free(m_impl->m_session);
        m_impl->m_session = nullptr;
    }
    if (m_impl->m_ssh_socket != INVALID_SOCKET) {
        closesocket(m_impl->m_ssh_socket);
        m_impl->m_ssh_socket = INVALID_SOCKET;
    }

    delete m_impl;
    m_impl = nullptr;
}

// ── Public accessors ──────────────────────────────────────────────────────────

uint16_t DirectForward::local_port() const
{
    return m_impl ? m_impl->m_local_port : 0;
}

bool DirectForward::is_alive() const
{
    return m_impl && m_impl->m_alive.load();
}

void DirectForward::cancel()
{
    if (!m_impl) return;
    m_impl->m_cancel.store(true);
    std::lock_guard<std::mutex> lock(m_impl->m_socket_mutex);
    if (m_impl->m_listen_sock != INVALID_SOCKET) {
        closesocket(m_impl->m_listen_sock);
        m_impl->m_listen_sock = INVALID_SOCKET;
    }
    if (m_impl->m_relay_sock != INVALID_SOCKET) {
        closesocket(m_impl->m_relay_sock);
        m_impl->m_relay_sock = INVALID_SOCKET;
    }
}

} // namespace ssh_tunnel
