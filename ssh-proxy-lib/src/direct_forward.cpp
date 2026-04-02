//////////////////////////////////////////////////////////////////////////////
//
// DirectForward — purpose and socket naming
//
// PURPOSE
//   Implements SSH local-port-forwarding in-process (no OpenSSH client needed).
//   Any code on this machine can reach a TCP endpoint that is only accessible
//   from the SSH server by connecting to 127.0.0.1:local_port() instead.
//
//   Example: SSH server can reach db.internal:5432 but this machine cannot.
//   After constructing DirectForward("ssh.host", ..., 5432, "db.internal"),
//   connecting to 127.0.0.1:local_port() is equivalent to connecting to
//   db.internal:5432 from the SSH server.
//
// SSH CHANNEL TYPE: direct-tcpip  (RFC 4254 §7.2, equivalent to `ssh -L`)
//   libssh2_channel_direct_tcpip() asks the SSH server to open an outbound TCP
//   connection to (target_host, target_port) on the caller's behalf.  Bytes
//   written to the channel arrive at the target; reads return what the target
//   sends back.
//
// THE THREE SOCKETS
//   m_ssh_socket  — raw TCP socket to the SSH server.  libssh2 owns its data;
//                   we keep it only so the destructor can close it to unblock
//                   the relay thread.
//
//   m_listen_sock — server socket bound to 127.0.0.1:0 (ephemeral port reported
//                   by local_port()).  Accepts exactly one caller, then closes.
//
//   m_relay_sock  — the accepted local caller's socket.  The relay thread
//                   shuttles bytes between this and the SSH channel.
//
//////////////////////////////////////////////////////////////////////////////

#include "ssh_tunnel.h"
#include "common.h"
#include <stdexcept>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>

namespace ssh_tunnel {

    struct DirectForward::Impl {
        ::SOCKET            m_ssh_socket  = INVALID_SOCKET;
        ::LIBSSH2_SESSION*  m_session     = nullptr;
        ::LIBSSH2_CHANNEL*  m_channel     = nullptr;

        std::mutex          m_socket_mutex;
        ::SOCKET            m_listen_sock = INVALID_SOCKET;
        ::SOCKET            m_relay_sock  = INVALID_SOCKET;

        ::uint16_t          m_local_port  = 0;
        std::thread         m_relay_thread;
        std::atomic<bool>   m_cancel{ false };
        std::atomic<bool>   m_alive{ true };
    };

    namespace {

        //
        // ── connect_tcp ───────────────────────────────────────────────────────────────
        //
        // DNS-resolve host:port and establish a blocking TCP connection with a
        // send/receive timeout. Returns the connected WinSocket; throws
        // std::runtime_error on any failure.

        WinSocket connect_tcp(const std::string& host, uint16_t port, uint32_t timeout_ms)
        {
            struct addrinfo hints{};
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            char port_str[8];
            ::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));

            addrinfo* raw_addr = nullptr;
            if (::getaddrinfo(host.c_str(), port_str, &hints, &raw_addr) != 0)
                throw std::runtime_error("DNS resolve failed for " + host);
            if (raw_addr == nullptr)
                throw std::runtime_error("getaddrinfo returned null for " + host);

            AddrInfoPtr addr(raw_addr);

            WinSocket sock(::socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP));
            if (sock.get() == INVALID_SOCKET)
                throw std::runtime_error("socket() failed for " + host);

            DWORD tv_ms = timeout_ms;
            ::setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
            ::setsockopt(sock.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

            if (::connect(sock.get(), addr->ai_addr, static_cast<int>(addr->ai_addrlen)) != 0)
                throw std::runtime_error("TCP connect to " + host + " failed: " + std::to_string(::WSAGetLastError()));

            return sock;
        }

        //
        // ── throw_ssh_error ───────────────────────────────────────────────────────────
        //

        [[noreturn]] void throw_ssh_error(LIBSSH2_SESSION* s, std::string msg)
        {
            char* errmsg = nullptr;
            ::libssh2_session_last_error(s, &errmsg, nullptr, 0);
            if (errmsg != nullptr)
            { 
                msg += ": "; 
                msg += errmsg; 
            }
            throw std::runtime_error(std::move(msg));
        }

        //
        // ── open_ssh_session ──────────────────────────────────────────────────────────
        //
        // Steps 3+4: init a libssh2 session over sock, complete the handshake, authenticate.
        // Returns a session in blocking mode; caller switches to non-blocking when ready.

        SshSessionPtr open_ssh_session(SOCKET sock, const std::string& username, const std::string& password)
        {
            SshSessionPtr session(::libssh2_session_init());
            if (session == nullptr)
            {
                throw std::runtime_error("DirectForward: libssh2_session_init failed");
            }

            ::libssh2_session_set_blocking(session.get(), 1);

            if (::libssh2_session_handshake(session.get(), sock) != 0)
            {
                throw_ssh_error(session.get(), "DirectForward: SSH handshake failed");
            }

            // Handshake complete — deleter may now send SSH_MSG_DISCONNECT on cleanup.
            session.get_deleter().send_disconnect = true;

            if (::libssh2_userauth_password(session.get(), username.c_str(), password.c_str()) != 0)
            {
                throw_ssh_error(session.get(), "DirectForward: SSH auth failed for user " + username);
            }

            return session;
        }

        //
        // ── open_direct_tcpip ─────────────────────────────────────────────────────────
        //
        // Step 5: ask the SSH server to connect outward to target_host:target_port and
        // attach that TCP stream to a new SSH channel.

        SshChannelPtr open_direct_tcpip(LIBSSH2_SESSION* session, const std::string& target_host, uint16_t target_port)
        {
            SshChannelPtr channel(::libssh2_channel_direct_tcpip(session, target_host.c_str(), static_cast<int>(target_port)));

            if (channel == nullptr)
            {
                throw_ssh_error(session, "DirectForward: channel_direct_tcpip to " + target_host + ":" + std::to_string(target_port) + " failed");
            }

            return channel;
        }

        //
        // ── create_local_listener ─────────────────────────────────────────────────────
        //
        // Step 6: bind a server socket to 127.0.0.1:0; returns the socket and the
        // OS-assigned port.  relay_proc accepts the one inbound connection on this socket.

        std::pair<WinSocket, uint16_t> create_local_listener()
        {
            WinSocket listen_sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
            if (listen_sock.get() == INVALID_SOCKET)
            {
                throw std::runtime_error("DirectForward: local socket() failed");
            }

            sockaddr_in bind_addr{};
            bind_addr.sin_family      = AF_INET;
            bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            bind_addr.sin_port        = 0;  // OS assigns

            if (::bind(listen_sock.get(), reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0)
            {
                throw std::runtime_error("DirectForward: local bind failed");
            }

            if (::listen(listen_sock.get(), 1) != 0)
            {
                throw std::runtime_error("DirectForward: local listen failed");
            }

            sockaddr_in bound{};
            int bound_len = sizeof(bound);
            ::getsockname(listen_sock.get(), reinterpret_cast<sockaddr*>(&bound), &bound_len);
            uint16_t port = ::ntohs(bound.sin_port);

            return { std::move(listen_sock), port };
        }

    } // namespace

    //
    // ── accept_connection ─────────────────────────────────────────────────────────
    //
    // Blocks on m_listen_sock until one local caller connects, then closes
    // m_listen_sock (single-accept — a second caller would block forever).
    // On success stores the accepted socket in impl->m_relay_sock and returns true.
    // Returns false if accept() fails (listen_sock was closed by cancel/dtor)
    // or if m_cancel was set before a caller arrived.

    bool DirectForward::accept_connection(Impl* impl)
    {
        WinSocket accepted(::accept(impl->m_listen_sock, nullptr, nullptr));
        {
            std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
            if (impl->m_listen_sock != INVALID_SOCKET)
            {
                ::closesocket(impl->m_listen_sock);
                impl->m_listen_sock = INVALID_SOCKET;
            }
        }

        if (accepted.get() == INVALID_SOCKET)
            return false;
        if (impl->m_cancel.load())
            return false;

        std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
        impl->m_relay_sock = accepted.release();
        return true;
    }

    //
    // ── run_relay_loop ────────────────────────────────────────────────────────────
    //
    // Shuttles bytes between impl->m_relay_sock and the SSH channel until either
    // side closes, libssh2_channel_eof() fires, or m_cancel is set.
    // Closes impl->m_relay_sock before returning.

    void DirectForward::run_relay_loop(Impl* impl)
    {
        ::SOCKET relay_sock = impl->m_relay_sock;
        static constexpr int BUF_SIZE = 16384;
        std::vector<char> buf(BUF_SIZE);

        bool running = true;
        while (running && !impl->m_cancel.load())
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(impl->m_ssh_socket, &rfds);
            FD_SET(relay_sock, &rfds);
            struct timeval tv{ 0, 50000 };  // 50 ms

            if (::select(0, &rfds, nullptr, nullptr, &tv) < 0)
            {
                break;
            }

            // SSH channel → relay_sock
            if (FD_ISSET(impl->m_ssh_socket, &rfds))
            {
                while (running)
                {
                    ssize_t n = ::libssh2_channel_read(impl->m_channel, buf.data(), BUF_SIZE);
                    if (n > 0)
                    {
                        if (::send(relay_sock, buf.data(), static_cast<int>(n), 0) <= 0)
                        {
                            running = false;
                        }
                    }
                    else if (n == LIBSSH2_ERROR_EAGAIN)
                    {
                        break;
                    }
                    else
                    {
                        running = false;
                    }
                }
            }

            // relay_sock → SSH channel
            if (running && FD_ISSET(relay_sock, &rfds))
            {
                int n = ::recv(relay_sock, buf.data(), BUF_SIZE, 0);
                if (n <= 0)
                {
                    running = false;
                }
                else
                {
                    int written = 0;
                    while (running && written < n)
                    {
                        ssize_t w = ::libssh2_channel_write(impl->m_channel, buf.data() + written, static_cast<size_t>(n - written));
                        if (w == LIBSSH2_ERROR_EAGAIN)
                        {
                            ::Sleep(1);
                            continue;
                        }
                        if (w <= 0)
                        {
                            running = false;
                            break;
                        }
                        written += static_cast<int>(w);
                    }
                }
            }

            if (running && ::libssh2_channel_eof(impl->m_channel))
            {
                running = false;
            }
        }

        {
            std::lock_guard<std::mutex> lock(impl->m_socket_mutex);
            if (impl->m_relay_sock != INVALID_SOCKET)
            {
                ::closesocket(impl->m_relay_sock);
                impl->m_relay_sock = INVALID_SOCKET;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    //
    // run_relay
    //
    // Thread entry point. Owns all libssh2 calls after the constructor returns
    // (libssh2 is not thread-safe; the constructor is the sole caller during
    // setup, this thread is the sole caller from here on).
    //
    // The select() loop uses a 50 ms timeout: short enough to detect m_cancel
    // promptly, long enough to avoid busy-waiting when both sides are idle.
    //
    // Blocking mode is re-enabled before channel teardown because send_eof /
    // wait_eof / channel_close are blocking libssh2 operations that must complete
    // before session teardown proceeds.
    //
    //////////////////////////////////////////////////////////////////////////////

    void DirectForward::run_relay(Impl* impl)
    {
        if (accept_connection(impl))
            run_relay_loop(impl);

        // Channel cleanup — this thread is the sole libssh2 user now
        if (impl->m_channel != nullptr)
        {
            ::libssh2_session_set_blocking(impl->m_session, 1);
            ::libssh2_channel_send_eof(impl->m_channel);
            ::libssh2_channel_wait_eof(impl->m_channel);
            ::libssh2_channel_close(impl->m_channel);
            ::libssh2_channel_free(impl->m_channel);
            impl->m_channel = nullptr;
        }

        impl->m_alive.store(false);
    }

    //////////////////////////////////////////////////////////////////////////////
    //
    // Constructor
    //
    // Sequences the setup helpers; all steps are blocking and throw on failure.
    // A successfully constructed DirectForward is ready to relay immediately.
    //
    //   Step 1  libssh2_init()          one-time process-wide crypto init (idempotent)
    //   Step 2  connect_tcp             DNS resolve + connect with timeout
    //   Steps 3+4  open_ssh_session     handshake + password auth
    //   Step 5  open_direct_tcpip       ask server to connect to target
    //   Step 6  create_local_listener   bind 127.0.0.1:0, record ephemeral port
    //   Step 7  commit + launch         non-blocking mode, hand off to run_relay
    //
    //////////////////////////////////////////////////////////////////////////////

    DirectForward::DirectForward(
        std::string  ssh_host,
        std::string  username,
        std::string  password,
        uint16_t     target_port,
        std::string  target_host,
        uint16_t     ssh_port,
        uint32_t     connect_timeout_ms)
    {
        if (::libssh2_init(0) != 0)
        {
            throw std::runtime_error("DirectForward: libssh2_init failed");     // Step 1
        }

        auto impl = std::make_unique<Impl>();

        WinSocket     ssh_sock = connect_tcp(ssh_host, ssh_port, connect_timeout_ms);        // Step 2
        SshSessionPtr session  = open_ssh_session(ssh_sock.get(), username, password);       // Steps 3+4
        SshChannelPtr channel  = open_direct_tcpip(session.get(), target_host, target_port); // Step 5

        auto [listen_sock, local_port] = create_local_listener();                            // Step 6
        impl->m_local_port = local_port;

        // Step 7: switch to non-blocking, commit all resources, launch relay thread
        ::libssh2_session_set_blocking(session.get(), 0);
        impl->m_ssh_socket  = ssh_sock.release();
        impl->m_session     = session.release();
        impl->m_channel     = channel.release();
        impl->m_listen_sock = listen_sock.release();
        m_impl = impl.release();
        m_impl->m_relay_thread = std::thread(&DirectForward::run_relay, m_impl);
    }

    //////////////////////////////////////////////////////////////////////////////
    //
    // Destructor
    //
    // Threading: the constructor is the sole libssh2 caller during setup; run_relay
    // is the sole libssh2 caller after that.  The destructor never calls libssh2
    // directly — it signals shutdown then joins run_relay, so there is no concurrent
    // access at any point.
    //
    // Shutdown sequence:
    //   1. Signal shutdown — sets m_cancel, closes m_listen_sock (unblocks accept())
    //      and m_relay_sock (unblocks recv()/select()), both under m_socket_mutex.
    //   2. Join run_relay — by the time join() returns, the channel has been freed
    //      and libssh2 is no longer in use.
    //   3. Free any remaining session/socket resources (covers the case where
    //      run_relay was never reached, e.g. accept() failed immediately).
    //
    //////////////////////////////////////////////////////////////////////////////

    DirectForward::~DirectForward()
    {
        if (m_impl == nullptr) return;

        m_impl->m_cancel.store(true);
        {
            std::lock_guard<std::mutex> lock(m_impl->m_socket_mutex);
            if (m_impl->m_listen_sock != INVALID_SOCKET)
            {
                ::closesocket(m_impl->m_listen_sock);
                m_impl->m_listen_sock = INVALID_SOCKET;
            }
            if (m_impl->m_relay_sock != INVALID_SOCKET)
            {
                ::closesocket(m_impl->m_relay_sock);
                m_impl->m_relay_sock = INVALID_SOCKET;
            }
        }

        if (m_impl->m_relay_thread.joinable())
            m_impl->m_relay_thread.join();

        // Session cleanup (run_relay already freed the channel, or it was never started)
        if (m_impl->m_channel != nullptr)
        {
            ::libssh2_session_set_blocking(m_impl->m_session, 1);
            ::libssh2_channel_close(m_impl->m_channel);
            ::libssh2_channel_free(m_impl->m_channel);
            m_impl->m_channel = nullptr;
        }
        if (m_impl->m_session != nullptr)
        {
            ::libssh2_session_set_blocking(m_impl->m_session, 1);
            libssh2_session_disconnect(m_impl->m_session, "Shutdown");
            ::libssh2_session_free(m_impl->m_session);
            m_impl->m_session = nullptr;
        }
        if (m_impl->m_ssh_socket != INVALID_SOCKET) 
        {
            ::closesocket(m_impl->m_ssh_socket);
            m_impl->m_ssh_socket = INVALID_SOCKET;
        }

        delete m_impl;
        m_impl = nullptr;
    }

    //
    // ── Public accessors ──────────────────────────────────────────────────────────
    //

    //
    // ── local_port ────────────────────────────────────────────────────────────────
    //

    uint16_t DirectForward::local_port() const
    {
        return m_impl ? m_impl->m_local_port : 0;
    }

    //
    // ── is_alive ──────────────────────────────────────────────────────────────────
    //

    bool DirectForward::is_alive() const
    {
        return m_impl && m_impl->m_alive.load();
    }

} // namespace ssh_tunnel