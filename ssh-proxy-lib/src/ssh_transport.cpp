//////////////////////////////////////////////////////////////////////////////
//
// SshTransport — SSH I/O thread, libssh2 session owner, channel multiplexer
//
// PURPOSE
//   Manages the full SSH connection lifecycle: blocking setup on the caller's
//   thread (TCP connect + handshake + auth + tcpip-forward listen), then a
//   dedicated I/O thread that accepts forwarded channels, drains write queues,
//   runs keepalives, and pumps active SOCKS5 sessions.
//
// THREADING MODEL
//   Connect() runs synchronously on the caller.  After StartAccepting()
//   launches IoThreadProc, ALL libssh2 calls are confined to that thread.
//   s_is_io_thread (thread_local) lets SshChannel methods detect their
//   calling context at runtime to choose direct call vs. queue dispatch.
//
// CROSS-THREAD QUEUES
//   m_write_queues  — IOCP threads post channel data via PostChannelWrite().
//                     DrainWriteQueues() flushes them on each I/O loop tick.
//   m_io_callbacks  — IOCP threads post arbitrary lambdas via PostToIoThread()
//                     (e.g. SendEof, channel_close/free).  DrainIoCallbacks()
//                     swaps the vector under lock, then invokes outside lock so
//                     callbacks cannot deadlock on m_io_callbacks_mutex.
//
// CHANNEL WRITE QUEUE LIFECYCLE
//   A ChannelQueue entry is registered eagerly at accept time, before
//   on_channel() is called, so PostChannelWrite never races the first Write().
//   RemoveChannelWriteQueue() (via the pre_close hook) removes the entry
//   before channel_free fires.  PostChannelWrite discards silently if the
//   entry is already gone — the channel pointer may be freed.
//
//////////////////////////////////////////////////////////////////////////////

#include "ssh_transport.h"
#include "logger.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

// Thread-local flag: true only on the SSH I/O thread.
// SshChannel uses this to decide whether to call libssh2 directly (I/O thread)
// or to marshal the call through a queue (any other thread).
static thread_local bool s_is_io_thread = false;

// ── SshChannel ────────────────────────────────────────────────────────────────

SshChannel::SshChannel(LIBSSH2_CHANNEL* ch, ThreadingHooks hooks)
    : m_channel(ch)
    , m_hooks(std::move(hooks))
{}

//
// ── SshChannel::Read ──────────────────────────────────────────────────────────
//
// Called on the SSH I/O thread only (libssh2 is not thread-safe).
// Translates libssh2 return codes to ErrorCode: WouldBlock on EAGAIN,
// ChannelClosed on EOF or zero bytes, ProtocolError on any other negative.
//

ErrorCode SshChannel::Read(uint8_t* buf, size_t len, size_t& bytes_read)
{
    bytes_read = 0;
    LIBSSH2_CHANNEL* ch = m_channel.load();
    if (ch == nullptr) return ErrorCode::ChannelClosed;

    ssize_t n = ::libssh2_channel_read(ch, reinterpret_cast<char*>(buf), len);
    if (n > 0)
    {
        bytes_read = static_cast<size_t>(n);
        return ErrorCode::Success;
    }
    if (n == 0 || ::libssh2_channel_eof(ch))
    {
        return ErrorCode::ChannelClosed;
    }
    if (n == LIBSSH2_ERROR_EAGAIN)
    {
        return ErrorCode::WouldBlock;
    }
    Logger::Error("libssh2_channel_read failed: %d", static_cast<int>(n));
    return ErrorCode::ProtocolError;
}

ErrorCode SshChannel::Write(const uint8_t* buf, size_t len)
{
    LIBSSH2_CHANNEL* ch = m_channel.load();
    if (ch == nullptr) return ErrorCode::ChannelClosed;

    // If we're NOT on the SSH I/O thread, post via the write queue so libssh2
    // is only touched by the I/O thread.
    if (m_hooks.post_write && !s_is_io_thread)
    {
        m_hooks.post_write(std::vector<uint8_t>(buf, buf + len));
        return ErrorCode::Success;
    }

    // On the I/O thread: call libssh2 directly (blocking with EAGAIN retry).
    size_t written = 0;
    while (written < len)
    {
        ssize_t n = ::libssh2_channel_write(ch,
                                            reinterpret_cast<const char*>(buf + written),
                                            len - written);
        if (n > 0)
        {
            written += static_cast<size_t>(n);
            continue;
        }
        if (n == LIBSSH2_ERROR_EAGAIN)
        {
            ::Sleep(1);
            continue;
        }
        Logger::Error("libssh2_channel_write failed: %d", static_cast<int>(n));
        return ErrorCode::ProtocolError;
    }
    return ErrorCode::Success;
}

//
// ── SshChannel::SendEof ───────────────────────────────────────────────────────
//
// Sends SSH_MSG_CHANNEL_EOF to signal the end of our outbound data stream.
// If called from outside the I/O thread the call is posted via post_io so
// libssh2 is only touched by the I/O thread.
//

void SshChannel::SendEof()
{
    LIBSSH2_CHANNEL* ch = m_channel.load();
    if (ch == nullptr) return;

    if (m_hooks.post_io && !s_is_io_thread)
    {
        m_hooks.post_io([ch]() { ::libssh2_channel_send_eof(ch); });
    }
    else
    {
        ::libssh2_channel_send_eof(ch);
    }
}

void SshChannel::Close()
{
    LIBSSH2_CHANNEL* ch = m_channel.exchange(nullptr);
    if (ch == nullptr) return;

    // Remove from the transport's write queue before freeing.
    // This must happen while ch is still a valid pointer so that
    // DrainWriteQueues cannot call libssh2_channel_write on a freed channel.
    if (m_hooks.pre_close) m_hooks.pre_close(ch);

    // Always post channel_close/free to io_callbacks — never call directly,
    // even on the IO thread. This guarantees that any io_callbacks already
    // queued for this channel (e.g. a SendEof posted by an IOCP thread just
    // before Close() ran) are drained in FIFO order before channel_free fires.
    if (m_hooks.post_io)
    {
        m_hooks.post_io([ch]()
        {
            ::libssh2_channel_close(ch);
            ::libssh2_channel_free(ch);
        });
    }
    else
    {
        ::libssh2_channel_close(ch);
        ::libssh2_channel_free(ch);
    }
}

bool SshChannel::IsEof() const
{
    LIBSSH2_CHANNEL* ch = m_channel.load();
    return ch != nullptr ? ::libssh2_channel_eof(ch) != 0 : true;
}

// Appends the libssh2 last-error string to context and returns a failed Result.
// The message travels in the Result so the caller can propagate or display it
// without relying on a separate log call.
namespace
{
    Result ssh_error(LIBSSH2_SESSION* s, std::string context, ErrorCode code)
    {
        char* errmsg = nullptr;
        ::libssh2_session_last_error(s, &errmsg, nullptr, 0);
        if (errmsg != nullptr) { context += ": "; context += errmsg; }
        return { code, std::move(context) };
    }
} // namespace

// ── SshTransport ──────────────────────────────────────────────────────────────

SshTransport::SshTransport() = default;

SshTransport::~SshTransport()
{
    Close();
}

Result SshTransport::Connect(const std::string& host, uint16_t port,
                              const std::string& username,
                              const std::string& password,
                              uint16_t forward_port,
                              uint32_t timeout_ms,
                              uint32_t keepalive_interval_ms)
{
    // All resources are held in local RAII guards.  Any early return below
    // automatically destroys them in reverse declaration order — no explicit
    // per-branch cleanup required.  On success, .release() transfers ownership
    // to the SshTransport members, where Close() manages their lifetime.

    // ── TCP connect ───────────────────────────────────────────────────────────
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    ::snprintf(port_str, sizeof(port_str), "%u", port);

    addrinfo* raw_addr = nullptr;
    if (::getaddrinfo(host.c_str(), port_str, &hints, &raw_addr) != 0 || raw_addr == nullptr)
        return { ErrorCode::DnsResolutionFailed, "DNS resolve failed for " + host };
    AddrInfoPtr addr(raw_addr);

    WinSocket sock(::socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP));
    if (!sock)
        return { ErrorCode::SocketError,
                 "socket() failed: " + std::to_string(::WSAGetLastError()) };

    // Apply connect timeout via SO_RCVTIMEO/SO_SNDTIMEO on a blocking socket
    DWORD tv_ms = timeout_ms;
    ::setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    ::setsockopt(sock.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));

    if (::connect(sock.get(), addr->ai_addr, static_cast<int>(addr->ai_addrlen)) != 0)
    {
        int err = ::WSAGetLastError();
        return { WsaToErrorCode(err),
                 "TCP connect to " + host + ":" + std::to_string(port) +
                 " failed (WSA " + std::to_string(err) + ")" };
    }
    addr.reset();
    Logger::Info("TCP connected to %s:%u", host.c_str(), port);

    // ── libssh2 session ───────────────────────────────────────────────────────
    SshSessionPtr session(::libssh2_session_init());
    if (!session)
        return { ErrorCode::SshHandshakeFailed, "libssh2_session_init failed" };

    ::libssh2_session_set_blocking(session.get(), 1);

    if (::libssh2_session_handshake(session.get(), sock.get()) != 0)
        return ssh_error(session.get(), "SSH handshake failed", ErrorCode::SshHandshakeFailed);
    // Handshake complete — deleter may now send SSH_MSG_DISCONNECT on cleanup.
    session.get_deleter().send_disconnect = true;

    // Log host key fingerprint at DEBUG (trust-all policy — no verification)
    const char* fingerprint = ::libssh2_hostkey_hash(session.get(), LIBSSH2_HOSTKEY_HASH_SHA256);
    if (fingerprint != nullptr)
    {
        char fp_hex[65] = {};
        for (int i = 0; i < 32; ++i)
            ::snprintf(fp_hex + i * 2, 3, "%02x", static_cast<unsigned char>(fingerprint[i]));
        Logger::Debug("SSH host key SHA-256: %s", fp_hex);
    }

    // ── Password authentication ───────────────────────────────────────────────
    if (::libssh2_userauth_password(session.get(), username.c_str(), password.c_str()) != 0)
        return ssh_error(session.get(), "SSH auth failed for user '" + username + "'",
                         ErrorCode::SshAuthFailed);
    Logger::Info("SSH authenticated as '%s'", username.c_str());

    // ── Remote port forwarding ────────────────────────────────────────────────
    // SshListenerPtr declared after SshSessionPtr so it is destroyed first,
    // before the session is freed (forward_cancel requires a live session).
    int bound_port = 0;
    SshListenerPtr listener(::libssh2_channel_forward_listen_ex(
        session.get(), "127.0.0.1", forward_port, &bound_port, /*queue_maxsize=*/128));
    if (!listener)
        return ssh_error(session.get(), "tcpip-forward request failed (port " +
                         std::to_string(forward_port) + ")", ErrorCode::SshChannelOpenFailed);
    Logger::Info("Remote port forwarding active: 127.0.0.1:%d → SOCKS5", bound_port);

    // Configure keepalives
    if (keepalive_interval_ms > 0)
        ::libssh2_keepalive_config(session.get(), 1,
            static_cast<unsigned>(keepalive_interval_ms / 1000));

    // Switch to non-blocking for the accept loop
    ::libssh2_session_set_blocking(session.get(), 0);

    // ── All resources acquired — commit to members ────────────────────────────
    m_socket   = std::move(sock);
    m_session  = std::move(session);
    m_listener = std::move(listener);
    m_connected.store(true);
    return {};
}

//
// ── StartAccepting ────────────────────────────────────────────────────────────
//
// Launches the SSH I/O thread.  on_channel is called for each accepted
// forwarded-tcpip channel and must return a SessionPumpFn that the I/O thread
// calls every loop iteration.  on_disconnect is called when the loop exits.
//

void SshTransport::StartAccepting(OnChannelAccepted on_channel,
                                   OnDisconnected on_disconnect)
{
    m_io_thread = std::thread(&SshTransport::IoThreadProc, this,
                              std::move(on_channel), std::move(on_disconnect));
}

//////////////////////////////////////////////////////////////////////////////
//
// IoThreadProc
//
// Main SSH I/O loop.  Each iteration:
//   1. DrainIoCallbacks  — flush lambdas posted by IOCP threads (SendEof,
//                          channel_close/free) before touching libssh2.
//   2. keepalive_send    — sends SSH keepalive if the interval has elapsed.
//   3. DrainWriteQueues  — flushes buffered channel writes from IOCP threads.
//   4. PumpSessions      — calls each active session's SSH→TCP pump.
//   5. forward_accept    — accepts the next inbound forwarded-tcpip channel.
//
// When no channel is ready, select() blocks for at most 1 ms.  The short
// timeout keeps relay latency low for active sessions without busy-waiting
// when the tunnel is idle.
//
// LIBSSH2 THREAD SAFETY
//   s_is_io_thread is set to true for this thread's lifetime.  SshChannel
//   methods use it to determine whether to call libssh2 directly or queue.
//
//////////////////////////////////////////////////////////////////////////////

void SshTransport::IoThreadProc(OnChannelAccepted on_channel,
                                 OnDisconnected on_disconnect)
{
    s_is_io_thread = true;
    Logger::Debug("SSH I/O thread started");

    ErrorCode disconnect_reason = ErrorCode::Success;

    while (!m_cancel.load())
    {
        // ── Drain callbacks posted from IOCP threads ──────────────────────────
        DrainIoCallbacks();

        // ── Send keepalives ───────────────────────────────────────────────────
        int next_keepalive = 0;
        ::libssh2_keepalive_send(m_session.get(), &next_keepalive);

        // ── Drain per-channel write queues ────────────────────────────────────
        DrainWriteQueues();

        // ── Pump active SOCKS5 sessions (SSH channel → TCP) ───────────────────
        PumpSessions();

        // ── Accept new channels ───────────────────────────────────────────────
        LIBSSH2_CHANNEL* ch = ::libssh2_channel_forward_accept(m_listener.get());
        if (ch != nullptr)
        {
            Logger::Debug("Accepted forwarded-tcpip channel");

            // Inject thread-safety callbacks so IOCP threads never call
            // libssh2 directly through SshChannel::Write/SendEof/Close.
            SshChannel::ThreadingHooks hooks{
                [this, ch](std::vector<uint8_t> data)
                {
                    PostChannelWrite(ch, std::move(data));
                },
                [this](std::function<void()> fn)
                {
                    PostToIoThread(std::move(fn));
                },
                [this](LIBSSH2_CHANNEL* c)
                {
                    RemoveChannelWriteQueue(c);
                }
            };

            // Register channel in the write queue eagerly so PostChannelWrite
            // can safely discard writes for channels not found in the queue.
            {
                std::lock_guard<std::mutex> lock(m_queues_mutex);
                m_write_queues.push_back(ChannelQueue{ ch, {} });
            }

            auto ssh_ch = std::make_unique<SshChannel>(ch, std::move(hooks));
            auto pump = on_channel(std::move(ssh_ch));
            if (pump) RegisterSessionPump(std::move(pump));
            continue;
        }

        int rc = ::libssh2_session_last_errno(m_session.get());
        if (rc == LIBSSH2_ERROR_EAGAIN)
        {
            // No channel yet — select on socket
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(m_socket.get(), &fds);
            struct timeval tv{ 0, 1000 };  // 1 ms — keeps relay latency low while sessions are active
            ::select(0, &fds, nullptr, nullptr, &tv);
            continue;
        }

        if (rc == LIBSSH2_ERROR_CHANNEL_UNKNOWN)
        {
            // Stale packet arrived for a channel that was already freed — non-fatal
            continue;
        }

        // Unexpected session error
        char* errmsg = nullptr;
        ::libssh2_session_last_error(m_session.get(), &errmsg, nullptr, 0);
        Logger::Error("SSH session error: %s", errmsg != nullptr ? errmsg : "unknown");
        disconnect_reason = ErrorCode::ProtocolError;
        break;
    }

    m_connected.store(false);
    Logger::Debug("SSH I/O thread exiting");

    if (on_disconnect)
        on_disconnect(disconnect_reason);
}

//
// ── DrainWriteQueues ──────────────────────────────────────────────────────────
//
// Called on the SSH I/O thread.  For each channel that has pending write data
// (posted by IOCP threads via PostChannelWrite), calls libssh2_channel_write
// until the queue is empty or EAGAIN stalls the session.  A partial write
// shrinks the front buffer in place rather than re-queuing.
//

void SshTransport::DrainWriteQueues()
{
    std::lock_guard<std::mutex> lock(m_queues_mutex);
    for (auto& q : m_write_queues)
    {
        while (!q.pending.empty())
        {
            auto& buf = q.pending.front();
            ssize_t n = ::libssh2_channel_write(q.channel,
                reinterpret_cast<const char*>(buf.data()), buf.size());
            if (n == LIBSSH2_ERROR_EAGAIN) break;
            if (n <= 0)
            {
                q.pending.clear();
                break;
            }
            if (static_cast<size_t>(n) < buf.size())
            {
                buf.erase(buf.begin(), buf.begin() + n);
                break;
            }
            q.pending.pop_front();
        }
    }
}

//
// ── DrainIoCallbacks ──────────────────────────────────────────────────────────
//
// Swaps m_io_callbacks out under the lock, then invokes the callbacks outside
// the lock.  The swap-then-release pattern prevents deadlock if a callback
// itself calls PostToIoThread (which acquires m_io_callbacks_mutex).
//

void SshTransport::DrainIoCallbacks()
{
    std::vector<std::function<void()>> callbacks;
    {
        std::lock_guard<std::mutex> lock(m_io_callbacks_mutex);
        callbacks.swap(m_io_callbacks);
    }
    for (auto& fn : callbacks) fn();
}

//
// ── PumpSessions ──────────────────────────────────────────────────────────────
//
// Calls each registered SessionPumpFn (i.e. Socks5Session::PumpSshRead) once
// per I/O loop iteration.  Pumps that return false — session closed — are
// erased in-place via the erase-remove idiom.
//

void SshTransport::PumpSessions()
{
    m_session_pumps.erase(
        std::remove_if(m_session_pumps.begin(), m_session_pumps.end(),
            [](auto& fn) { return !fn(); }),
        m_session_pumps.end());
}

void SshTransport::RemoveChannelWriteQueue(LIBSSH2_CHANNEL* ch)
{
    std::lock_guard<std::mutex> lock(m_queues_mutex);
    m_write_queues.erase(
        std::remove_if(m_write_queues.begin(), m_write_queues.end(),
            [ch](const ChannelQueue& q) { return q.channel == ch; }),
        m_write_queues.end());
}

void SshTransport::PostChannelWrite(LIBSSH2_CHANNEL* ch, std::vector<uint8_t> data)
{
    std::lock_guard<std::mutex> lock(m_queues_mutex);
    for (auto& q : m_write_queues)
    {
        if (q.channel == ch)
        {
            q.pending.push_back(std::move(data));
            return;
        }
    }
    // Channel not registered (was closed and removed) — discard silently.
    // Never create a new entry here: the channel pointer may already be freed.
}

void SshTransport::RegisterSessionPump(SessionPumpFn fn)
{
    // Called on the SSH I/O thread (from within on_channel) — no mutex needed.
    m_session_pumps.push_back(std::move(fn));
}

void SshTransport::PostToIoThread(std::function<void()> fn)
{
    std::lock_guard<std::mutex> lock(m_io_callbacks_mutex);
    m_io_callbacks.push_back(std::move(fn));
}

void SshTransport::Close()
{
    m_cancel.store(true);
    if (m_io_thread.joinable())
        m_io_thread.join();

    // RAII destructors handle cleanup in correct order:
    // m_listener destroyed first (forward_cancel), then m_session (disconnect + free),
    // then m_socket (closesocket).
    m_listener.reset();
    m_session.reset();   // sends SSH_MSG_DISCONNECT if handshake was completed
    m_socket = WinSocket{};
    m_connected.store(false);
    Logger::Debug("SshTransport closed");
}

bool SshTransport::IsConnected() const
{
    return m_connected.load();
}
