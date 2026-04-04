//////////////////////////////////////////////////////////////////////////////
//
// TcpConnection — async TCP connection to SOCKS5 target hosts (IOCP)
//
// PURPOSE
//   Handles the outbound TCP leg of each SOCKS5 relay: asynchronous DNS,
//   ConnectEx, a continuous overlapped recv loop, and a serialised send queue —
//   all driven by the process-wide IOCP via IoEngine.
//
// CONNECTEX REQUIREMENTS
//   ConnectEx requires the socket to be bound before the call (bound to
//   INADDR_ANY:0 here).  After the completion fires, SO_UPDATE_CONNECT_CONTEXT
//   must be set on the socket before normal socket operations can be used.
//
// DNS OFFLOAD
//   getaddrinfo is blocking.  ConnectAsync posts a work item via
//   IoEngine::PostCompletion so DNS runs on an IOCP worker thread rather than
//   the SSH I/O thread.  m_abort is checked before and after getaddrinfo to
//   handle Close() being called while DNS was in flight.
//
// SEND SERIALISATION
//   Only one WSASend is outstanding at a time.  Send() enqueues data and
//   starts FlushSendQueue() if no send is in progress; OnSendComplete() calls
//   it again to drain the next entry.  Both call sites hold m_send_mutex.
//
// CLOSE SEQUENCE
//   CancelIoEx cancels all pending overlapped operations; each completion
//   arrives with ERROR_OPERATION_ABORTED (mapped to ErrorCode::Shutdown).
//   shutdown(SD_BOTH) + closesocket follow to release the socket handle.
//
//////////////////////////////////////////////////////////////////////////////

#include "tcp_connection.h"
#include "logger.h"
#include <cstring>

TcpConnection::TcpConnection()
    : m_socket(INVALID_SOCKET)
    , m_send_in_progress(false)
{}

TcpConnection::~TcpConnection()
{
    Close();
}

//
// ── ConnectAsync ──────────────────────────────────────────────────────────────
//
// Initiates an async connect.  DNS resolution is blocking, so this posts a
// work item to an IOCP worker thread (DoConnectOnWorkerThread) rather than
// resolving inline, which would block the SSH I/O thread.
//

void TcpConnection::ConnectAsync(const std::string& host, uint16_t port,
                                  OnConnected on_connected)
{
    m_on_connected = std::move(on_connected);

    // Post DNS + socket setup as a work item on an IOCP worker thread so the
    // SSH I/O thread is not blocked by getaddrinfo.
    ::ZeroMemory(static_cast<OVERLAPPED*>(&m_dns_ctx), sizeof(OVERLAPPED));
    m_dns_ctx.op = IoOp::Work;
    m_dns_ctx.callback = [self = shared_from_this(), host, port]
                         (IoContext*, DWORD, ErrorCode) mutable
    {
        self->DoConnectOnWorkerThread(std::move(host), port);
    };
    IoEngine::PostCompletion(&m_dns_ctx);
}

//////////////////////////////////////////////////////////////////////////////
//
// DoConnectOnWorkerThread
//
// Runs on an IOCP worker thread.  Performs the blocking DNS resolve, creates
// and binds the socket (ConnectEx requires a pre-bound socket), associates it
// with the IOCP, then fires ConnectEx to initiate the async connect.
//
// m_abort is checked after getaddrinfo: if Close() was called while DNS was
// in flight the result is discarded and the on_connected callback gets
// ErrorCode::Shutdown instead of proceeding with a socket that will be
// immediately closed.
//
//////////////////////////////////////////////////////////////////////////////

void TcpConnection::DoConnectOnWorkerThread(std::string host, uint16_t port)
{
    // Guard against Close() being called before this work item was processed.
    if (m_abort.load())
    {
        if (m_on_connected) m_on_connected(ErrorCode::Shutdown);
        return;
    }

    // DNS resolve (blocking, but on an IOCP worker thread — not the SSH I/O thread)
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    ::sprintf_s(port_str, "%u", port);

    int ret = ::getaddrinfo(host.c_str(), port_str, &hints, &result);
    if (ret != 0 || result == nullptr)
    {
        Logger::Warn("DNS resolve failed for %s: %d", host.c_str(), ret);
        if (m_on_connected) m_on_connected(ErrorCode::DnsResolutionFailed);
        return;
    }

    if (m_abort.load())
    {
        ::freeaddrinfo(result);
        if (m_on_connected) m_on_connected(ErrorCode::Shutdown);
        return;
    }

    struct addrinfo* addr = result;
    m_socket = ::WSASocketW(addr->ai_family, SOCK_STREAM, IPPROTO_TCP,
                            nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (m_socket == INVALID_SOCKET)
    {
        ::freeaddrinfo(result);
        if (m_on_connected) m_on_connected(ErrorCode::SocketError);
        return;
    }

    // ConnectEx requires the socket to be bound
    struct sockaddr_in bind_addr{};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = 0;

    if (::bind(m_socket, reinterpret_cast<struct sockaddr*>(&bind_addr),
               sizeof(bind_addr)) != 0)
    {
        Logger::Error("bind failed: %d", ::WSAGetLastError());
        ::closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        ::freeaddrinfo(result);
        if (m_on_connected) m_on_connected(ErrorCode::SocketError);
        return;
    }

    // Associate with IOCP
    ErrorCode ec = IoEngine::Associate(m_socket);
    if (ec != ErrorCode::Success)
    {
        ::closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        ::freeaddrinfo(result);
        if (m_on_connected) m_on_connected(ec);
        return;
    }

    // Disable Nagle
    BOOL nodelay = TRUE;
    ::setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    // Initiate async connect
    ::ZeroMemory(static_cast<OVERLAPPED*>(&m_connect_ctx), sizeof(OVERLAPPED));
    m_connect_ctx.op     = IoOp::Connect;
    m_connect_ctx.socket = m_socket;
    m_connect_ctx.callback = [self = shared_from_this()]
                              (IoContext*, DWORD, ErrorCode ec2)
    {
        if (ec2 == ErrorCode::Success)
        {
            ::setsockopt(self->m_socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
                         nullptr, 0);
            self->m_connected.store(true);
            Logger::Debug("Target connected (socket %llu)",
                          static_cast<unsigned long long>(self->m_socket));
        }
        if (self->m_on_connected) self->m_on_connected(ec2);
    };

    LPFN_CONNECTEX connect_ex = IoEngine::GetConnectEx();
    BOOL ok = connect_ex(m_socket, addr->ai_addr,
                         static_cast<int>(addr->ai_addrlen),
                         nullptr, 0, nullptr, &m_connect_ctx);
    ::freeaddrinfo(result);

    if (!ok)
    {
        int err = ::WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            Logger::Error("ConnectEx failed: %d", err);
            m_connect_ctx.callback = nullptr;  // release shared_ptr
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            if (m_on_connected) m_on_connected(WsaToErrorCode(err));
        }
    }
}

void TcpConnection::StartReading(OnDataReceived on_data, OnDisconnected on_disconnect)
{
    m_on_data       = std::move(on_data);
    m_on_disconnect = std::move(on_disconnect);
    m_reading.store(true);
    PostRecv();
}

//
// ── PostRecv ──────────────────────────────────────────────────────────────────
//
// Issues one overlapped WSARecv into m_recv_ctx.inline_buf.  The completion
// callback (OnRecvComplete) delivers the data then re-issues PostRecv to keep
// the recv loop running for the lifetime of the connection.
//

void TcpConnection::PostRecv()
{
    if (!m_connected.load() || !m_reading.load()) return;

    ::ZeroMemory(static_cast<OVERLAPPED*>(&m_recv_ctx), sizeof(OVERLAPPED));
    m_recv_ctx.op            = IoOp::Recv;
    m_recv_ctx.socket        = m_socket;
    m_recv_ctx.wsa_buf.buf   = reinterpret_cast<char*>(m_recv_ctx.inline_buf);
    m_recv_ctx.wsa_buf.len   = sizeof(m_recv_ctx.inline_buf);
    m_recv_ctx.callback = [self = shared_from_this()](IoContext* ctx, DWORD bytes,
                                                       ErrorCode ec)
    {
        self->OnRecvComplete(ctx, bytes, ec);
    };

    DWORD flags = 0;
    int ret = ::WSARecv(m_socket, &m_recv_ctx.wsa_buf, 1, nullptr, &flags,
                        &m_recv_ctx, nullptr);
    if (ret == SOCKET_ERROR)
    {
        int err = ::WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            Logger::Debug("WSARecv on target failed: %d", err);
            m_reading.store(false);
            if (m_on_disconnect) m_on_disconnect(WsaToErrorCode(err));
        }
    }
}

//
// ── OnRecvComplete ────────────────────────────────────────────────────────────
//
// IOCP completion for WSARecv.  Zero bytes with Success signals a graceful
// TCP close; the on_disconnect callback receives ConnectionReset to let the
// session close both sides cleanly.
//

void TcpConnection::OnRecvComplete(IoContext* /*ctx*/, DWORD bytes, ErrorCode ec)
{
    if (ec != ErrorCode::Success || bytes == 0)
    {
        m_reading.store(false);
        if (m_on_disconnect)
            m_on_disconnect(ec == ErrorCode::Success ? ErrorCode::ConnectionReset : ec);
        return;
    }

    if (m_on_data)
    {
        m_on_data(m_recv_ctx.inline_buf, bytes);
    }

    if (m_reading.load())
    {
        PostRecv();
    }
}

//
// ── Send ──────────────────────────────────────────────────────────────────────
//
// Thread-safe enqueue.  Copies data into the send queue and starts
// FlushSendQueue() if no WSASend is currently outstanding.  Called from
// IOCP worker threads (TCP→SSH relay callback) and the SSH I/O thread.
//

ErrorCode TcpConnection::Send(const uint8_t* data, size_t len)
{
    if (!m_connected.load()) return ErrorCode::ConnectionReset;

    std::unique_lock<std::mutex> lock(m_send_mutex);
    m_send_queue.push(ByteBuffer(data, data + len));
    if (!m_send_in_progress)
        FlushSendQueue();  // called with lock held
    return ErrorCode::Success;
}

void TcpConnection::FlushSendQueue()
{
    // Must be called with m_send_cs held
    if (m_send_queue.empty())
    {
        m_send_in_progress = false;
        return;
    }

    m_send_in_progress = true;
    ByteBuffer& front = m_send_queue.front();

    ::ZeroMemory(static_cast<OVERLAPPED*>(&m_send_ctx), sizeof(OVERLAPPED));
    m_send_ctx.op            = IoOp::Send;
    m_send_ctx.socket        = m_socket;
    m_send_ctx.wsa_buf.buf   = reinterpret_cast<char*>(front.data());
    m_send_ctx.wsa_buf.len   = static_cast<ULONG>(front.size());
    m_send_ctx.callback = [self = shared_from_this()](IoContext* ctx, DWORD bytes,
                                                       ErrorCode ec)
    {
        self->OnSendComplete(ctx, bytes, ec);
    };

    int ret = ::WSASend(m_socket, &m_send_ctx.wsa_buf, 1, nullptr, 0,
                        &m_send_ctx, nullptr);
    if (ret == SOCKET_ERROR)
    {
        int err = ::WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            Logger::Debug("WSASend on target failed: %d", err);
            m_send_in_progress = false;
        }
    }
}

void TcpConnection::OnSendComplete(IoContext* /*ctx*/, DWORD /*bytes*/, ErrorCode ec)
{
    std::unique_lock<std::mutex> lock(m_send_mutex);
    if (!m_send_queue.empty())
        m_send_queue.pop();
    if (ec != ErrorCode::Success)
    {
        m_send_in_progress = false;
        return;
    }
    FlushSendQueue();  // called with lock held
}

//
// ── Close ─────────────────────────────────────────────────────────────────────
//
// Sets the abort/connected/reading flags first so any in-flight callbacks see
// a closed state before CancelIoEx fires their completions.  The send queue
// is drained under m_send_mutex to release any pending ByteBuffer memory.
//

void TcpConnection::Close()
{
    m_abort.store(true);
    m_connected.store(false);
    m_reading.store(false);

    if (m_socket != INVALID_SOCKET)
    {
        ::CancelIoEx(reinterpret_cast<HANDLE>(m_socket), nullptr);
        ::shutdown(m_socket, SD_BOTH);
        ::closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }

    std::lock_guard<std::mutex> lock(m_send_mutex);
    while (!m_send_queue.empty()) m_send_queue.pop();
    m_send_in_progress = false;
}
