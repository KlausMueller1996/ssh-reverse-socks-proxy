#include "tcp_connection.h"
#include "logger.h"
#include <cstring>

TcpConnection::TcpConnection()
    : m_socket(INVALID_SOCKET)
    , m_connected(false)
    , m_reading(false)
    , m_send_in_progress(false)
{
    InitializeCriticalSection(&m_send_cs);
}

TcpConnection::~TcpConnection() {
    Close();
    DeleteCriticalSection(&m_send_cs);
}

ErrorCode TcpConnection::ConnectAsync(const std::string& host, uint16_t port, OnConnected on_connected) {
    m_on_connected = std::move(on_connected);

    // DNS resolve (blocking — called from channel context)
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    sprintf_s(port_str, "%u", port);

    int ret = getaddrinfo(host.c_str(), port_str, &hints, &result);
    if (ret != 0 || !result) {
        Logger::Warn("DNS resolve failed for %s: %d", host.c_str(), ret);
        return ErrorCode::DnsResolutionFailed;
    }

    // Find first result and create socket
    struct addrinfo* addr = result;
    m_socket = WSASocketW(addr->ai_family, SOCK_STREAM, IPPROTO_TCP,
                          nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (m_socket == INVALID_SOCKET) {
        freeaddrinfo(result);
        return ErrorCode::SocketError;
    }

    // ConnectEx requires the socket to be bound
    struct sockaddr_storage bind_addr{};
    int bind_len = 0;
    if (addr->ai_family == AF_INET) {
        struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(&bind_addr);
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = INADDR_ANY;
        sa->sin_port = 0;
        bind_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(&bind_addr);
        sa->sin6_family = AF_INET6;
        sa->sin6_addr = in6addr_any;
        sa->sin6_port = 0;
        bind_len = sizeof(struct sockaddr_in6);
    }

    if (bind(m_socket, reinterpret_cast<struct sockaddr*>(&bind_addr), bind_len) != 0) {
        Logger::Error("bind failed: %d", WSAGetLastError());
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        freeaddrinfo(result);
        return ErrorCode::SocketError;
    }

    // Associate with IOCP
    ErrorCode ec = IoEngine::Associate(m_socket);
    if (ec != ErrorCode::Success) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        freeaddrinfo(result);
        return ec;
    }

    // Disable Nagle
    BOOL nodelay = TRUE;
    setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    // Initiate async connect
    ZeroMemory(static_cast<OVERLAPPED*>(&m_connect_ctx), sizeof(OVERLAPPED));
    m_connect_ctx.op = IoOp::Connect;
    m_connect_ctx.socket = m_socket;
    m_connect_ctx.callback = [this](IoContext* ctx, DWORD bytes, ErrorCode ec2) {
        if (ec2 == ErrorCode::Success) {
            // Update socket context so shutdown/getpeername work
            setsockopt(m_socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
            m_connected = true;
            Logger::Debug("Target connected (socket %llu)", static_cast<unsigned long long>(m_socket));
        }
        if (m_on_connected) m_on_connected(ec2);
    };

    LPFN_CONNECTEX connect_ex = IoEngine::GetConnectEx();
    BOOL ok = connect_ex(m_socket, addr->ai_addr, static_cast<int>(addr->ai_addrlen),
                         nullptr, 0, nullptr, &m_connect_ctx);
    freeaddrinfo(result);

    if (!ok) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            Logger::Error("ConnectEx failed: %d", err);
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
            return WsaToErrorCode(err);
        }
    }

    return ErrorCode::Success;
}

void TcpConnection::StartReading(OnDataReceived on_data, OnDisconnected on_disconnect) {
    m_on_data = std::move(on_data);
    m_on_disconnect = std::move(on_disconnect);
    m_reading = true;
    PostRecv();
}

void TcpConnection::PostRecv() {
    if (!m_connected || !m_reading) return;

    ZeroMemory(static_cast<OVERLAPPED*>(&m_recv_ctx), sizeof(OVERLAPPED));
    m_recv_ctx.op = IoOp::Recv;
    m_recv_ctx.socket = m_socket;
    m_recv_ctx.wsa_buf.buf = reinterpret_cast<char*>(m_recv_ctx.inline_buf);
    m_recv_ctx.wsa_buf.len = sizeof(m_recv_ctx.inline_buf);
    m_recv_ctx.callback = [this](IoContext* ctx, DWORD bytes, ErrorCode ec) {
        OnRecvComplete(ctx, bytes, ec);
    };

    DWORD flags = 0;
    int ret = WSARecv(m_socket, &m_recv_ctx.wsa_buf, 1, nullptr, &flags, &m_recv_ctx, nullptr);
    if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            Logger::Debug("WSARecv on target failed: %d", err);
            m_reading = false;
            if (m_on_disconnect) m_on_disconnect(WsaToErrorCode(err));
        }
    }
}

void TcpConnection::OnRecvComplete(IoContext* /*ctx*/, DWORD bytes, ErrorCode ec) {
    if (ec != ErrorCode::Success || bytes == 0) {
        m_reading = false;
        if (m_on_disconnect) m_on_disconnect(ec == ErrorCode::Success ? ErrorCode::ConnectionReset : ec);
        return;
    }

    if (m_on_data) {
        m_on_data(m_recv_ctx.inline_buf, bytes);
    }

    if (m_reading) {
        PostRecv();
    }
}

ErrorCode TcpConnection::Send(const uint8_t* data, size_t len) {
    if (!m_connected) return ErrorCode::ConnectionReset;

    EnterCriticalSection(&m_send_cs);

    m_send_queue.push(ByteBuffer(data, data + len));

    if (!m_send_in_progress) {
        FlushSendQueue();
    }

    LeaveCriticalSection(&m_send_cs);
    return ErrorCode::Success;
}

void TcpConnection::FlushSendQueue() {
    // Must be called with m_send_cs held
    if (m_send_queue.empty()) {
        m_send_in_progress = false;
        return;
    }

    m_send_in_progress = true;
    ByteBuffer& front = m_send_queue.front();

    ZeroMemory(static_cast<OVERLAPPED*>(&m_send_ctx), sizeof(OVERLAPPED));
    m_send_ctx.op = IoOp::Send;
    m_send_ctx.socket = m_socket;
    m_send_ctx.wsa_buf.buf = reinterpret_cast<char*>(front.data());
    m_send_ctx.wsa_buf.len = static_cast<ULONG>(front.size());
    m_send_ctx.callback = [this](IoContext* ctx, DWORD bytes, ErrorCode ec) {
        OnSendComplete(ctx, bytes, ec);
    };

    int ret = WSASend(m_socket, &m_send_ctx.wsa_buf, 1, nullptr, 0, &m_send_ctx, nullptr);
    if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            Logger::Debug("WSASend on target failed: %d", err);
            m_send_in_progress = false;
        }
    }
}

void TcpConnection::OnSendComplete(IoContext* /*ctx*/, DWORD /*bytes*/, ErrorCode ec) {
    EnterCriticalSection(&m_send_cs);

    if (!m_send_queue.empty()) {
        m_send_queue.pop();
    }

    if (ec != ErrorCode::Success) {
        m_send_in_progress = false;
        LeaveCriticalSection(&m_send_cs);
        return;
    }

    FlushSendQueue();
    LeaveCriticalSection(&m_send_cs);
}

void TcpConnection::Close() {
    m_connected = false;
    m_reading = false;

    if (m_socket != INVALID_SOCKET) {
        // Cancel pending I/O
        CancelIoEx(reinterpret_cast<HANDLE>(m_socket), nullptr);
        shutdown(m_socket, SD_BOTH);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }

    EnterCriticalSection(&m_send_cs);
    while (!m_send_queue.empty()) m_send_queue.pop();
    m_send_in_progress = false;
    LeaveCriticalSection(&m_send_cs);
}
