#pragma once
#include "common.h"
#include "async_io.h"
#include <string>
#include <queue>

// Async outbound TCP connection to a target host.
class TcpConnection {
public:
    using OnConnected    = std::function<void(ErrorCode)>;
    using OnDataReceived = std::function<void(const uint8_t*, size_t)>;
    using OnDisconnected = std::function<void(ErrorCode)>;

    TcpConnection();
    ~TcpConnection();

    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    // Resolve host and begin async connect.
    // Callback fires on IOCP thread when connect completes.
    ErrorCode ConnectAsync(const std::string& host, uint16_t port, OnConnected on_connected);

    // Start async reads. Data delivered via on_data on IOCP threads.
    void StartReading(OnDataReceived on_data, OnDisconnected on_disconnect);

    // Async send. Data is queued and sent in order.
    ErrorCode Send(const uint8_t* data, size_t len);

    // Close the connection.
    void Close();

    SOCKET GetSocket() const { return m_socket; }

private:
    void PostRecv();
    void OnRecvComplete(IoContext* ctx, DWORD bytes, ErrorCode ec);
    void FlushSendQueue();
    void OnSendComplete(IoContext* ctx, DWORD bytes, ErrorCode ec);

    SOCKET              m_socket;
    bool                m_connected;
    bool                m_reading;

    IoContext            m_connect_ctx;
    IoContext            m_recv_ctx;
    IoContext            m_send_ctx;
    bool                m_send_in_progress;

    CRITICAL_SECTION    m_send_cs;
    std::queue<ByteBuffer> m_send_queue;

    OnConnected          m_on_connected;
    OnDataReceived       m_on_data;
    OnDisconnected       m_on_disconnect;
};
