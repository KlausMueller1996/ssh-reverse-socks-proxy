#pragma once
#include "common.h"
#include "async_io.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <queue>

// Async outbound TCP connection to a target host.
//
// Lifetime: always heap-allocated via std::make_shared<TcpConnection>().
// IoContext callbacks capture shared_ptr<TcpConnection> so the object stays
// alive until all pending IOCP completions have been processed.
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    using OnConnected    = std::function<void(ErrorCode)>;
    using OnDataReceived = std::function<void(const uint8_t*, size_t)>;
    using OnDisconnected = std::function<void(ErrorCode)>;

    TcpConnection();
    ~TcpConnection();

    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    // Post DNS resolution + async connect to an IOCP worker thread.
    // Fire-and-forget: returns immediately; all results arrive via on_connected callback.
    void ConnectAsync(const std::string& host, uint16_t port, OnConnected on_connected);

    // Start async reads. Data delivered via on_data on IOCP threads.
    void StartReading(OnDataReceived on_data, OnDisconnected on_disconnect);

    // Async send. Data is queued and sent in order.
    ErrorCode Send(const uint8_t* data, size_t len);

    // Close the connection.
    void Close();

    SOCKET GetSocket() const { return m_socket; }

private:
    // Runs on an IOCP worker thread: DNS + socket setup + ConnectEx.
    void DoConnectOnWorkerThread(std::string host, uint16_t port);
    void PostRecv();
    void OnRecvComplete(IoContext* ctx, DWORD bytes, ErrorCode ec);
    void FlushSendQueue();
    void OnSendComplete(IoContext* ctx, DWORD bytes, ErrorCode ec);

    SOCKET                m_socket;
    std::atomic<bool>     m_connected{false};
    std::atomic<bool>     m_reading{false};
    std::atomic<bool>     m_abort{false};   // set by Close(); guards DoConnectOnWorkerThread

    IoContext             m_dns_ctx;        // work item: DNS + connect setup on worker thread
    IoContext             m_connect_ctx;
    IoContext             m_recv_ctx;
    IoContext             m_send_ctx;
    bool                  m_send_in_progress;

    std::mutex            m_send_mutex;
    std::queue<ByteBuffer> m_send_queue;

    OnConnected          m_on_connected;
    OnDataReceived       m_on_data;
    OnDisconnected       m_on_disconnect;
};
