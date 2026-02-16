#pragma once
#include "common.h"
#include "async_io.h"

class SslTransport {
public:
    // Callback types
    using OnDataReceived = std::function<void(const uint8_t*, size_t)>;
    using OnDisconnected = std::function<void(ErrorCode)>;

    SslTransport();
    ~SslTransport();

    // Non-copyable
    SslTransport(const SslTransport&) = delete;
    SslTransport& operator=(const SslTransport&) = delete;

    // Connect to server, perform TLS handshake.
    // Blocks until handshake completes (called from reconnect loop thread).
    ErrorCode Connect(const char* host, uint16_t port, bool verify_cert);

    // Start async reading from the SSL socket.
    // Decrypted data is delivered via on_data callback on IOCP threads.
    void StartReading(OnDataReceived on_data, OnDisconnected on_disconnect);

    // Send data over SSL (encrypts + sends). Thread-safe.
    ErrorCode Send(const uint8_t* data, size_t len);

    // Graceful SSL shutdown + socket close.
    void Close();

    bool IsConnected() const { return m_connected; }

private:
    ErrorCode DoHandshake(const char* host, bool verify_cert);
    ErrorCode SendRaw(const uint8_t* data, size_t len);
    ErrorCode RecvRaw(uint8_t* buf, size_t buf_size, size_t& bytes_read);
    void PostRecv();
    void OnRecvComplete(IoContext* ctx, DWORD bytes, ErrorCode ec);
    void ProcessDecryptBuffer();

    SOCKET              m_socket;
    CredHandle          m_cred_handle;
    CtxtHandle          m_sec_context;
    bool                m_cred_acquired;
    bool                m_context_initialized;
    bool                m_connected;

    // Stream sizes from SChannel
    SecPkgContext_StreamSizes m_stream_sizes;

    // Receive decryption buffer (accumulates TLS records)
    ByteBuffer          m_decrypt_buf;
    size_t              m_decrypt_buf_used;

    // Send serialization
    CRITICAL_SECTION    m_send_cs;

    // Async read context
    IoContext            m_recv_ctx;
    OnDataReceived       m_on_data;
    OnDisconnected       m_on_disconnect;
};
