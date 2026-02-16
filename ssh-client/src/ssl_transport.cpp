#include "ssl_transport.h"
#include "logger.h"
#include <cstdio>

static constexpr size_t INITIAL_DECRYPT_BUF_SIZE = 32 * 1024;
static constexpr size_t MAX_DECRYPT_BUF_SIZE = 256 * 1024;

SslTransport::SslTransport()
    : m_socket(INVALID_SOCKET)
    , m_cred_acquired(false)
    , m_context_initialized(false)
    , m_connected(false)
    , m_stream_sizes{}
    , m_decrypt_buf_used(0)
{
    SecInvalidateHandle(&m_cred_handle);
    SecInvalidateHandle(&m_sec_context);
    InitializeCriticalSection(&m_send_cs);
    m_decrypt_buf.resize(INITIAL_DECRYPT_BUF_SIZE);
}

SslTransport::~SslTransport() {
    Close();
    DeleteCriticalSection(&m_send_cs);
}

ErrorCode SslTransport::Connect(const char* host, uint16_t port, bool verify_cert) {
    // DNS resolve
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    sprintf_s(port_str, "%u", port);

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0 || !result) {
        Logger::Error("DNS resolution failed for %s: %d", host, ret);
        return ErrorCode::DnsResolutionFailed;
    }

    // Create socket and connect (blocking for handshake)
    m_socket = INVALID_SOCKET;
    for (struct addrinfo* ptr = result; ptr; ptr = ptr->ai_next) {
        m_socket = socket(ptr->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (m_socket == INVALID_SOCKET)
            continue;

        if (connect(m_socket, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0)
            break;

        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    freeaddrinfo(result);

    if (m_socket == INVALID_SOCKET) {
        Logger::Error("TCP connect to %s:%u failed: %d", host, port, WSAGetLastError());
        return ErrorCode::ConnectionRefused;
    }

    Logger::Info("TCP connected to %s:%u", host, port);

    // Disable Nagle
    BOOL nodelay = TRUE;
    setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    // Acquire SChannel credentials
    SCH_CREDENTIALS sch_cred{};
    sch_cred.dwVersion = SCH_CREDENTIALS_VERSION;
    sch_cred.dwFlags = SCH_USE_STRONG_CRYPTO;
    if (!verify_cert) {
        sch_cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        nullptr, const_cast<char*>(UNISP_NAME_A), SECPKG_CRED_OUTBOUND,
        nullptr, &sch_cred, nullptr, nullptr, &m_cred_handle, nullptr);

    if (ss != SEC_E_OK) {
        Logger::Error("AcquireCredentialsHandle failed: 0x%08X", ss);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        return ErrorCode::SslHandshakeFailed;
    }
    m_cred_acquired = true;

    // TLS handshake
    ErrorCode ec = DoHandshake(host, verify_cert);
    if (ec != ErrorCode::Success) {
        Close();
        return ec;
    }

    // Query stream sizes
    ss = QueryContextAttributes(&m_sec_context, SECPKG_ATTR_STREAM_SIZES, &m_stream_sizes);
    if (ss != SEC_E_OK) {
        Logger::Error("QueryContextAttributes STREAM_SIZES failed: 0x%08X", ss);
        Close();
        return ErrorCode::SslHandshakeFailed;
    }

    Logger::Info("TLS handshake complete (header=%lu trailer=%lu max_msg=%lu)",
        m_stream_sizes.cbHeader, m_stream_sizes.cbTrailer, m_stream_sizes.cbMaximumMessage);

    m_connected = true;
    return ErrorCode::Success;
}

ErrorCode SslTransport::DoHandshake(const char* host, bool /*verify_cert*/) {
    DWORD sspi_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                       ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                       ISC_REQ_STREAM;

    SecBuffer out_buf{};
    out_buf.BufferType = SECBUFFER_TOKEN;
    SecBufferDesc out_desc{};
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buf;

    // First call — no input
    DWORD out_flags = 0;
    SECURITY_STATUS ss = InitializeSecurityContextA(
        &m_cred_handle, nullptr, const_cast<char*>(host),
        sspi_flags, 0, 0, nullptr, 0,
        &m_sec_context, &out_desc, &out_flags, nullptr);

    m_context_initialized = true;

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK) {
        Logger::Error("InitializeSecurityContext (initial) failed: 0x%08X", ss);
        return ErrorCode::SslHandshakeFailed;
    }

    // Send initial token
    if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
        ErrorCode ec = SendRaw(static_cast<uint8_t*>(out_buf.pvBuffer), out_buf.cbBuffer);
        FreeContextBuffer(out_buf.pvBuffer);
        if (ec != ErrorCode::Success) return ec;
    }

    // Handshake loop
    ByteBuffer hs_buf(16384);
    size_t hs_used = 0;

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        // Read more data from server
        size_t bytes_read = 0;
        ErrorCode ec = RecvRaw(hs_buf.data() + hs_used, hs_buf.size() - hs_used, bytes_read);
        if (ec != ErrorCode::Success) return ec;
        if (bytes_read == 0) return ErrorCode::SslDisconnected;
        hs_used += bytes_read;

        // Set up input buffers
        SecBuffer in_bufs[2]{};
        in_bufs[0].BufferType = SECBUFFER_TOKEN;
        in_bufs[0].pvBuffer = hs_buf.data();
        in_bufs[0].cbBuffer = static_cast<ULONG>(hs_used);
        in_bufs[1].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc in_desc{};
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_bufs;

        SecBuffer out_buf2{};
        out_buf2.BufferType = SECBUFFER_TOKEN;
        SecBufferDesc out_desc2{};
        out_desc2.ulVersion = SECBUFFER_VERSION;
        out_desc2.cBuffers = 1;
        out_desc2.pBuffers = &out_buf2;

        out_flags = 0;
        ss = InitializeSecurityContextA(
            &m_cred_handle, &m_sec_context, nullptr,
            sspi_flags, 0, 0, &in_desc, 0,
            nullptr, &out_desc2, &out_flags, nullptr);

        // Send any output token
        if (out_buf2.cbBuffer > 0 && out_buf2.pvBuffer) {
            ec = SendRaw(static_cast<uint8_t*>(out_buf2.pvBuffer), out_buf2.cbBuffer);
            FreeContextBuffer(out_buf2.pvBuffer);
            if (ec != ErrorCode::Success) return ec;
        }

        // Handle extra data (unconsumed by SChannel)
        if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
            size_t extra = in_bufs[1].cbBuffer;
            memmove(hs_buf.data(), hs_buf.data() + hs_used - extra, extra);
            hs_used = extra;
        } else if (ss != SEC_E_INCOMPLETE_MESSAGE) {
            hs_used = 0;
        }

        // Grow buffer if needed
        if (hs_used >= hs_buf.size()) {
            hs_buf.resize(hs_buf.size() * 2);
        }

        if (ss == SEC_E_OK) {
            // Handshake complete — save any extra data into decrypt buffer
            if (hs_used > 0) {
                memcpy(m_decrypt_buf.data(), hs_buf.data(), hs_used);
                m_decrypt_buf_used = hs_used;
            }
            Logger::Debug("TLS handshake succeeded");
            return ErrorCode::Success;
        }

        if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE) {
            Logger::Error("InitializeSecurityContext failed: 0x%08X", ss);
            return ErrorCode::SslHandshakeFailed;
        }
    }

    return ErrorCode::SslHandshakeFailed;
}

void SslTransport::StartReading(OnDataReceived on_data, OnDisconnected on_disconnect) {
    m_on_data = std::move(on_data);
    m_on_disconnect = std::move(on_disconnect);

    // Associate socket with IOCP
    IoEngine::Associate(m_socket);

    // If there's leftover data from the handshake, process it first
    if (m_decrypt_buf_used > 0) {
        ProcessDecryptBuffer();
    }

    // Post first async recv
    PostRecv();
}

void SslTransport::PostRecv() {
    if (!m_connected) return;

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
            Logger::Error("WSARecv failed: %d", err);
            if (m_on_disconnect) m_on_disconnect(WsaToErrorCode(err));
        }
    }
}

void SslTransport::OnRecvComplete(IoContext* /*ctx*/, DWORD bytes, ErrorCode ec) {
    if (ec != ErrorCode::Success || bytes == 0) {
        Logger::Info("SSL recv completed with %s (bytes=%lu)",
            ErrorCodeToString(ec), static_cast<unsigned long>(bytes));
        m_connected = false;
        if (m_on_disconnect) m_on_disconnect(ec == ErrorCode::Success ? ErrorCode::SslDisconnected : ec);
        return;
    }

    // Append received ciphertext to decrypt buffer
    if (m_decrypt_buf_used + bytes > m_decrypt_buf.size()) {
        size_t new_size = m_decrypt_buf_used + bytes + 4096;
        if (new_size > MAX_DECRYPT_BUF_SIZE) {
            Logger::Error("Decrypt buffer overflow");
            m_connected = false;
            if (m_on_disconnect) m_on_disconnect(ErrorCode::ProtocolError);
            return;
        }
        m_decrypt_buf.resize(new_size);
    }
    memcpy(m_decrypt_buf.data() + m_decrypt_buf_used, m_recv_ctx.inline_buf, bytes);
    m_decrypt_buf_used += bytes;

    ProcessDecryptBuffer();

    // Continue reading
    if (m_connected) {
        PostRecv();
    }
}

void SslTransport::ProcessDecryptBuffer() {
    while (m_decrypt_buf_used > 0) {
        SecBuffer bufs[4]{};
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = m_decrypt_buf.data();
        bufs[0].cbBuffer = static_cast<ULONG>(m_decrypt_buf_used);
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc buf_desc{};
        buf_desc.ulVersion = SECBUFFER_VERSION;
        buf_desc.cBuffers = 4;
        buf_desc.pBuffers = bufs;

        SECURITY_STATUS ss = DecryptMessage(&m_sec_context, &buf_desc, 0, nullptr);

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            // Need more data
            break;
        }

        if (ss == SEC_I_CONTEXT_EXPIRED) {
            Logger::Info("TLS shutdown received from server");
            m_connected = false;
            if (m_on_disconnect) m_on_disconnect(ErrorCode::SslDisconnected);
            return;
        }

        if (ss != SEC_E_OK) {
            Logger::Error("DecryptMessage failed: 0x%08X", ss);
            m_connected = false;
            if (m_on_disconnect) m_on_disconnect(ErrorCode::SslDecryptError);
            return;
        }

        // Find the decrypted data and extra buffers
        const uint8_t* plaintext = nullptr;
        size_t plaintext_len = 0;
        size_t extra_len = 0;

        for (int i = 0; i < 4; ++i) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                plaintext = static_cast<const uint8_t*>(bufs[i].pvBuffer);
                plaintext_len = bufs[i].cbBuffer;
            }
            if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer > 0) {
                extra_len = bufs[i].cbBuffer;
            }
        }

        // Deliver decrypted data
        if (plaintext && plaintext_len > 0 && m_on_data) {
            m_on_data(plaintext, plaintext_len);
        }

        // Move extra data to front of buffer
        if (extra_len > 0) {
            memmove(m_decrypt_buf.data(),
                    m_decrypt_buf.data() + m_decrypt_buf_used - extra_len,
                    extra_len);
            m_decrypt_buf_used = extra_len;
        } else {
            m_decrypt_buf_used = 0;
        }
    }
}

ErrorCode SslTransport::Send(const uint8_t* data, size_t len) {
    if (!m_connected) return ErrorCode::SslDisconnected;

    EnterCriticalSection(&m_send_cs);

    // Encrypt and send in chunks of cbMaximumMessage
    size_t max_chunk = m_stream_sizes.cbMaximumMessage;
    size_t offset = 0;

    // Allocate a send buffer: header + data + trailer
    size_t send_buf_size = m_stream_sizes.cbHeader + max_chunk + m_stream_sizes.cbTrailer;
    ByteBuffer send_buf(send_buf_size);

    ErrorCode ec = ErrorCode::Success;

    while (offset < len) {
        size_t chunk = (std::min)(len - offset, max_chunk);

        // Build the message: [header][data][trailer]
        uint8_t* header_ptr = send_buf.data();
        uint8_t* data_ptr = header_ptr + m_stream_sizes.cbHeader;
        uint8_t* trailer_ptr = data_ptr + chunk;

        memcpy(data_ptr, data + offset, chunk);

        SecBuffer bufs[4]{};
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = header_ptr;
        bufs[0].cbBuffer = m_stream_sizes.cbHeader;

        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = data_ptr;
        bufs[1].cbBuffer = static_cast<ULONG>(chunk);

        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = trailer_ptr;
        bufs[2].cbBuffer = m_stream_sizes.cbTrailer;

        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc buf_desc{};
        buf_desc.ulVersion = SECBUFFER_VERSION;
        buf_desc.cBuffers = 4;
        buf_desc.pBuffers = bufs;

        SECURITY_STATUS ss = EncryptMessage(&m_sec_context, 0, &buf_desc, 0);
        if (ss != SEC_E_OK) {
            Logger::Error("EncryptMessage failed: 0x%08X", ss);
            ec = ErrorCode::SslEncryptError;
            break;
        }

        // Total encrypted length
        size_t total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        ec = SendRaw(send_buf.data(), total);
        if (ec != ErrorCode::Success) break;

        offset += chunk;
    }

    LeaveCriticalSection(&m_send_cs);
    return ec;
}

ErrorCode SslTransport::SendRaw(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int ret = send(m_socket, reinterpret_cast<const char*>(data + sent),
                       static_cast<int>(len - sent), 0);
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            Logger::Error("send() failed: %d", err);
            return WsaToErrorCode(err);
        }
        if (ret == 0) return ErrorCode::SslDisconnected;
        sent += static_cast<size_t>(ret);
    }
    return ErrorCode::Success;
}

ErrorCode SslTransport::RecvRaw(uint8_t* buf, size_t buf_size, size_t& bytes_read) {
    int ret = recv(m_socket, reinterpret_cast<char*>(buf), static_cast<int>(buf_size), 0);
    if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Logger::Error("recv() failed: %d", err);
        return WsaToErrorCode(err);
    }
    bytes_read = static_cast<size_t>(ret);
    return ErrorCode::Success;
}

void SslTransport::Close() {
    m_connected = false;

    if (m_context_initialized) {
        // Send TLS shutdown
        DWORD type = SCHANNEL_SHUTDOWN;
        SecBuffer buf{};
        buf.BufferType = SECBUFFER_TOKEN;
        buf.pvBuffer = &type;
        buf.cbBuffer = sizeof(type);

        SecBufferDesc buf_desc{};
        buf_desc.ulVersion = SECBUFFER_VERSION;
        buf_desc.cBuffers = 1;
        buf_desc.pBuffers = &buf;

        ApplyControlToken(&m_sec_context, &buf_desc);

        // Build final shutdown token
        SecBuffer out_buf{};
        out_buf.BufferType = SECBUFFER_TOKEN;
        SecBufferDesc out_desc{};
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buf;

        DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                      ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM;
        DWORD out_flags = 0;
        SECURITY_STATUS ss = InitializeSecurityContextA(
            &m_cred_handle, &m_sec_context, nullptr,
            flags, 0, 0, nullptr, 0,
            nullptr, &out_desc, &out_flags, nullptr);

        if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
            if (out_buf.cbBuffer > 0 && out_buf.pvBuffer) {
                SendRaw(static_cast<uint8_t*>(out_buf.pvBuffer), out_buf.cbBuffer);
                FreeContextBuffer(out_buf.pvBuffer);
            }
        }

        DeleteSecurityContext(&m_sec_context);
        SecInvalidateHandle(&m_sec_context);
        m_context_initialized = false;
    }

    if (m_cred_acquired) {
        FreeCredentialsHandle(&m_cred_handle);
        SecInvalidateHandle(&m_cred_handle);
        m_cred_acquired = false;
    }

    if (m_socket != INVALID_SOCKET) {
        shutdown(m_socket, SD_BOTH);
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }

    m_decrypt_buf_used = 0;
    Logger::Debug("SslTransport closed");
}
