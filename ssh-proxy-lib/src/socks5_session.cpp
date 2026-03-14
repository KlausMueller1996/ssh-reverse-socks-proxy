#include "socks5_session.h"
#include "logger.h"

Socks5Session::Socks5Session(std::unique_ptr<IChannel> channel)
    : m_channel(std::move(channel))
    , m_tcp(std::make_shared<TcpConnection>())
{}

Socks5Session::~Socks5Session() {
    Close();
}

void Socks5Session::Start() {
    ReadFromChannel();
}

void Socks5Session::ReadFromChannel() {
    if (m_state.load() == State::Closed) return;

    uint8_t buf[4096];
    size_t bytes_read = 0;
    ErrorCode ec;

    // Loop on WouldBlock: on the SSH I/O thread, spin-wait until data arrives.
    do {
        ec = m_channel->Read(buf, sizeof(buf), bytes_read);
        if (ec == ErrorCode::WouldBlock) Sleep(1);
    } while (ec == ErrorCode::WouldBlock);

    if (ec != ErrorCode::Success || bytes_read == 0) {
        Close();
        return;
    }

    OnChannelData(buf, bytes_read);
}

void Socks5Session::OnChannelData(const uint8_t* data, size_t len) {
    m_inbound_buf.insert(m_inbound_buf.end(), data, data + len);

    switch (m_state.load()) {
    case State::ReadingMethods:
        HandleMethodNegotiation(m_inbound_buf.data(), m_inbound_buf.size());
        break;
    case State::ReadingRequest:
        HandleConnectRequest(m_inbound_buf.data(), m_inbound_buf.size());
        break;
    default:
        break;
    }
}

void Socks5Session::HandleMethodNegotiation(const uint8_t* data, size_t len) {
    bool supports_no_auth = false;
    int consumed = Socks5::ParseMethodRequest(data, len, supports_no_auth);

    if (consumed == 0) {
        ReadFromChannel();  // need more data
        return;
    }
    if (consumed < 0 || !supports_no_auth) {
        Logger::Warn("SOCKS5: method negotiation failed (no-auth not offered)");
        auto reply = Socks5::BuildMethodResponse(Socks5::AUTH_NO_ACCEPTABLE);
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    m_inbound_buf.erase(m_inbound_buf.begin(), m_inbound_buf.begin() + consumed);
    auto reply = Socks5::BuildMethodResponse(Socks5::AUTH_NONE);
    m_channel->Write(reply.data(), reply.size());

    m_state.store(State::ReadingRequest);
    ReadFromChannel();
}

void Socks5Session::HandleConnectRequest(const uint8_t* data, size_t len) {
    Socks5::ConnectRequest req{};
    int consumed = Socks5::ParseConnectRequest(data, len, req);

    if (consumed == 0) {
        ReadFromChannel();  // need more data
        return;
    }
    if (consumed < 0) {
        Logger::Warn("SOCKS5: malformed connect request");
        auto reply = Socks5::BuildConnectReply(Socks5::REP_GENERAL_FAILURE);
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    m_inbound_buf.erase(m_inbound_buf.begin(), m_inbound_buf.begin() + consumed);

    if (req.atyp != Socks5::ATYP_IPV4 &&
        req.atyp != Socks5::ATYP_IPV6 &&
        req.atyp != Socks5::ATYP_DOMAIN) {
        auto reply = Socks5::BuildConnectReply(Socks5::REP_ADDRESS_TYPE_NOT_SUPPORTED);
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    Logger::Debug("SOCKS5: CONNECT %s:%u", req.host.c_str(), req.port);
    StartTcpConnect(req);
}

void Socks5Session::StartTcpConnect(const Socks5::ConnectRequest& req) {
    m_state.store(State::Connecting);

    // Use weak_ptr: TcpConnection must not hold a strong ref back to the session
    // (session owns m_tcp, so that would be a cycle).
    std::weak_ptr<Socks5Session> weak = weak_from_this();
    m_tcp->ConnectAsync(req.host, req.port,
        [weak](ErrorCode connect_ec) {
            if (auto self = weak.lock()) self->OnTcpConnected(connect_ec);
        });
    // Errors (DNS failure, socket error) now arrive via the callback above.
}

void Socks5Session::OnTcpConnected(ErrorCode ec) {
    // This fires on an IOCP worker thread. All m_channel calls go through
    // the post_write / post_io queues and are safe to call here.

    if (ec != ErrorCode::Success) {
        Logger::Warn("SOCKS5: target TCP connect failed: %s", ErrorCodeToString(ec));
        auto reply = Socks5::BuildConnectReply(Socks5::ErrorCodeToSocks5Reply(ec));
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    // Send SOCKS5 success reply (enqueued → SSH I/O thread drains it).
    auto reply = Socks5::BuildConnectReply(Socks5::REP_SUCCESS);
    m_channel->Write(reply.data(), reply.size());

    m_state.store(State::Relaying);
    StartRelay();
}

void Socks5Session::StartRelay() {
    // Called from an IOCP thread. Set up the TCP→SSH direction only.
    // The SSH→TCP direction is handled by PumpSshRead(), called by the SSH I/O thread.

    // weak_ptr breaks the ownership cycle: session owns m_tcp (shared_ptr),
    // so m_tcp's callbacks must not hold a strong ref back to the session.
    std::weak_ptr<Socks5Session> weak = weak_from_this();

    m_tcp->StartReading(
        [weak](const uint8_t* data, size_t len) {
            if (auto self = weak.lock()) self->m_channel->Write(data, len);
        },
        [weak](ErrorCode) {
            if (auto self = weak.lock()) {
                self->m_channel->SendEof();
                self->Close();
            }
        });
}

bool Socks5Session::PumpSshRead() {
    // Called on the SSH I/O thread every loop iteration.

    State s = m_state.load();
    if (s == State::Closed) return false;
    if (s != State::Relaying) return true;  // still in handshake; keep pump alive

    uint8_t buf[4096];
    size_t bytes_read = 0;
    ErrorCode ec = m_channel->Read(buf, sizeof(buf), bytes_read);

    if (ec == ErrorCode::WouldBlock) return true;  // no data yet, try next iteration

    if (ec != ErrorCode::Success || bytes_read == 0) {
        Close();
        return false;
    }

    m_tcp->Send(buf, bytes_read);
    return true;
}

void Socks5Session::Close() {
    // Atomic exchange ensures Close runs exactly once even if called from both
    // the IOCP thread (TCP close callback) and the SSH I/O thread (PumpSshRead).
    State prev = m_state.exchange(State::Closed);
    if (prev == State::Closed) return;

    m_tcp->Close();
    if (m_channel) {
        m_channel->SendEof();
        m_channel->Close();
    }
    Logger::Debug("SOCKS5 session closed");
}
