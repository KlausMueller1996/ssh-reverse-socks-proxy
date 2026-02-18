#include "socks5_session.h"
#include "logger.h"

Socks5Session::Socks5Session(std::unique_ptr<IChannel> channel)
    : m_channel(std::move(channel))
{}

Socks5Session::~Socks5Session() {
    Close();
}

void Socks5Session::Start() {
    ReadFromChannel();
}

void Socks5Session::ReadFromChannel() {
    if (m_state == State::Closed) return;

    uint8_t buf[4096];
    size_t bytes_read = 0;
    ErrorCode ec = m_channel->Read(buf, sizeof(buf), bytes_read);

    if (ec != ErrorCode::Success || bytes_read == 0) {
        Close();
        return;
    }

    OnChannelData(buf, bytes_read);
}

void Socks5Session::OnChannelData(const uint8_t* data, size_t len) {
    m_inbound_buf.insert(m_inbound_buf.end(), data, data + len);

    switch (m_state) {
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

    m_state = State::ReadingRequest;
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
    m_state = State::Connecting;

    auto self = shared_from_this();
    ErrorCode ec = m_tcp.ConnectAsync(req.host, req.port,
        [self](ErrorCode connect_ec) {
            self->OnTcpConnected(connect_ec);
        });

    if (ec != ErrorCode::Success) {
        auto reply = Socks5::BuildConnectReply(Socks5::ErrorCodeToSocks5Reply(ec));
        m_channel->Write(reply.data(), reply.size());
        Close();
    }
}

void Socks5Session::OnTcpConnected(ErrorCode ec) {
    if (ec != ErrorCode::Success) {
        Logger::Warn("SOCKS5: target TCP connect failed: %s", ErrorCodeToString(ec));
        auto reply = Socks5::BuildConnectReply(Socks5::ErrorCodeToSocks5Reply(ec));
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    // Send success reply
    auto reply = Socks5::BuildConnectReply(Socks5::REP_SUCCESS);
    m_channel->Write(reply.data(), reply.size());

    m_state = State::Relaying;
    StartRelay();
}

void Socks5Session::StartRelay() {
    auto self = shared_from_this();

    // Target → SSH channel (IOCP thread → channel write queue)
    m_tcp.StartReading(
        [self](const uint8_t* data, size_t len) {
            // Data from target: write to SSH channel
            self->m_channel->Write(data, len);
        },
        [self](ErrorCode) {
            self->m_channel->SendEof();
            self->Close();
        });

    // SSH channel → target (run on calling/I/O thread, loop until EOF)
    for (;;) {
        if (m_channel->IsEof()) break;
        uint8_t buf[4096];
        size_t bytes_read = 0;
        ErrorCode ec = m_channel->Read(buf, sizeof(buf), bytes_read);
        if (ec != ErrorCode::Success || bytes_read == 0) break;
        m_tcp.Send(buf, bytes_read);
    }

    Close();
}

void Socks5Session::Close() {
    if (m_state == State::Closed) return;
    m_state = State::Closed;
    m_tcp.Close();
    if (m_channel) {
        m_channel->SendEof();
        m_channel->Close();
    }
    Logger::Debug("SOCKS5 session closed");
}
