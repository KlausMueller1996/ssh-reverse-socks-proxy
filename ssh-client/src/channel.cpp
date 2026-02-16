#include "channel.h"
#include "mux_session.h"
#include "logger.h"

Channel::Channel(uint16_t id, MuxSession* session, uint32_t window_size)
    : m_id(id)
    , m_session(session)
    , m_state(ChannelState::Opening)
    , m_method_done(false)
    , m_send_window(window_size)
    , m_recv_window(window_size)
    , m_recv_window_initial(window_size)
    , m_recv_consumed(0)
{
}

Channel::~Channel() {
    ForceClose();
}

void Channel::OnOpen() {
    Logger::Debug("Channel %u: opened", m_id);
    m_state = ChannelState::Opening;
    // Send open ACK
    m_session->SendChannelOpenAck(m_id);
    m_state = ChannelState::Requesting;
}

void Channel::OnRequest(const uint8_t* data, size_t len) {
    if (m_state != ChannelState::Requesting) {
        Logger::Warn("Channel %u: OnRequest in wrong state %d", m_id, static_cast<int>(m_state));
        return;
    }

    // Accumulate SOCKS5 data
    m_socks5_buf.insert(m_socks5_buf.end(), data, data + len);
    ProcessSocks5();
}

void Channel::ProcessSocks5() {
    const uint8_t* buf = m_socks5_buf.data();
    size_t len = m_socks5_buf.size();

    if (!m_method_done) {
        // Parse method selection
        bool supports_no_auth = false;
        int consumed = Socks5::ParseMethodRequest(buf, len, supports_no_auth);
        if (consumed == 0) return; // need more data
        if (consumed < 0 || !supports_no_auth) {
            Logger::Warn("Channel %u: SOCKS5 auth negotiation failed", m_id);
            ByteBuffer resp = Socks5::BuildMethodResponse(Socks5::AUTH_NO_ACCEPTABLE);
            m_session->SendChannelRequestAck(m_id, resp.data(), static_cast<uint32_t>(resp.size()));
            SendCloseToMux(FRAME_FLAG_RST);
            m_state = ChannelState::Closed;
            return;
        }

        // Send method response (no auth)
        ByteBuffer resp = Socks5::BuildMethodResponse(Socks5::AUTH_NONE);
        m_session->SendChannelRequestAck(m_id, resp.data(), static_cast<uint32_t>(resp.size()));

        // Remove consumed bytes
        m_socks5_buf.erase(m_socks5_buf.begin(), m_socks5_buf.begin() + consumed);
        m_method_done = true;
    }

    // Parse connect request
    buf = m_socks5_buf.data();
    len = m_socks5_buf.size();
    if (len == 0) return;

    int consumed = Socks5::ParseConnectRequest(buf, len, m_connect_req);
    if (consumed == 0) return; // need more data
    if (consumed < 0) {
        Logger::Warn("Channel %u: malformed SOCKS5 connect request", m_id);
        ByteBuffer reply = Socks5::BuildConnectReply(Socks5::REP_GENERAL_FAILURE);
        m_session->SendChannelRequestAck(m_id, reply.data(), static_cast<uint32_t>(reply.size()));
        SendCloseToMux(FRAME_FLAG_RST);
        m_state = ChannelState::Closed;
        return;
    }

    m_socks5_buf.erase(m_socks5_buf.begin(), m_socks5_buf.begin() + consumed);

    Logger::Info("Channel %u: CONNECT %s:%u", m_id, m_connect_req.host.c_str(), m_connect_req.port);

    // Start async TCP connect to target
    m_state = ChannelState::Connecting;
    m_target = std::make_unique<TcpConnection>();

    ErrorCode ec = m_target->ConnectAsync(m_connect_req.host, m_connect_req.port,
        [this](ErrorCode ec2) { OnTargetConnected(ec2); });

    if (ec != ErrorCode::Success) {
        // DNS failure or socket creation error — immediate failure
        OnTargetConnected(ec);
    }
}

void Channel::OnTargetConnected(ErrorCode ec) {
    if (m_state != ChannelState::Connecting) return;

    if (ec != ErrorCode::Success) {
        Logger::Warn("Channel %u: target connect failed: %s", m_id, ErrorCodeToString(ec));
        uint8_t reply_code = Socks5::ErrorCodeToSocks5Reply(ec);
        ByteBuffer reply = Socks5::BuildConnectReply(reply_code);
        m_session->SendChannelRequestAck(m_id, reply.data(), static_cast<uint32_t>(reply.size()));
        SendCloseToMux(FRAME_FLAG_RST);
        m_state = ChannelState::Closed;
        m_target.reset();
        return;
    }

    // Send success reply
    ByteBuffer reply = Socks5::BuildConnectReply(Socks5::REP_SUCCESS);
    m_session->SendChannelRequestAck(m_id, reply.data(), static_cast<uint32_t>(reply.size()));

    m_state = ChannelState::Relaying;
    Logger::Debug("Channel %u: relay started", m_id);

    // Start reading from target
    m_target->StartReading(
        [this](const uint8_t* data, size_t len) { OnTargetData(data, len); },
        [this](ErrorCode ec2) { OnTargetDisconnected(ec2); }
    );
}

void Channel::OnData(const uint8_t* data, size_t len) {
    if (m_state != ChannelState::Relaying) {
        Logger::Debug("Channel %u: DATA in state %d, dropping", m_id, static_cast<int>(m_state));
        return;
    }

    // Track receive window
    m_recv_consumed += static_cast<uint32_t>(len);

    // Forward to target
    if (m_target) {
        m_target->Send(data, len);
    }

    // Replenish window if half consumed
    if (m_recv_consumed >= m_recv_window_initial / 2) {
        m_session->SendWindowUpdate(m_id, m_recv_consumed);
        m_recv_window += m_recv_consumed;
        m_recv_consumed = 0;
    }
}

void Channel::OnWindowUpdate(uint32_t increment) {
    m_send_window += increment;
    Logger::Debug("Channel %u: window update +%u (now %u)", m_id, increment, m_send_window);
}

void Channel::OnClose(uint8_t flags) {
    Logger::Debug("Channel %u: close received (flags=0x%02X)", m_id, flags);

    // Send close ACK
    m_session->SendChannelCloseAck(m_id);

    // Tear down target
    if (m_target) {
        m_target->Close();
        m_target.reset();
    }

    m_state = ChannelState::Closed;
}

void Channel::OnTargetData(const uint8_t* data, size_t len) {
    if (m_state != ChannelState::Relaying) return;

    SendToMux(data, len);
}

void Channel::OnTargetDisconnected(ErrorCode ec) {
    Logger::Debug("Channel %u: target disconnected: %s", m_id, ErrorCodeToString(ec));

    if (m_state == ChannelState::Relaying || m_state == ChannelState::Connecting) {
        SendCloseToMux(FRAME_FLAG_FIN);
        m_state = ChannelState::Closing;
    }

    if (m_target) {
        m_target->Close();
    }
}

void Channel::SendToMux(const uint8_t* data, size_t len) {
    // Chunk to respect send window and max frame payload
    size_t offset = 0;
    while (offset < len) {
        uint32_t chunk = static_cast<uint32_t>((std::min)(len - offset, static_cast<size_t>(FRAME_MAX_PAYLOAD)));
        if (m_send_window > 0) {
            chunk = (std::min)(chunk, m_send_window);
            m_send_window -= chunk;
        }
        m_session->SendData(m_id, data + offset, chunk);
        offset += chunk;
    }
}

void Channel::SendCloseToMux(uint8_t flags) {
    m_session->SendChannelClose(m_id, flags);
}

void Channel::ForceClose() {
    if (m_state == ChannelState::Closed) return;

    if (m_target) {
        m_target->Close();
        m_target.reset();
    }
    m_state = ChannelState::Closed;
}
