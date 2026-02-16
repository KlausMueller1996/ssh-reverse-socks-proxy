#include "mux_session.h"
#include "channel.h"
#include "logger.h"

MuxSession::MuxSession(SslTransport* transport, uint32_t channel_window_size, int keepalive_ms)
    : m_transport(transport)
    , m_channel_window_size(channel_window_size)
    , m_keepalive_ms(keepalive_ms)
    , m_running(false)
    , m_keepalive_timer(nullptr)
{
    InitializeSRWLock(&m_channels_lock);
}

MuxSession::~MuxSession() {
    Shutdown();
}

void MuxSession::Start(OnDisconnected on_disconnect) {
    m_on_disconnect = std::move(on_disconnect);
    m_running = true;

    m_transport->StartReading(
        [this](const uint8_t* data, size_t len) { OnDataReceived(data, len); },
        [this](ErrorCode ec) { OnTransportDisconnected(ec); }
    );

    StartKeepaliveTimer();
    Logger::Info("MuxSession started");
}

void MuxSession::Shutdown() {
    if (!m_running) return;
    m_running = false;

    StopKeepaliveTimer();
    CloseAllChannels();
    Logger::Info("MuxSession shut down (%zu channels cleaned)",
        static_cast<size_t>(0)); // channels already cleared
}

void MuxSession::OnDataReceived(const uint8_t* data, size_t len) {
    std::vector<Frame> frames;
    m_codec.Feed(data, len, frames);

    for (const auto& frame : frames) {
        DispatchFrame(frame);
    }
}

void MuxSession::OnTransportDisconnected(ErrorCode ec) {
    Logger::Warn("Transport disconnected: %s", ErrorCodeToString(ec));
    m_running = false;
    StopKeepaliveTimer();
    CloseAllChannels();
    if (m_on_disconnect) m_on_disconnect(ec);
}

void MuxSession::DispatchFrame(const Frame& frame) {
    FrameType ft = static_cast<FrameType>(frame.header.type);

    switch (ft) {
    case FrameType::ChannelOpen:      HandleChannelOpen(frame);    break;
    case FrameType::ChannelRequest:   HandleChannelRequest(frame); break;
    case FrameType::Data:             HandleData(frame);           break;
    case FrameType::ChannelClose:     HandleChannelClose(frame);   break;
    case FrameType::ChannelCloseAck:  HandleChannelCloseAck(frame); break;
    case FrameType::Ping:             HandlePing(frame);           break;
    case FrameType::WindowUpdate:     HandleWindowUpdate(frame);   break;
    default:
        Logger::Warn("Unknown frame type: 0x%02X", frame.header.type);
        break;
    }
}

void MuxSession::HandleChannelOpen(const Frame& frame) {
    uint16_t id = frame.header.channel_id;
    Logger::Debug("ChannelOpen for channel %u", id);

    auto ch = std::make_unique<Channel>(id, this, m_channel_window_size);

    AcquireSRWLockExclusive(&m_channels_lock);
    m_channels[id] = std::move(ch);
    Channel* ptr = m_channels[id].get();
    ReleaseSRWLockExclusive(&m_channels_lock);

    ptr->OnOpen();
}

void MuxSession::HandleChannelRequest(const Frame& frame) {
    Channel* ch = FindChannel(frame.header.channel_id);
    if (!ch) {
        Logger::Warn("ChannelRequest for unknown channel %u", frame.header.channel_id);
        return;
    }
    ch->OnRequest(frame.payload.data(), frame.payload.size());
}

void MuxSession::HandleData(const Frame& frame) {
    Channel* ch = FindChannel(frame.header.channel_id);
    if (!ch) {
        Logger::Debug("Data for unknown channel %u", frame.header.channel_id);
        return;
    }
    ch->OnData(frame.payload.data(), frame.payload.size());
}

void MuxSession::HandleChannelClose(const Frame& frame) {
    Channel* ch = FindChannel(frame.header.channel_id);
    if (!ch) {
        // Already gone — send ACK anyway
        SendChannelCloseAck(frame.header.channel_id);
        return;
    }
    ch->OnClose(frame.header.flags);

    // Remove if fully closed
    if (ch->GetState() == ChannelState::Closed) {
        RemoveChannel(frame.header.channel_id);
    }
}

void MuxSession::HandleChannelCloseAck(const Frame& frame) {
    Channel* ch = FindChannel(frame.header.channel_id);
    if (ch) {
        ch->ForceClose();
        RemoveChannel(frame.header.channel_id);
    }
}

void MuxSession::HandlePing(const Frame& /*frame*/) {
    Logger::Debug("Ping received, sending Pong");
    ByteBuffer pong = FrameCodec::BuildPong();
    SendFrame(pong);
}

void MuxSession::HandleWindowUpdate(const Frame& frame) {
    if (frame.payload.size() < 4) {
        Logger::Warn("WindowUpdate with insufficient payload");
        return;
    }
    uint32_t increment = 0;
    memcpy(&increment, frame.payload.data(), 4);

    Channel* ch = FindChannel(frame.header.channel_id);
    if (ch) {
        ch->OnWindowUpdate(increment);
    }
}

// --- Send helpers ---

void MuxSession::SendChannelOpenAck(uint16_t channel_id) {
    SendFrame(FrameCodec::BuildChannelOpenAck(channel_id));
}

void MuxSession::SendChannelRequestAck(uint16_t channel_id, const uint8_t* data, uint32_t len) {
    SendFrame(FrameCodec::BuildChannelRequestAck(channel_id, data, len));
}

void MuxSession::SendData(uint16_t channel_id, const uint8_t* data, uint32_t len) {
    SendFrame(FrameCodec::BuildData(channel_id, data, len));
}

void MuxSession::SendChannelClose(uint16_t channel_id, uint8_t flags) {
    SendFrame(FrameCodec::BuildChannelClose(channel_id, flags));
}

void MuxSession::SendChannelCloseAck(uint16_t channel_id) {
    SendFrame(FrameCodec::BuildChannelCloseAck(channel_id));
}

void MuxSession::SendWindowUpdate(uint16_t channel_id, uint32_t increment) {
    SendFrame(FrameCodec::BuildWindowUpdate(channel_id, increment));
}

void MuxSession::SendFrame(const ByteBuffer& frame_bytes) {
    if (!m_running || !m_transport) return;
    m_transport->Send(frame_bytes.data(), frame_bytes.size());
}

// --- Channel registry ---

Channel* MuxSession::FindChannel(uint16_t id) {
    AcquireSRWLockShared(&m_channels_lock);
    auto it = m_channels.find(id);
    Channel* ch = (it != m_channels.end()) ? it->second.get() : nullptr;
    ReleaseSRWLockShared(&m_channels_lock);
    return ch;
}

void MuxSession::RemoveChannel(uint16_t id) {
    AcquireSRWLockExclusive(&m_channels_lock);
    auto it = m_channels.find(id);
    if (it != m_channels.end()) {
        Logger::Debug("Removing channel %u", id);
        m_channels.erase(it);
    }
    ReleaseSRWLockExclusive(&m_channels_lock);
}

void MuxSession::CloseAllChannels() {
    AcquireSRWLockExclusive(&m_channels_lock);
    for (auto& pair : m_channels) {
        pair.second->ForceClose();
    }
    size_t count = m_channels.size();
    m_channels.clear();
    ReleaseSRWLockExclusive(&m_channels_lock);

    if (count > 0) {
        Logger::Info("Closed all %zu channels", count);
    }
}

// --- Keepalive timer ---

void CALLBACK MuxSession::KeepaliveTimerCallback(PVOID param, BOOLEAN /*timer_fired*/) {
    auto* self = static_cast<MuxSession*>(param);
    if (self->m_running) {
        Logger::Debug("Sending keepalive ping");
        ByteBuffer ping = FrameCodec::BuildPing();
        self->SendFrame(ping);
    }
}

void MuxSession::StartKeepaliveTimer() {
    if (m_keepalive_ms <= 0) return;

    CreateTimerQueueTimer(&m_keepalive_timer, nullptr,
        KeepaliveTimerCallback, this,
        static_cast<DWORD>(m_keepalive_ms),
        static_cast<DWORD>(m_keepalive_ms),
        WT_EXECUTEDEFAULT);

    Logger::Debug("Keepalive timer started (%d ms)", m_keepalive_ms);
}

void MuxSession::StopKeepaliveTimer() {
    if (m_keepalive_timer) {
        DeleteTimerQueueTimer(nullptr, m_keepalive_timer, INVALID_HANDLE_VALUE);
        m_keepalive_timer = nullptr;
    }
}
