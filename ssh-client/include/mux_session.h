#pragma once
#include "common.h"
#include "mux_protocol.h"
#include "ssl_transport.h"
#include <unordered_map>
#include <memory>

class Channel;

class MuxSession {
public:
    using OnDisconnected = std::function<void(ErrorCode)>;

    MuxSession(SslTransport* transport, uint32_t channel_window_size, int keepalive_ms);
    ~MuxSession();

    MuxSession(const MuxSession&) = delete;
    MuxSession& operator=(const MuxSession&) = delete;

    // Start processing: hooks into transport callbacks.
    void Start(OnDisconnected on_disconnect);

    // Tear down all channels and stop processing.
    void Shutdown();

    // Send helpers — called by Channel instances
    void SendChannelOpenAck(uint16_t channel_id);
    void SendChannelRequestAck(uint16_t channel_id, const uint8_t* data, uint32_t len);
    void SendData(uint16_t channel_id, const uint8_t* data, uint32_t len);
    void SendChannelClose(uint16_t channel_id, uint8_t flags);
    void SendChannelCloseAck(uint16_t channel_id);
    void SendWindowUpdate(uint16_t channel_id, uint32_t increment);

private:
    void OnDataReceived(const uint8_t* data, size_t len);
    void OnTransportDisconnected(ErrorCode ec);
    void DispatchFrame(const Frame& frame);

    void HandleChannelOpen(const Frame& frame);
    void HandleChannelRequest(const Frame& frame);
    void HandleData(const Frame& frame);
    void HandleChannelClose(const Frame& frame);
    void HandleChannelCloseAck(const Frame& frame);
    void HandlePing(const Frame& frame);
    void HandleWindowUpdate(const Frame& frame);

    void SendFrame(const ByteBuffer& frame_bytes);

    Channel* FindChannel(uint16_t id);
    void RemoveChannel(uint16_t id);
    void CloseAllChannels();

    // Keepalive timer
    static void CALLBACK KeepaliveTimerCallback(PVOID param, BOOLEAN timer_fired);
    void StartKeepaliveTimer();
    void StopKeepaliveTimer();

    SslTransport*       m_transport;
    uint32_t            m_channel_window_size;
    int                 m_keepalive_ms;

    FrameCodec          m_codec;

    // Channel registry protected by SRWLOCK
    SRWLOCK             m_channels_lock;
    std::unordered_map<uint16_t, std::unique_ptr<Channel>> m_channels;

    OnDisconnected      m_on_disconnect;
    bool                m_running;

    HANDLE              m_keepalive_timer;
};
