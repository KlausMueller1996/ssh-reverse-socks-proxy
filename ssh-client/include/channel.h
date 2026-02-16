#pragma once
#include "common.h"
#include "mux_protocol.h"
#include "socks5_handler.h"
#include "tcp_connection.h"
#include <memory>

class MuxSession; // forward

enum class ChannelState : uint8_t {
    Opening,     // CHANNEL_OPEN received, sending ACK
    Requesting,  // Waiting for SOCKS5 handshake + connect request
    Connecting,  // Async TCP connect in progress to target
    Relaying,    // Bidirectional data relay
    Closing,     // FIN sent or received, draining
    Closed,      // Terminal
};

class Channel {
public:
    Channel(uint16_t id, MuxSession* session, uint32_t window_size);
    ~Channel();

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    uint16_t GetId() const { return m_id; }
    ChannelState GetState() const { return m_state; }

    // Events from MuxSession (mux side)
    void OnOpen();
    void OnRequest(const uint8_t* data, size_t len);
    void OnData(const uint8_t* data, size_t len);
    void OnWindowUpdate(uint32_t increment);
    void OnClose(uint8_t flags);

    // Tear down everything immediately
    void ForceClose();

private:
    // SOCKS5 handshake processing
    void ProcessSocks5();

    // Target-side event handlers
    void OnTargetConnected(ErrorCode ec);
    void OnTargetData(const uint8_t* data, size_t len);
    void OnTargetDisconnected(ErrorCode ec);

    // Send data back through the mux
    void SendToMux(const uint8_t* data, size_t len);
    void SendCloseToMux(uint8_t flags = 0);

    uint16_t                      m_id;
    MuxSession*                   m_session;
    ChannelState                  m_state;

    // SOCKS5 handshake buffer
    ByteBuffer                    m_socks5_buf;
    bool                          m_method_done;
    Socks5::ConnectRequest        m_connect_req;

    // Target TCP connection
    std::unique_ptr<TcpConnection> m_target;

    // Flow control: send window (how much we can send to server)
    uint32_t                      m_send_window;
    // Flow control: recv window (how much server can send to us)
    uint32_t                      m_recv_window;
    uint32_t                      m_recv_window_initial;
    uint32_t                      m_recv_consumed;
};
