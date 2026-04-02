#pragma once
#include "common.h"
#include "ssh_channel.h"
#include "tcp_connection.h"
#include "socks5_handler.h"
#include <atomic>
#include <memory>
#include <vector>

// Socks5Session manages one forwarded-tcpip channel end-to-end:
//   SOCKS5 handshake (over IChannel) → async TCP connect → bidirectional relay.
//
// Lifetime: created on the SSH I/O thread when a channel is accepted;
// destroyed when both sides have closed.
class Socks5Session : public std::enable_shared_from_this<Socks5Session> {
public:
    explicit Socks5Session(std::unique_ptr<IChannel> channel);
    ~Socks5Session();

    Socks5Session(const Socks5Session&) = delete;
    Socks5Session& operator=(const Socks5Session&) = delete;

    // Called on the SSH I/O thread once the session is set up.
    // Currently a no-op: the full lifecycle (handshake through relay) is driven
    // non-blocking by PumpSshRead(). Kept for call-site clarity.
    void Start();

    // Called by the SSH I/O thread on every loop iteration.
    // Drives the full session lifecycle: SOCKS5 handshake (ReadingMethods /
    // ReadingRequest) and bidirectional relay (Relaying) without blocking.
    // Returns false when the session is done (pump will be deregistered).
    bool PumpSshRead();

private:
    // State machine transitions:
    //
    //   ReadingMethods → ReadingRequest → Connecting → Relaying → Closed
    //                                                              ↑
    //                       error or EOF at any phase ────────────┘
    enum class State {
        ReadingMethods,
        ReadingRequest,
        Connecting,
        Relaying,
        Closed,
    };

    void OnChannelData(const uint8_t* data, size_t len);

    void HandleMethodNegotiation(const uint8_t* data, size_t len);
    void HandleConnectRequest(const uint8_t* data, size_t len);
    void StartTcpConnect(const Socks5::ConnectRequest& req);
    void OnTcpConnected(ErrorCode ec);
    void StartRelay();
    void Close();

    std::unique_ptr<IChannel>           m_channel;
    std::shared_ptr<TcpConnection>      m_tcp;
    std::atomic<State>         m_state{State::ReadingMethods};
    std::vector<uint8_t>       m_inbound_buf;   // data from SSH channel
};
