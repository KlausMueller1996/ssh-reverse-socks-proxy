#pragma once
#include "common.h"
#include "ssh_channel.h"
#include "tcp_connection.h"
#include "socks5_handler.h"
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

    // Begin the SOCKS5 handshake. Must be called on the SSH I/O thread.
    // The session manages its own lifetime via shared_ptr once started.
    void Start();

private:
    enum class State {
        ReadingMethods,
        ReadingRequest,
        Connecting,
        Relaying,
        Closed,
    };

    // Called on the SSH I/O thread to read from the SSH channel.
    void ReadFromChannel();
    void OnChannelData(const uint8_t* data, size_t len);

    void HandleMethodNegotiation(const uint8_t* data, size_t len);
    void HandleConnectRequest(const uint8_t* data, size_t len);
    void StartTcpConnect(const Socks5::ConnectRequest& req);
    void OnTcpConnected(ErrorCode ec);
    void StartRelay();
    void Close();

    std::unique_ptr<IChannel> m_channel;
    TcpConnection             m_tcp;
    State                     m_state = State::ReadingMethods;
    std::vector<uint8_t>      m_inbound_buf;   // data from SSH channel
};
