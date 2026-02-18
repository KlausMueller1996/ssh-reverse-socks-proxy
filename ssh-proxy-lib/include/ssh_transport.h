#pragma once
#include "common.h"
#include "ssh_channel.h"
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <deque>
#include <vector>

// SshTransport owns the full SSH connection lifecycle:
//   TCP connect → SSH handshake → auth → tcpip-forward request → channel-accept loop.
// All libssh2 calls happen on an internal I/O thread; this class is not thread-safe
// for concurrent Connect/Close calls — use from a single controlling thread.
class SshTransport {
public:
    // Fires on the SSH I/O thread for each inbound forwarded-tcpip channel.
    using OnChannelAccepted = std::function<void(std::unique_ptr<SshChannel>)>;
    // Fires on the SSH I/O thread when the session drops.
    using OnDisconnected    = std::function<void(ErrorCode)>;

    SshTransport();
    ~SshTransport();

    SshTransport(const SshTransport&) = delete;
    SshTransport& operator=(const SshTransport&) = delete;

    // Blocking: TCP connect + SSH handshake + password auth + tcpip-forward request.
    // Returns ErrorCode::Success or a relevant error.
    // Must be called before StartAccepting().
    ErrorCode Connect(const std::string& host, uint16_t port,
                      const std::string& username, const std::string& password,
                      uint16_t forward_port, uint32_t timeout_ms,
                      uint32_t keepalive_interval_ms);

    // Spawns the I/O thread. on_channel fires for each accepted forwarded-tcpip
    // channel; on_disconnect fires once when the session drops.
    // Must only be called after a successful Connect().
    void StartAccepting(OnChannelAccepted on_channel, OnDisconnected on_disconnect);

    // Signals the I/O thread to stop and waits for it to exit.
    // Closes the libssh2 session and the TCP socket.
    void Close();

    bool IsConnected() const;

    // Post data to a channel's write queue (thread-safe — called from IOCP threads).
    // The I/O thread drains all queues in its select loop.
    void PostChannelWrite(LIBSSH2_CHANNEL* ch, std::vector<uint8_t> data);

private:
    void IoThreadProc(OnChannelAccepted on_channel, OnDisconnected on_disconnect);
    void DrainWriteQueues();

    SOCKET            m_socket  = INVALID_SOCKET;
    LIBSSH2_SESSION*  m_session = nullptr;
    LIBSSH2_LISTENER* m_listener = nullptr;

    std::thread       m_io_thread;
    std::atomic<bool> m_cancel{false};
    std::atomic<bool> m_connected{false};

    // Per-channel write queues: channel ptr → pending buffers
    struct ChannelQueue {
        LIBSSH2_CHANNEL*          channel;
        std::deque<std::vector<uint8_t>> pending;
    };
    std::mutex                   m_queues_mutex;
    std::vector<ChannelQueue>    m_write_queues;
};
