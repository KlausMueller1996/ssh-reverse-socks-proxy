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
    // Called on every I/O thread loop iteration. Returns false when done
    // (automatically removed from the pump list).
    using SessionPumpFn     = std::function<bool()>;

    // Fires on the SSH I/O thread for each inbound forwarded-tcpip channel.
    // The returned SessionPumpFn (if non-null) is auto-registered as a per-iteration
    // pump — callers do not need to call RegisterSessionPump separately.
    using OnChannelAccepted = std::function<SessionPumpFn(std::unique_ptr<SshChannel>)>;

    // Fires on the SSH I/O thread when the session drops.
    using OnDisconnected    = std::function<void(ErrorCode)>;

    SshTransport();
    ~SshTransport();

    SshTransport(const SshTransport&) = delete;
    SshTransport& operator=(const SshTransport&) = delete;

    // Blocking: TCP connect + SSH handshake + password auth + tcpip-forward request.
    // Returns Result::ok() on success; on failure Result::what() carries the reason.
    // Must be called before StartAccepting().
    Result Connect(const std::string& host, uint16_t port,
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

private:
    void IoThreadProc(OnChannelAccepted on_channel, OnDisconnected on_disconnect);
    void DrainWriteQueues();
    void DrainIoCallbacks();
    void PumpSessions();

    // Post data to a channel's write queue (thread-safe — called from IOCP threads).
    void PostChannelWrite(LIBSSH2_CHANNEL* ch, std::vector<uint8_t> data);

    // Remove a channel's write queue entry (thread-safe).
    void RemoveChannelWriteQueue(LIBSSH2_CHANNEL* ch);

    // Post a callback to run on the SSH I/O thread. Thread-safe.
    void PostToIoThread(std::function<void()> fn);

    // Register a pump to be called on every I/O thread loop iteration.
    // MUST be called on the SSH I/O thread.
    void RegisterSessionPump(SessionPumpFn fn);

    // SSH resources — declared in this order so m_listener is destroyed before
    // m_session (C++ destroys members in reverse declaration order).
    WinSocket         m_socket;
    SshSessionPtr     m_session;
    SshListenerPtr    m_listener;

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

    // Session pumps: driven by I/O thread each loop iteration (I/O thread only).
    std::vector<SessionPumpFn>   m_session_pumps;

    // Callbacks posted from IOCP threads to run on the I/O thread.
    std::mutex                           m_io_callbacks_mutex;
    std::vector<std::function<void()>>   m_io_callbacks;
};
