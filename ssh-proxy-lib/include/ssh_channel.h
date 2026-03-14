#pragma once
#include "common.h"
#include <atomic>
#include <functional>
#include <vector>

// IChannel — testability interface for Socks5Session.
// Unit tests inject a fake implementation without requiring a live SSH connection.
class IChannel {
public:
    virtual ~IChannel() = default;

    // Read up to len bytes into buf. Sets bytes_read.
    // Returns WouldBlock if no data is available yet (non-blocking mode).
    virtual ErrorCode Read(uint8_t* buf, size_t len, size_t& bytes_read) = 0;

    // Write exactly len bytes. Thread-safe: when called from a non-I/O thread
    // the write is queued for the SSH I/O thread to drain.
    virtual ErrorCode Write(const uint8_t* buf, size_t len) = 0;

    // Signal EOF on the write side (half-close). Thread-safe.
    virtual void SendEof() = 0;

    // Close the channel. Thread-safe.
    virtual void Close() = 0;

    // True if the remote side has sent EOF.
    virtual bool IsEof() const = 0;
};

// Concrete implementation wrapping a LIBSSH2_CHANNEL*.
//
// libssh2 is not thread-safe. Read/IsEof must only be called on the SSH I/O
// thread. Write/SendEof/Close are thread-safe: when a PostWriteFn / PostIoFn
// is provided (set by SshTransport when accepting a channel), calls arriving
// from IOCP worker threads are marshalled back to the I/O thread via queues
// instead of touching libssh2 directly.
class SshChannel : public IChannel {
public:
    // Posts write data to the SSH I/O thread's per-channel queue.
    using PostWriteFn  = std::function<void(std::vector<uint8_t>)>;
    // Posts an arbitrary callback to run on the SSH I/O thread.
    using PostIoFn     = std::function<void(std::function<void()>)>;
    // Called synchronously at the start of Close(), before channel_free is posted.
    // Used by SshTransport to remove the channel from the write queue while it is
    // still valid, preventing DrainWriteQueues from writing to a freed channel.
    using PreCloseFn   = std::function<void(LIBSSH2_CHANNEL*)>;

    explicit SshChannel(LIBSSH2_CHANNEL* ch,
                        PostWriteFn post_write = {},
                        PostIoFn    post_io    = {},
                        PreCloseFn  pre_close  = {});
    ~SshChannel() override { Close(); }

    SshChannel(const SshChannel&) = delete;
    SshChannel& operator=(const SshChannel&) = delete;

    ErrorCode Read(uint8_t* buf, size_t len, size_t& bytes_read) override;
    ErrorCode Write(const uint8_t* buf, size_t len) override;
    void SendEof() override;
    void Close() override;
    bool IsEof() const override;

private:
    std::atomic<LIBSSH2_CHANNEL*> m_channel;
    PostWriteFn                   m_post_write;
    PostIoFn                      m_post_io;
    PreCloseFn                    m_pre_close;
};
