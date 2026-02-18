#pragma once
#include "common.h"

// IChannel — testability interface for Socks5Session.
// Unit tests inject a fake implementation without requiring a live SSH connection.
class IChannel {
public:
    virtual ~IChannel() = default;

    // Read up to len bytes into buf. Sets bytes_read. Blocks until data is
    // available, EOF, or error.
    virtual ErrorCode Read(uint8_t* buf, size_t len, size_t& bytes_read) = 0;

    // Write exactly len bytes. Blocks until fully written or error.
    virtual ErrorCode Write(const uint8_t* buf, size_t len) = 0;

    // Signal EOF on the write side (half-close).
    virtual void SendEof() = 0;

    // Close the channel.
    virtual void Close() = 0;

    // True if the remote side has sent EOF.
    virtual bool IsEof() const = 0;
};

// Concrete implementation wrapping a LIBSSH2_CHANNEL*.
// All calls must be made on the SSH I/O thread (libssh2 is not thread-safe).
class SshChannel : public IChannel {
public:
    explicit SshChannel(LIBSSH2_CHANNEL* ch) : m_channel(ch) {}
    ~SshChannel() override { Close(); }

    SshChannel(const SshChannel&) = delete;
    SshChannel& operator=(const SshChannel&) = delete;

    ErrorCode Read(uint8_t* buf, size_t len, size_t& bytes_read) override;
    ErrorCode Write(const uint8_t* buf, size_t len) override;
    void SendEof() override;
    void Close() override;
    bool IsEof() const override;

private:
    LIBSSH2_CHANNEL* m_channel;
};
