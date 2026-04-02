#pragma once

// Windows headers — order matters
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <libssh2.h>

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <algorithm>
#include <stdexcept>

// Shared type alias
using ByteBuffer = std::vector<uint8_t>;

// Error codes used throughout the library (no exceptions in internal code)
enum class ErrorCode : int {
    Success = 0,
    InvalidArgument,
    OutOfMemory,
    SocketError,
    ConnectionReset,
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable,
    NetworkUnreachable,
    DnsResolutionFailed,
    SshHandshakeFailed,
    SshAuthFailed,
    SshChannelOpenFailed,
    ProtocolError,
    BufferTooSmall,
    ChannelClosed,
    Socks5AuthFailure,
    Socks5UnsupportedCommand,
    Socks5UnsupportedAddressType,
    Shutdown,
    IoIncomplete,
    WouldBlock,
};

inline const char* ErrorCodeToString(ErrorCode ec) {
    switch (ec) {
    case ErrorCode::Success:                      return "Success";
    case ErrorCode::InvalidArgument:              return "InvalidArgument";
    case ErrorCode::OutOfMemory:                  return "OutOfMemory";
    case ErrorCode::SocketError:                  return "SocketError";
    case ErrorCode::ConnectionReset:              return "ConnectionReset";
    case ErrorCode::ConnectionRefused:            return "ConnectionRefused";
    case ErrorCode::ConnectionTimeout:            return "ConnectionTimeout";
    case ErrorCode::HostUnreachable:              return "HostUnreachable";
    case ErrorCode::NetworkUnreachable:           return "NetworkUnreachable";
    case ErrorCode::DnsResolutionFailed:          return "DnsResolutionFailed";
    case ErrorCode::SshHandshakeFailed:           return "SshHandshakeFailed";
    case ErrorCode::SshAuthFailed:                return "SshAuthFailed";
    case ErrorCode::SshChannelOpenFailed:         return "SshChannelOpenFailed";
    case ErrorCode::ProtocolError:                return "ProtocolError";
    case ErrorCode::BufferTooSmall:               return "BufferTooSmall";
    case ErrorCode::ChannelClosed:                return "ChannelClosed";
    case ErrorCode::Socks5AuthFailure:            return "Socks5AuthFailure";
    case ErrorCode::Socks5UnsupportedCommand:     return "Socks5UnsupportedCommand";
    case ErrorCode::Socks5UnsupportedAddressType: return "Socks5UnsupportedAddressType";
    case ErrorCode::Shutdown:                     return "Shutdown";
    case ErrorCode::IoIncomplete:                 return "IoIncomplete";
    case ErrorCode::WouldBlock:                   return "WouldBlock";
    }
    return "Unknown";
}

// Convert a WinSock error to ErrorCode
inline ErrorCode WsaToErrorCode(int wsa_error) {
    switch (wsa_error) {
    case 0:              return ErrorCode::Success;
    case WSAECONNRESET:  return ErrorCode::ConnectionReset;
    case WSAECONNREFUSED:return ErrorCode::ConnectionRefused;
    case WSAETIMEDOUT:   return ErrorCode::ConnectionTimeout;
    case WSAEHOSTUNREACH:return ErrorCode::HostUnreachable;
    case WSAENETUNREACH: return ErrorCode::NetworkUnreachable;
    default:             return ErrorCode::SocketError;
    }
}

// A result type that pairs an ErrorCode with an optional diagnostic message.
// Used by setup functions that cannot throw but need to propagate a human-readable
// reason alongside the category code.  Callers check ok() and read what() for display.
struct Result {
    ErrorCode   code    = ErrorCode::Success;
    std::string message;

    Result() = default;                                           // success
    explicit Result(ErrorCode c) : code(c) {}                    // code only
    Result(ErrorCode c, std::string msg)
        : code(c), message(std::move(msg)) {}

    bool ok() const { return code == ErrorCode::Success; }

    // Returns the diagnostic message if one was set, otherwise the enum name.
    const char* what() const {
        return message.empty() ? ErrorCodeToString(code) : message.c_str();
    }
};

// ── RAII handles ──────────────────────────────────────────────────────────────
// Used as local guards in setup functions (constructors / Connect).
// On success, call .release() to hand ownership to the owning member.
// On any early return or throw, the destructor fires automatically —
// no per-branch cleanup code required.

// LIBSSH2_SESSION* — set_blocking(1) → [optional disconnect] → free.
// send_disconnect defaults to false so that the deleter is safe to use
// before the handshake completes (no SSH transport to send over yet).
// Set ptr.get_deleter().send_disconnect = true after libssh2_session_handshake
// succeeds, so that subsequent cleanup sends a clean SSH_MSG_DISCONNECT.
struct SshSessionDeleter {
    bool send_disconnect = false;
    void operator()(LIBSSH2_SESSION* s) const {
        libssh2_session_set_blocking(s, 1);
        if (send_disconnect)
            libssh2_session_disconnect(s, "Shutdown");
        libssh2_session_free(s);
    }
};
using SshSessionPtr = std::unique_ptr<LIBSSH2_SESSION, SshSessionDeleter>;

// LIBSSH2_CHANNEL* — close → free.
struct SshChannelDeleter {
    void operator()(LIBSSH2_CHANNEL* c) const {
        libssh2_channel_close(c);
        libssh2_channel_free(c);
    }
};
using SshChannelPtr = std::unique_ptr<LIBSSH2_CHANNEL, SshChannelDeleter>;

// LIBSSH2_LISTENER* — forward_cancel (also frees the listener object).
// NOTE: the owning session must still be alive when the deleter fires.
// Declare SshListenerPtr *after* SshSessionPtr in any local scope so that
// C++ destroys it first (reverse declaration order), before the session.
struct SshListenerDeleter {
    void operator()(LIBSSH2_LISTENER* l) const {
        libssh2_channel_forward_cancel(l);
    }
};
using SshListenerPtr = std::unique_ptr<LIBSSH2_LISTENER, SshListenerDeleter>;

// SOCKET is a UINT_PTR (integer handle), not a pointer, so unique_ptr
// cannot wrap it directly.  WinSocket is a minimal move-only RAII guard.
struct WinSocket {
    SOCKET s = INVALID_SOCKET;

    WinSocket() = default;
    explicit WinSocket(SOCKET sock) : s(sock) {}
    ~WinSocket()                               { close(); }
    WinSocket(WinSocket&& o) noexcept          : s(o.s) { o.s = INVALID_SOCKET; }
    WinSocket& operator=(WinSocket&& o) noexcept {
        if (this != &o) { close(); s = o.s; o.s = INVALID_SOCKET; }
        return *this;
    }
    WinSocket(const WinSocket&)            = delete;
    WinSocket& operator=(const WinSocket&) = delete;

    SOCKET get()    const { return s; }
    SOCKET release()      { SOCKET t = s; s = INVALID_SOCKET; return t; }
    explicit operator bool() const { return s != INVALID_SOCKET; }

private:
    void close() { if (s != INVALID_SOCKET) { closesocket(s); s = INVALID_SOCKET; } }
};

// addrinfo* — freeaddrinfo.
struct AddrInfoDeleter {
    void operator()(addrinfo* ai) const { freeaddrinfo(ai); }
};
using AddrInfoPtr = std::unique_ptr<addrinfo, AddrInfoDeleter>;

