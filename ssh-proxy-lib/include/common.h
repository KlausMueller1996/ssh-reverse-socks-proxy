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
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <algorithm>

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
