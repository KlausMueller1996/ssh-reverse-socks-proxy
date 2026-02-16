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

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "mswsock.lib")

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <algorithm>

// Shared type aliases
using ByteBuffer = std::vector<uint8_t>;

// Error codes used throughout the project (no exceptions)
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
    SslHandshakeFailed,
    SslCertificateError,
    SslEncryptError,
    SslDecryptError,
    SslDisconnected,
    ProtocolError,
    BufferTooSmall,
    ChannelNotFound,
    ChannelClosed,
    WindowExhausted,
    Socks5AuthFailure,
    Socks5UnsupportedCommand,
    Socks5UnsupportedAddressType,
    Shutdown,
    IoIncomplete,
};

// Convert a WinSock error to ErrorCode
inline ErrorCode WsaToErrorCode(int wsa_error) {
    switch (wsa_error) {
    case 0:                  return ErrorCode::Success;
    case WSAECONNRESET:      return ErrorCode::ConnectionReset;
    case WSAECONNREFUSED:    return ErrorCode::ConnectionRefused;
    case WSAETIMEDOUT:       return ErrorCode::ConnectionTimeout;
    case WSAEHOSTUNREACH:    return ErrorCode::HostUnreachable;
    case WSAENETUNREACH:     return ErrorCode::NetworkUnreachable;
    default:                 return ErrorCode::SocketError;
    }
}

inline const char* ErrorCodeToString(ErrorCode ec) {
    switch (ec) {
    case ErrorCode::Success:                    return "Success";
    case ErrorCode::InvalidArgument:            return "InvalidArgument";
    case ErrorCode::OutOfMemory:                return "OutOfMemory";
    case ErrorCode::SocketError:                return "SocketError";
    case ErrorCode::ConnectionReset:            return "ConnectionReset";
    case ErrorCode::ConnectionRefused:          return "ConnectionRefused";
    case ErrorCode::ConnectionTimeout:          return "ConnectionTimeout";
    case ErrorCode::HostUnreachable:            return "HostUnreachable";
    case ErrorCode::NetworkUnreachable:         return "NetworkUnreachable";
    case ErrorCode::DnsResolutionFailed:        return "DnsResolutionFailed";
    case ErrorCode::SslHandshakeFailed:         return "SslHandshakeFailed";
    case ErrorCode::SslCertificateError:        return "SslCertificateError";
    case ErrorCode::SslEncryptError:            return "SslEncryptError";
    case ErrorCode::SslDecryptError:            return "SslDecryptError";
    case ErrorCode::SslDisconnected:            return "SslDisconnected";
    case ErrorCode::ProtocolError:              return "ProtocolError";
    case ErrorCode::BufferTooSmall:             return "BufferTooSmall";
    case ErrorCode::ChannelNotFound:            return "ChannelNotFound";
    case ErrorCode::ChannelClosed:              return "ChannelClosed";
    case ErrorCode::WindowExhausted:            return "WindowExhausted";
    case ErrorCode::Socks5AuthFailure:          return "Socks5AuthFailure";
    case ErrorCode::Socks5UnsupportedCommand:   return "Socks5UnsupportedCommand";
    case ErrorCode::Socks5UnsupportedAddressType: return "Socks5UnsupportedAddressType";
    case ErrorCode::Shutdown:                   return "Shutdown";
    case ErrorCode::IoIncomplete:               return "IoIncomplete";
    }
    return "Unknown";
}
