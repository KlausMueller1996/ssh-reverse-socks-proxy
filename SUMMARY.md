
claude --resume 52929940-c76c-4c74-9036-15b23906df3a

# Reverse SOCKS5 Proxy over SSL Tunnel — Implementation Summary

## What This Is

A Windows client that connects outbound to a remote server via SSL/TLS (SChannel), then acts as a **reverse SOCKS5 proxy** — the server sends SOCKS5 requests through the tunnel, and the client resolves them locally on its network.

```
[Remote Server] <--SSL/TLS--> [SslTransport] <--frames--> [MuxSession] <--channels--> [Channel + Socks5] <--TCP--> [Target Hosts]
```

## Project Structure

```
ssh-client/
├── ssh-client.sln                          VS2022 solution
└── ssh-client/
    ├── ssh-client.vcxproj                  C++17, x64, W4+WX, Console
    ├── ssh-client.vcxproj.filters
    ├── include/
    │   ├── common.h                        Windows headers, pragmas, ErrorCode enum
    │   ├── config.h                        AppConfig + CLI parsing
    │   ├── logger.h                        Thread-safe stderr logger
    │   ├── async_io.h                      IOCP engine (IoContext, IoEngine)
    │   ├── ssl_transport.h                 SChannel TLS connection
    │   ├── mux_protocol.h                  Frame header, codec, builders
    │   ├── mux_session.h                   Session manager, channel registry
    │   ├── channel.h                       Per-channel state machine
    │   ├── socks5_handler.h                SOCKS5 parser/builder (RFC 1928)
    │   └── tcp_connection.h                Async outbound TCP to targets
    └── src/
        ├── main.cpp                        Entry point, reconnect loop, Ctrl+C
        ├── config.cpp                      CLI argument parsing
        ├── logger.cpp                      Timestamped, thread-safe logging
        ├── async_io.cpp                    IOCP creation, worker threads, ConnectEx
        ├── ssl_transport.cpp               TLS handshake, encrypt/decrypt, async recv
        ├── mux_protocol.cpp                Frame accumulation + encoding
        ├── mux_session.cpp                 Frame dispatch, channel lifecycle, keepalive
        ├── channel.cpp                     SOCKS5 handshake + relay state machine
        ├── socks5_handler.cpp              RFC 1928 parsing and reply building
        └── tcp_connection.cpp              DNS resolve, ConnectEx, overlapped R/W
```

## What Each Layer Does

### Foundation

| File | Role |
|------|------|
| **common.h** | Pulls in `winsock2.h`, `security.h`, `schannel.h`, `mswsock.h`. Links `ws2_32`, `secur32`, `crypt32`, `mswsock`. Defines `ErrorCode` enum and `ByteBuffer` alias. |
| **config.h/.cpp** | `AppConfig` struct with `--server`, `--port`, `--no-verify`, `--reconnect-ms`, `--reconnect-max`, `--keepalive-ms`, `--threads`, `--log-level`. |
| **logger.h/.cpp** | `Logger::Debug/Info/Warn/Error` with `YYYY-MM-DD HH:MM:SS.mmm [LVL] [TID]` format. Uses `CRITICAL_SECTION` for thread safety. |
| **async_io.h/.cpp** | `IoEngine` singleton: creates IOCP, spawns worker thread pool (CPU count by default), loads `ConnectEx` via `WSAIoctl`. Workers call `GetQueuedCompletionStatus` in a loop and dispatch to `IoContext::callback`. |

### SSL Transport

| File | Role |
|------|------|
| **ssl_transport.h/.cpp** | Blocking TCP connect + TLS handshake (called from reconnect loop). Uses `SCH_CREDENTIALS` with `SCH_USE_STRONG_CRYPTO`. Handshake loop handles `SEC_I_CONTINUE_NEEDED` and `SEC_E_INCOMPLETE_MESSAGE`. After handshake, queries `SECPKG_ATTR_STREAM_SIZES` for encrypt/decrypt buffer sizing. **Send path**: `EncryptMessage` chunked to `cbMaximumMessage` (~16KB), serialized via `CRITICAL_SECTION`. **Recv path**: async `WSARecv` on IOCP, `DecryptMessage` with `SECBUFFER_EXTRA` handling for partial TLS records. |

### Wire Protocol

| File | Role |
|------|------|
| **mux_protocol.h/.cpp** | 8-byte frame header (type, flags, channel_id, payload_length), little-endian. `FrameCodec::Feed()` accumulates partial data and emits complete `Frame` objects. Convenience builders for all frame types. Max payload 64KB. |

Frame types:
- `CHANNEL_OPEN (0x01)` / `CHANNEL_OPEN_ACK (0x02)` — server opens a new channel
- `CHANNEL_REQUEST (0x03)` / `CHANNEL_REQUEST_ACK (0x04)` — SOCKS5 handshake data
- `DATA (0x05)` — relay payload
- `CHANNEL_CLOSE (0x06)` / `CHANNEL_CLOSE_ACK (0x07)` — teardown
- `PING (0x08)` / `PONG (0x09)` — keepalive
- `WINDOW_UPDATE (0x0A)` — flow control

### SOCKS5

| File | Role |
|------|------|
| **socks5_handler.h/.cpp** | Parses method selection (RFC 1928 §3) and CONNECT requests (§4) supporting IPv4, IPv6, and domain address types. Builds method responses and connect replies. Maps `ErrorCode` → SOCKS5 reply codes (`WSAENETUNREACH→0x03`, `WSAEHOSTUNREACH→0x04`, `WSAECONNREFUSED→0x05`, `WSAETIMEDOUT→0x06`). |

### Channel & Session

| File | Role |
|------|------|
| **channel.h/.cpp** | State machine per SOCKS5 session: `Opening → Requesting → Connecting → Relaying → Closing → Closed`. On `CHANNEL_OPEN`: sends ACK, transitions to Requesting. On `CHANNEL_REQUEST`: accumulates SOCKS5 bytes, parses method negotiation then CONNECT request, initiates async TCP connect. On target connect success: sends SOCKS5 success reply, starts bidirectional relay. Flow control: 256KB receive window, replenished at 50% consumption via `WINDOW_UPDATE`. |
| **tcp_connection.h/.cpp** | `getaddrinfo` for DNS, `WSASocketW` with `WSA_FLAG_OVERLAPPED`, `ConnectEx` for async connect, `WSARecv`/`WSASend` for overlapped I/O. Write queue with `CRITICAL_SECTION` serialization. |
| **mux_session.h/.cpp** | Hooks into `SslTransport` read callbacks. Feeds raw bytes to `FrameCodec`, dispatches decoded frames to handlers. Channel registry (`unordered_map<uint16_t, unique_ptr<Channel>>`) protected by `SRWLOCK`. Keepalive timer via `CreateTimerQueueTimer`. On transport disconnect: closes all channels, notifies main loop. |

### Integration

| File | Role |
|------|------|
| **main.cpp** | `SetConsoleCtrlHandler` for Ctrl+C. Reconnect loop: connect → run session → on disconnect, exponential backoff (1s → 2s → 4s → ... → 60s cap). |

## Design Decisions

- **No exceptions** — `ErrorCode` return values throughout (IOCP callbacks + exceptions = trouble)
- **SChannel only** — no OpenSSL dependency, uses Windows native TLS
- **IOCP thread pool** — CPU-count worker threads, all socket I/O is overlapped
- **Single TCP connection** — everything multiplexed over one SSL tunnel
- **Send serialization** — `CRITICAL_SECTION` on SSL encrypt path (SChannel contexts are not thread-safe)

## Not Yet Implemented

- **Authentication** — no client-to-server auth after TLS handshake
- **TLS client certificates** (mutual TLS)
- **Backoff reset** — delay doesn't reset to initial on successful connection
- **Graceful channel draining** — FIN-flagged close doesn't wait for in-flight data
- **Send-side flow control enforcement** — send window is tracked but not used to pause target reads

## Building

Open `ssh-client.sln` in Visual Studio 2022, select **x64** / **Debug** or **Release**, build.

## Usage

```
ssh-client.exe --server 10.0.0.1 --port 8443
ssh-client.exe --server example.com --port 443 --no-verify --log-level debug
ssh-client.exe --help
```
