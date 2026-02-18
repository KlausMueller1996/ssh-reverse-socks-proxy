# Reverse SOCKS5 Proxy over SSH — Implementation Summary

## What This Is

A self-contained Windows executable that connects outbound to a Linux OpenSSH server,
requests **remote port forwarding**, and fulfils SOCKS5 requests that arrive through
the tunnel. Functionally equivalent to running:

```
ssh -R 1080:localhost:1080 user@server
```

…but embedded and scriptable, with no OpenSSH client dependency.

```
[SOCKS5 Client]
      |  SOCKS5 (TCP)
      v
[OpenSSH Server :1080]   <-- remote port-forward listener
      |  forwarded-tcpip channel (over SSH)
      v
[ssh-proxy.exe]         <-- this program
      |  async TCP
      v
[Target Host]
```

## Solution Structure

Three Visual Studio 2022 projects, all targeting **x64**, statically linked (`/MT`/`/MTd`).

```
ssh-proxy.sln
├── ssh-proxy-lib\          Static library — all core logic
│   ├── public\
│   │   └── ssh_proxy.h     Single public header (namespace ssh_proxy)
│   ├── include\            Private headers
│   │   ├── common.h
│   │   ├── ssh_config.h
│   │   ├── logger.h
│   │   ├── ssh_channel.h
│   │   ├── ssh_transport.h
│   │   ├── socks5_session.h
│   │   ├── socks5_handler.h
│   │   ├── async_io.h
│   │   └── tcp_connection.h
│   └── src\
│       ├── connect.cpp
│       ├── ssh_transport.cpp
│       ├── socks5_session.cpp
│       ├── socks5_handler.cpp
│       ├── logger.cpp
│       ├── async_io.cpp
│       └── tcp_connection.cpp
├── ssh-proxy\              Thin console executable
│   ├── include\
│   │   └── config.h        CliArgs + ParseCommandLine()
│   └── src\
│       ├── main.cpp
│       └── config.cpp
└── ssh-proxy-tests\        Google Test executable (63 tests)
    └── src\
        ├── test_main.cpp
        ├── test_logger.cpp
        ├── test_socks5.cpp
        ├── test_socks5_session.cpp
        ├── test_config.cpp
        └── test_connect.cpp
```

## Public API (`ssh_proxy.h`)

All symbols live in `namespace ssh_proxy`.

```cpp
enum class LogLevel { Debug, Info, Warn, Error };

class Connect {
public:
    // Synchronously connects (TCP + SSH handshake + auth + port-forward request).
    // Throws std::runtime_error on failure.
    // Starts an internal I/O thread on success; destructor cancels and joins it.
    Connect(std::string server_host, std::string username, std::string password,
            uint16_t server_port = 22, uint16_t forward_port = 1080,
            uint32_t connect_timeout_ms = 10000,
            uint32_t keepalive_interval_ms = 30000,
            LogLevel log_level = LogLevel::Info);
    ~Connect();

    void Cancel();          // Signal I/O thread to stop (non-blocking)
    bool IsConnected();     // False after Cancel() or unexpected session drop
};

std::string GetLog();       // Last ≤100 log entries, formatted, oldest first
```

## Layer-by-Layer Breakdown

### Foundation (`common.h`, `logger.h`)

| File | Role |
|------|------|
| **common.h** | Windows headers (correct order), `libssh2.h`, `ErrorCode` enum, `WsaToErrorCode`, `ByteBuffer` alias. |
| **logger.h/.cpp** | Static circular buffer (100 entries, `std::deque`), mutex-protected. `SetMinLevel`, `SetCallback` (real-time hook, used by CLI to mirror to stderr), `Snapshot()`. No stderr output by default. `ssh_proxy::GetLog()` formats the snapshot. |

### SSH Transport (`ssh_transport.h/.cpp`)

Owns the libssh2 session and the dedicated **SSH I/O thread** (all libssh2 calls are confined to this thread — the library is not thread-safe).

- **Connect phase** (blocking, called from constructor):
  `socket() → connect() → libssh2_session_handshake() → libssh2_userauth_password() → libssh2_channel_forward_listen_ex()`
  Host key fingerprint logged at DEBUG; all keys accepted unconditionally.
- **Accept loop** (SSH I/O thread):
  `libssh2_channel_forward_accept()` in a non-blocking `select()` loop (100 ms timeout). Each accepted channel is handed to an `OnChannelAccepted` callback.
- **Write queues**: IOCP workers cannot call libssh2 directly. They post data to per-channel `mutex`-protected queues; the I/O thread drains them each loop iteration.
- **Keepalive**: `libssh2_keepalive_send()` called according to `keepalive_interval_ms`.

### SOCKS5 Protocol (`socks5_handler.h/.cpp`)

Pure functions, no state. Covers RFC 1928 fully:

| Function | Role |
|----------|------|
| `ParseMethodRequest` | Returns bytes consumed, 0 if incomplete, -1 on error. Sets `supports_no_auth`. |
| `BuildMethodResponse` | `{VER, METHOD}` |
| `ParseConnectRequest` | IPv4, IPv6, domain. Returns bytes consumed, 0 if incomplete, -1 on error. |
| `BuildConnectReply` | `{VER, REP, RSV, ATYP, ADDR, PORT}` |
| `ErrorCodeToSocks5Reply` | Maps `ErrorCode` → SOCKS5 reply byte |

### SOCKS5 Session (`socks5_session.h/.cpp`, `ssh_channel.h`)

`IChannel` is a pure virtual interface wrapping one forwarded-tcpip channel. `SshChannel` is the libssh2 implementation; `FakeChannel` is the test double.

`Socks5Session` owns one `IChannel` and one `TcpConnection`. State machine:

```
ReadingMethods → ReadingRequest → Connecting → Relaying → Closed
```

- **ReadingMethods / ReadingRequest**: Synchronous reads on the SSH I/O thread via `IChannel::Read`. Partial data is accumulated in `m_inbound_buf` and re-parsed on the next read.
- **Connecting**: `TcpConnection::ConnectAsync()` — hands off to IOCP.
- **Relaying**: Bidirectional. `channel → target`: I/O thread calls `IChannel::Read`, posts to IOCP via `TcpConnection::Send`. `target → channel`: IOCP callback calls `IChannel::Write` via the SSH transport's write queue.

### Async I/O (`async_io.h/.cpp`, `tcp_connection.h/.cpp`)

| File | Role |
|------|------|
| **async_io.h/.cpp** | `IoEngine` singleton: IOCP handle + thread pool (CPU-count workers). Loads `ConnectEx` via `WSAIoctl`. Workers call `GetQueuedCompletionStatus` and invoke `IoContext::callback`. |
| **tcp_connection.h/.cpp** | `getaddrinfo` for DNS, `WSASocketW` + `ConnectEx` for async connect, `WSARecv`/`WSASend` with overlapped I/O and write-queue serialization. |

### RAII Handle (`connect.cpp`)

`ssh_proxy::Connect` ties everything together:

1. Allocates `Impl` (holds `SshProxyConfig` + `SshTransport` + `atomic<bool> connected`)
2. Calls `IoEngine::Init()` (idempotent) and `libssh2_init()` (idempotent)
3. Calls `SshTransport::Connect()` — throws `std::runtime_error` on any failure
4. Calls `SshTransport::StartAccepting()` with two lambdas:
   - `on_channel`: wraps the channel in `Socks5Session`, calls `session->Start()`
   - `on_disconnect`: sets `connected = false`, logs a warning

Destructor calls `SshTransport::Close()` which signals the I/O thread and joins it.

### CLI (`config.h/.cpp`, `main.cpp`)

`ParseCommandLine` fills `CliArgs`. Required: `--server`, `--username`/`-u`, `--password`/`-p`. Optional: `--port`(22), `--forward-port`/`-f`(1080), `--connect-timeout`(10000), `--keepalive-ms`(30000), `--log-level`(info).

`main.cpp` registers a `Logger::SetCallback` to mirror log entries to stderr, installs a `SetConsoleCtrlHandler` for Ctrl+C, constructs `ssh_proxy::Connect`, then spins on `IsConnected()` until the session ends. No reconnect logic — the library is single-shot; retry is left to the caller.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **SSH is the multiplexer** | `libssh2_channel_forward_listen_ex` + `forwarded-tcpip` channels replace the old custom frame protocol entirely |
| **Dedicated SSH I/O thread** | libssh2 is not thread-safe; all libssh2 calls are serialized to one thread |
| **IOCP for target TCP only** | IOCP workers are not allowed to touch libssh2; they post to per-channel write queues instead |
| **IChannel abstraction** | Decouples `Socks5Session` from libssh2 so it can be unit-tested with a `FakeChannel` |
| **Constructor throws** | No zombie objects; `Connect` is either fully operational or doesn't exist |
| **No host key verification** | Fingerprint is logged at DEBUG; trust-all policy suitable for internal/embedded use |
| **Static linking** | vcpkg triplet `x64-windows-static`; produces a single self-contained `ssh-proxy.exe` |
| **No reconnect in library** | Reconnect logic belongs in the embedding application, not the library |

## Dependencies

All statically linked via vcpkg manifest (`vcpkg.json`):

| Library | Purpose |
|---------|---------|
| `libssh2` (OpenSSL + zlib features) | SSH transport |
| `gtest` | Unit tests |
| `ws2_32`, `mswsock` | Winsock, IOCP, ConnectEx |
| `bcrypt` | WinCNG (libssh2 crypto backend) |
| `crypt32` | Windows certificate store (required by OpenSSL's CAPI/WinStore engines) |

vcpkg install layout (manifest mode, x64-windows-static):
```
vcpkg_installed/x64-windows-static/x64-windows-static/include/   ← headers
vcpkg_installed/x64-windows-static/x64-windows-static/lib/       ← release libs
vcpkg_installed/x64-windows-static/x64-windows-static/debug/lib/ ← debug libs
```

## Building

Open `ssh-proxy.sln` in Visual Studio 2022. On first build, VS installs vcpkg dependencies automatically (~23 min cold, cached thereafter). Select **x64 / Debug** or **Release** and build.

From VS Code: **Ctrl+Shift+B** → *Build Debug* (default task).

## Running

```
ssh-proxy.exe --server 10.0.0.1 --username alice --password s3cr3t
ssh-proxy.exe --server jump.example.com -u bob -p hunter2 --forward-port 8080 --log-level debug
ssh-proxy.exe --help
```

Once running, configure your SOCKS5 client to use `127.0.0.1:1080` (or the `--forward-port` value) on the **SSH server**.

## Testing

```
bin\Debug\ssh-proxy-tests.exe
```

63 tests across 9 suites. Pure-function tests run in <10 ms; `ConnectTest` exercises the throwing constructor against `127.0.0.1:1` (~6 s total due to TCP timeout).

| Suite | Coverage |
|-------|---------|
| `LoggerTest` | Circular buffer, min-level filtering, callback, timestamp format, `GetLog()` |
| `Socks5ParseMethod` | Method request parsing — complete, incomplete, bad version, zero methods |
| `Socks5BuildMethod` | Method response encoding |
| `Socks5ParseConnect` | CONNECT request — IPv4, domain, IPv6, incomplete, bad version, unknown atyp |
| `Socks5BuildReply` | Connect reply encoding, bind address, port byte order |
| `Socks5ErrorMapping` | `ErrorCode` → SOCKS5 reply code mapping |
| `Socks5Session` | SOCKS5 handshake state machine via `FakeChannel` — accept, reject, bad version, malformed request, partial data reassembly |
| `ParseCLITest` | All CLI flags, defaults, validation, short flags, error paths |
| `ConnectTest` | Constructor throws on unreachable host/DNS failure, exception message non-empty |
