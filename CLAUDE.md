# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Windows C++17 static library + CLI that connects outbound to a Linux OpenSSH server, requests remote port forwarding, and serves SOCKS5 requests arriving through the tunnel — without requiring an OpenSSH client installation.

## Build

**Requirements**: Visual Studio 2022, vcpkg (integrated). On first build, vcpkg installs dependencies (~23 min cold; cached thereafter).

```
# From VS Code (default task — Ctrl+Shift+B):
"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" ssh-proxy.sln /p:Configuration=Debug /p:Platform=x64 /m /v:minimal

# Release:
"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" ssh-proxy.sln /p:Configuration=Release /p:Platform=x64 /m /v:minimal
```

All output goes to `bin\Debug\` or `bin\Release\`. The only supported target is **x64**; all projects link statically (`/MT`/`/MTd`).

## Running Tests

```
bin\Debug\ssh-proxy-tests.exe
```

63 tests across 9 suites. The `ConnectTest` suite (~6 s) exercises the constructor against `127.0.0.1:1` to test timeout/refusal handling; all other suites are <10 ms.

## Architecture

Three MSBuild projects in `ssh-proxy.sln`:

- **`ssh-proxy-lib`** — static library with all core logic; single public header at `ssh-proxy-lib/public/ssh_proxy.h` (`namespace ssh_proxy`)
- **`ssh-proxy`** — thin CLI wrapper (`main.cpp` + `config.cpp`)
- **`ssh-proxy-tests`** — Google Test executable

### Critical threading rule

**All libssh2 calls are confined to the dedicated SSH I/O thread** (`SshTransport`). libssh2 is not thread-safe. IOCP workers (which handle target TCP connections) must never call libssh2 directly — they post data to per-channel mutex-protected write queues, which the SSH I/O thread drains each loop iteration.

### Layer summary

| Layer | Files | Role |
|-------|-------|------|
| Foundation | `common.h`, `logger.h/.cpp` | Windows header order, `ErrorCode` enum, `ByteBuffer` alias, circular log buffer (100 entries, mutex-protected) |
| SSH Transport | `ssh_transport.h/.cpp` | Owns libssh2 session + SSH I/O thread. Connect phase: TCP → handshake → password auth → `forward_listen`. Accept loop: non-blocking `select()` + `forward_accept`, 100 ms timeout. |
| SOCKS5 Protocol | `socks5_handler.h/.cpp` | Pure stateless functions — parse/build method negotiation and CONNECT request (RFC 1928, IPv4/IPv6/domain) |
| SOCKS5 Session | `socks5_session.h/.cpp`, `ssh_channel.h` | State machine (`ReadingMethods → ReadingRequest → Connecting → Relaying → Closed`) owns one `IChannel` + one `TcpConnection` |
| Async TCP | `async_io.h/.cpp`, `tcp_connection.h/.cpp` | `IoEngine` singleton: IOCP + thread pool. `TcpConnection`: DNS via `getaddrinfo`, async connect via `ConnectEx`, overlapped recv/send |
| Public API | `connect.cpp`, `ssh_proxy.h` | `ssh_proxy::Connect` RAII handle — constructor throws `std::runtime_error` on any failure; destructor joins I/O thread |

### `IChannel` abstraction

`ssh_channel.h` defines `IChannel` (pure virtual). `SshChannel` wraps a real libssh2 channel; `FakeChannel` (test double) drives `Socks5Session` in unit tests without touching libssh2.

### Key design decisions

- **Constructor throws** — no zombie `Connect` objects
- **No reconnect** — `Connect` is single-shot; retry belongs in the embedding application
- **No host key verification** — fingerprint logged at DEBUG; trust-all policy
- **Static linking** — vcpkg triplet `x64-windows-static`; single self-contained `.exe`

## Dependencies (vcpkg manifest mode, `x64-windows-static`)

- `libssh2` (OpenSSL + zlib features) — SSH transport
- `gtest` — unit tests
- System: `ws2_32`, `mswsock` (Winsock/IOCP/ConnectEx), `bcrypt` (WinCNG), `crypt32`

vcpkg headers/libs land in `vcpkg_installed/x64-windows-static/x64-windows-static/`.
