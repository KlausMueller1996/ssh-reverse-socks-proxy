#pragma once
#include "common.h"
#include <functional>

// Completion key used to signal worker threads to exit
static constexpr ULONG_PTR IOCP_SHUTDOWN_KEY = 0xDEAD;

// I/O operation types
enum class IoOp : uint8_t {
    Connect,
    Send,
    Recv,
    Timer,
};

// Extends OVERLAPPED — must be allocated for each async operation.
// The IOCP callback receives the OVERLAPPED* and static_casts back to IoContext*.
struct IoContext : OVERLAPPED {
    IoOp    op;
    SOCKET  socket;
    WSABUF  wsa_buf;
    uint8_t inline_buf[4096]{ 0 };
    void*   user_data;

    // Callback: (IoContext*, DWORD bytes_transferred, ErrorCode)
    std::function<void(IoContext*, DWORD, ErrorCode)> callback;

    IoContext() {
        ZeroMemory(static_cast<OVERLAPPED*>(this), sizeof(OVERLAPPED));
        op = IoOp::Recv;
        socket = INVALID_SOCKET;
        wsa_buf.buf = reinterpret_cast<char*>(inline_buf);
        wsa_buf.len = sizeof(inline_buf);
        user_data = nullptr;
    }
};

// Singleton IOCP engine — owns the completion port and worker threads.
class IoEngine {
public:
    // Initialize with given thread count (0 = CPU count).
    static ErrorCode Init(int thread_count);

    // Shut down: post shutdown completions, join workers, close IOCP handle.
    static void Shutdown();

    // Associate a socket with the IOCP.
    static ErrorCode Associate(SOCKET sock, ULONG_PTR key = 0);

    // Load ConnectEx function pointer for a socket family.
    static LPFN_CONNECTEX GetConnectEx();

    // Post a manual completion to wake a worker.
    static void PostCompletion(IoContext* ctx, DWORD bytes = 0);

    // Get the IOCP handle (for advanced use).
    static HANDLE GetHandle();

private:
    static DWORD WINAPI WorkerThread(LPVOID param);

    static HANDLE            s_iocp;
    static HANDLE*           s_threads;
    static int               s_thread_count;
    static LPFN_CONNECTEX    s_connect_ex;
    static bool              s_initialized;
};
