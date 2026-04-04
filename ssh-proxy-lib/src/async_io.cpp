//////////////////////////////////////////////////////////////////////////////
//
// IoEngine — process-wide IOCP singleton, worker thread pool, ConnectEx loader
//
// PURPOSE
//   Owns the one Windows I/O Completion Port shared by all TcpConnection
//   objects.  Provides the worker thread pool that dequeues completions and
//   invokes the per-operation callbacks stored in each IoContext.
//
// DESIGN
//   All members are static — IoEngine is never instantiated.  Init() is
//   idempotent so callers do not need to coordinate first-caller semantics.
//
// CONNECTEX
//   ConnectEx is not a normal Winsock symbol; it must be retrieved at runtime
//   via WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER).  Init() loads it once
//   into s_connect_ex; GetConnectEx() hands it to TcpConnection callers.
//
// SHUTDOWN PROTOCOL
//   Shutdown() posts one IOCP_SHUTDOWN_KEY packet per worker thread.  Each
//   worker breaks its dequeue loop on that sentinel and returns, which is
//   detected by WaitForMultipleObjects before handle and memory cleanup.
//
//////////////////////////////////////////////////////////////////////////////

#include "async_io.h"
#include "logger.h"

HANDLE          IoEngine::s_iocp = nullptr;
HANDLE*         IoEngine::s_threads = nullptr;
int             IoEngine::s_thread_count = 0;
LPFN_CONNECTEX  IoEngine::s_connect_ex = nullptr;
bool            IoEngine::s_initialized = false;

//////////////////////////////////////////////////////////////////////////////
//
// Init
//
// Sequences one-time process-wide setup: Winsock, the IOCP handle, ConnectEx,
// and the worker thread pool.  Any step failure rolls back what was already
// allocated and returns ErrorCode::SocketError.  Safe to call multiple times —
// returns Success immediately if already initialised.
//
//////////////////////////////////////////////////////////////////////////////

ErrorCode IoEngine::Init(int thread_count)
{
    if (s_initialized)
        return ErrorCode::Success;

    // Initialize Winsock
    WSADATA wsa;
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        Logger::Error("WSAStartup failed: %d", ::WSAGetLastError());
        return ErrorCode::SocketError;
    }

    // Determine thread count
    if (thread_count <= 0)
    {
        SYSTEM_INFO si;
        ::GetSystemInfo(&si);
        thread_count = static_cast<int>(si.dwNumberOfProcessors);
        if (thread_count < 1) thread_count = 1;
    }

    // Create completion port
    s_iocp = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, static_cast<DWORD>(thread_count));
    if (s_iocp == nullptr)
    {
        Logger::Error("CreateIoCompletionPort failed: %lu", ::GetLastError());
        return ErrorCode::SocketError;
    }

    // Load ConnectEx
    SOCKET tmp = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tmp != INVALID_SOCKET)
    {
        GUID guid = WSAID_CONNECTEX;
        DWORD bytes = 0;
        ::WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &guid, sizeof(guid),
                   &s_connect_ex, sizeof(s_connect_ex),
                   &bytes, nullptr, nullptr);
        ::closesocket(tmp);
    }
    if (s_connect_ex == nullptr)
    {
        Logger::Error("Failed to load ConnectEx");
        return ErrorCode::SocketError;
    }

    // Start worker threads
    s_thread_count = thread_count;
    s_threads = new HANDLE[thread_count]{};
    for (int i = 0; i < thread_count; ++i)
    {
        s_threads[i] = ::CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
        if (s_threads[i] == nullptr)
        {
            Logger::Error("CreateThread failed: %lu", ::GetLastError());
            // Shut down any workers that were already spawned
            for (int j = 0; j < i; ++j)
                ::PostQueuedCompletionStatus(s_iocp, 0, IOCP_SHUTDOWN_KEY, nullptr);
            if (i > 0)
                ::WaitForMultipleObjects(static_cast<DWORD>(i), s_threads, TRUE, 5000);
            for (int j = 0; j < i; ++j) ::CloseHandle(s_threads[j]);
            delete[] s_threads;
            s_threads = nullptr;
            ::CloseHandle(s_iocp);
            s_iocp = nullptr;
            ::WSACleanup();
            return ErrorCode::SocketError;
        }
    }

    s_initialized = true;
    Logger::Info("IoEngine initialized with %d worker threads", thread_count);
    return ErrorCode::Success;
}

//
// ── Shutdown ──────────────────────────────────────────────────────────────────
//
// Signals every worker thread to exit via IOCP_SHUTDOWN_KEY, waits up to
// 5 seconds for all of them, then releases the IOCP handle and Winsock.
//

void IoEngine::Shutdown()
{
    if (!s_initialized)
        return;

    // Signal all workers to exit
    for (int i = 0; i < s_thread_count; ++i)
    {
        ::PostQueuedCompletionStatus(s_iocp, 0, IOCP_SHUTDOWN_KEY, nullptr);
    }

    // Wait for all workers
    ::WaitForMultipleObjects(static_cast<DWORD>(s_thread_count), s_threads, TRUE, 5000);

    for (int i = 0; i < s_thread_count; ++i)
    {
        ::CloseHandle(s_threads[i]);
    }
    delete[] s_threads;
    s_threads = nullptr;

    ::CloseHandle(s_iocp);
    s_iocp = nullptr;

    ::WSACleanup();
    s_initialized = false;

    Logger::Info("IoEngine shut down");
}

//
// ── Associate ─────────────────────────────────────────────────────────────────
//
// Binds sock to the shared IOCP so that subsequent overlapped operations on it
// complete via the worker thread pool.  Must be called before the first
// WSARecv, WSASend, or ConnectEx on the socket.
//

ErrorCode IoEngine::Associate(SOCKET sock, ULONG_PTR key)
{
    HANDLE h = ::CreateIoCompletionPort(reinterpret_cast<HANDLE>(sock), s_iocp, key, 0);
    if (h == nullptr)
    {
        Logger::Error("Associate socket to IOCP failed: %lu", ::GetLastError());
        return ErrorCode::SocketError;
    }
    return ErrorCode::Success;
}

LPFN_CONNECTEX IoEngine::GetConnectEx()
{
    return s_connect_ex;
}

//
// ── PostCompletion ────────────────────────────────────────────────────────────
//
// Manually queues ctx as a synthetic completion packet.  Used to dispatch
// arbitrary work (e.g. DNS resolve, TcpConnection::ConnectAsync) onto IOCP
// worker threads without an actual I/O operation.
//

void IoEngine::PostCompletion(IoContext* ctx, DWORD bytes)
{
    ::PostQueuedCompletionStatus(s_iocp, bytes, 0, ctx);
}

//////////////////////////////////////////////////////////////////////////////
//
// WorkerThread
//
// IOCP dequeue loop.  Runs on each worker thread for the lifetime of the
// engine.  On each iteration it blocks in GetQueuedCompletionStatus then
// dispatches to the callback stored in the IoContext.
//
// The callback is moved out of ctx before being called.  This releases any
// shared_ptr captured in the lambda immediately after the call, breaking
// self-reference cycles (e.g. IoContext callback → shared_ptr<TcpConnection>
// → IoContext) that would otherwise prevent destruction.
//
//////////////////////////////////////////////////////////////////////////////

DWORD WINAPI IoEngine::WorkerThread(LPVOID /*param*/)
{
    Logger::Debug("IOCP worker thread started");

    for (;;)
    {
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        LPOVERLAPPED overlapped = nullptr;

        BOOL ok = ::GetQueuedCompletionStatus(
            s_iocp, &bytes_transferred, &completion_key, &overlapped, INFINITE);

        // Shutdown signal
        if (completion_key == IOCP_SHUTDOWN_KEY)
        {
            Logger::Debug("IOCP worker thread shutting down");
            break;
        }

        if (overlapped == nullptr)
        {
            // Spurious wake or error with no overlapped
            continue;
        }

        auto* ctx = static_cast<IoContext*>(overlapped);

        ErrorCode ec = ErrorCode::Success;
        if (!ok)
        {
            DWORD err = ::GetLastError();
            if (err == ERROR_OPERATION_ABORTED)
            {
                // Cancelled — socket was closed
                ec = ErrorCode::Shutdown;
            }
            else
            {
                ec = WsaToErrorCode(static_cast<int>(err));
                if (ec == ErrorCode::Success)
                    ec = ErrorCode::SocketError;
            }
        }

        if (ctx->callback)
        {
            // Move out before calling: releases any shared_ptr captured in the
            // callback immediately after the call, breaking self-reference cycles
            // (e.g. IoContext callback → shared_ptr<TcpConnection> → IoContext).
            auto cb = std::move(ctx->callback);
            cb(ctx, bytes_transferred, ec);
        }
    }

    return 0;
}
