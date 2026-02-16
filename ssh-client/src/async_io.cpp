#include "async_io.h"
#include "logger.h"

HANDLE          IoEngine::s_iocp = nullptr;
HANDLE*         IoEngine::s_threads = nullptr;
int             IoEngine::s_thread_count = 0;
LPFN_CONNECTEX  IoEngine::s_connect_ex = nullptr;
bool            IoEngine::s_initialized = false;

ErrorCode IoEngine::Init(int thread_count) {
    if (s_initialized)
        return ErrorCode::Success;

    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        Logger::Error("WSAStartup failed: %d", WSAGetLastError());
        return ErrorCode::SocketError;
    }

    // Determine thread count
    if (thread_count <= 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        thread_count = static_cast<int>(si.dwNumberOfProcessors);
        if (thread_count < 1) thread_count = 1;
    }

    // Create completion port
    s_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, static_cast<DWORD>(thread_count));
    if (!s_iocp) {
        Logger::Error("CreateIoCompletionPort failed: %lu", GetLastError());
        return ErrorCode::SocketError;
    }

    // Load ConnectEx
    SOCKET tmp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tmp != INVALID_SOCKET) {
        GUID guid = WSAID_CONNECTEX;
        DWORD bytes = 0;
        WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &s_connect_ex, sizeof(s_connect_ex),
                 &bytes, nullptr, nullptr);
        closesocket(tmp);
    }
    if (!s_connect_ex) {
        Logger::Error("Failed to load ConnectEx");
        return ErrorCode::SocketError;
    }

    // Start worker threads
    s_thread_count = thread_count;
    s_threads = new HANDLE[thread_count];
    for (int i = 0; i < thread_count; ++i) {
        s_threads[i] = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
        if (!s_threads[i]) {
            Logger::Error("CreateThread failed: %lu", GetLastError());
            return ErrorCode::SocketError;
        }
    }

    s_initialized = true;
    Logger::Info("IoEngine initialized with %d worker threads", thread_count);
    return ErrorCode::Success;
}

void IoEngine::Shutdown() {
    if (!s_initialized)
        return;

    // Signal all workers to exit
    for (int i = 0; i < s_thread_count; ++i) {
        PostQueuedCompletionStatus(s_iocp, 0, IOCP_SHUTDOWN_KEY, nullptr);
    }

    // Wait for all workers
    WaitForMultipleObjects(static_cast<DWORD>(s_thread_count), s_threads, TRUE, 5000);

    for (int i = 0; i < s_thread_count; ++i) {
        CloseHandle(s_threads[i]);
    }
    delete[] s_threads;
    s_threads = nullptr;

    CloseHandle(s_iocp);
    s_iocp = nullptr;

    WSACleanup();
    s_initialized = false;

    Logger::Info("IoEngine shut down");
}

ErrorCode IoEngine::Associate(SOCKET sock, ULONG_PTR key) {
    HANDLE h = CreateIoCompletionPort(reinterpret_cast<HANDLE>(sock), s_iocp, key, 0);
    if (!h) {
        Logger::Error("Associate socket to IOCP failed: %lu", GetLastError());
        return ErrorCode::SocketError;
    }
    return ErrorCode::Success;
}

LPFN_CONNECTEX IoEngine::GetConnectEx() {
    return s_connect_ex;
}

void IoEngine::PostCompletion(IoContext* ctx, DWORD bytes) {
    PostQueuedCompletionStatus(s_iocp, bytes, 0, ctx);
}

HANDLE IoEngine::GetHandle() {
    return s_iocp;
}

DWORD WINAPI IoEngine::WorkerThread(LPVOID /*param*/) {
    Logger::Debug("IOCP worker thread started");

    for (;;) {
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        LPOVERLAPPED overlapped = nullptr;

        BOOL ok = GetQueuedCompletionStatus(
            s_iocp, &bytes_transferred, &completion_key, &overlapped, INFINITE);

        // Shutdown signal
        if (completion_key == IOCP_SHUTDOWN_KEY) {
            Logger::Debug("IOCP worker thread shutting down");
            break;
        }

        if (!overlapped) {
            // Spurious wake or error with no overlapped
            continue;
        }

        auto* ctx = static_cast<IoContext*>(overlapped);

        ErrorCode ec = ErrorCode::Success;
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED) {
                // Cancelled — socket was closed
                ec = ErrorCode::Shutdown;
            } else {
                ec = WsaToErrorCode(static_cast<int>(err));
                if (ec == ErrorCode::Success)
                    ec = ErrorCode::SocketError;
            }
        }

        if (ctx->callback) {
            ctx->callback(ctx, bytes_transferred, ec);
        }
    }

    return 0;
}
