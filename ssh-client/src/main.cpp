#include "common.h"
#include "config.h"
#include "logger.h"
#include "async_io.h"
#include "ssl_transport.h"
#include "mux_session.h"

// Global shutdown flag
static volatile LONG g_shutdown = 0;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        Logger::Info("Shutdown signal received");
        InterlockedExchange(&g_shutdown, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

static void RunSession(const AppConfig& config) {
    SslTransport transport;

    ErrorCode ec = transport.Connect(
        config.server_host.c_str(),
        config.server_port,
        config.verify_certificate);

    if (ec != ErrorCode::Success) {
        Logger::Error("Failed to connect: %s", ErrorCodeToString(ec));
        return;
    }

    Logger::Info("Connected to %s:%u", config.server_host.c_str(), config.server_port);

    // Session disconnect event
    HANDLE disconnect_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ErrorCode disconnect_reason = ErrorCode::Success;

    MuxSession session(&transport, config.channel_window_size, config.keepalive_interval_ms);
    session.Start([&](ErrorCode reason) {
        disconnect_reason = reason;
        SetEvent(disconnect_event);
    });

    // Wait for disconnect or shutdown
    while (!g_shutdown) {
        DWORD wait = WaitForSingleObject(disconnect_event, 1000);
        if (wait == WAIT_OBJECT_0) break;
    }

    session.Shutdown();
    transport.Close();
    CloseHandle(disconnect_event);

    Logger::Info("Session ended: %s", ErrorCodeToString(disconnect_reason));
}

int main(int argc, char* argv[]) {
    AppConfig config;
    ErrorCode ec = ParseCommandLine(argc, argv, config);
    if (ec == ErrorCode::Shutdown) return 0;     // --help
    if (ec != ErrorCode::Success)  return 1;

    Logger::Init(config.log_level);
    Logger::Info("ssh-client starting");

    // Initialize IOCP engine
    ec = IoEngine::Init(config.io_thread_count);
    if (ec != ErrorCode::Success) {
        Logger::Error("IoEngine init failed: %s", ErrorCodeToString(ec));
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // Reconnect loop with exponential backoff
    int delay_ms = config.reconnect_delay_initial_ms;

    while (!g_shutdown) {
        RunSession(config);

        if (g_shutdown) break;

        Logger::Info("Reconnecting in %d ms...", delay_ms);
        Sleep(static_cast<DWORD>(delay_ms));

        // Exponential backoff
        delay_ms = (std::min)(delay_ms * 2, config.reconnect_delay_max_ms);
    }

    // Reset backoff on clean exit path (future: reset on successful connect)
    IoEngine::Shutdown();
    Logger::Info("ssh-client exiting");
    return 0;
}
