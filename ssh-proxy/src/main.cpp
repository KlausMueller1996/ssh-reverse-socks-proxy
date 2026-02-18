#include "config.h"
#include "../../ssh-proxy-lib/public/ssh_proxy.h"
#include "../../ssh-proxy-lib/include/logger.h"
#include <cstdio>
#include <windows.h>

// Global cancel handle — set by Ctrl-C handler, polled in main loop.
static ssh_proxy::Connect* g_connect = nullptr;
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        if (g_connect) g_connect->Cancel();
        return TRUE;
    default:
        return FALSE;
    }
}

int main(int argc, char* argv[]) {
    CliArgs args;
    if (!ParseCommandLine(argc, argv, args))
        return 1;
    if (args.server_host.empty())   // --help
        return 0;

    // Mirror log entries to stderr in real time
    Logger::SetCallback([](const LogEntry& e) {
        static const char* tags[] = { "DBG", "INF", "WRN", "ERR" };
        int idx = static_cast<int>(e.level);
        if (idx < 0 || idx > 3) idx = 3;
        fprintf(stderr, "%s [%s] %s\n",
                e.timestamp.c_str(), tags[idx], e.message.c_str());
    });

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    try {
        ssh_proxy::Connect connect(
            args.server_host,
            args.username,
            args.password,
            args.server_port,
            args.forward_port,
            args.connect_timeout_ms,
            args.keepalive_interval_ms,
            args.log_level);

        g_connect = &connect;

        // Block until Cancel() is called (Ctrl-C) or the session drops
        while (connect.IsConnected()) {
            Sleep(500);
        }

        g_connect = nullptr;

    } catch (const std::exception& e) {
        fprintf(stderr, "Fatal: %s\n", e.what());
        fprintf(stderr, "%s", ssh_proxy::GetLog().c_str());
        return 1;
    }

    return 0;
}
