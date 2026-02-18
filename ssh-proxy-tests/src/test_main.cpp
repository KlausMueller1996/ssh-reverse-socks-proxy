#include <gtest/gtest.h>
#include <winsock2.h>
#include <windows.h>

// Global setup: initialise Winsock before any test runs.
// libssh2_init is called inside ssh_proxy::Connect; tests that exercise
// it directly do so via the Connect constructor.
int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();

    WSACleanup();
    return result;
}
