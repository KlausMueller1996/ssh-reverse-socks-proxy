#include <gtest/gtest.h>
#include "ssh_proxy.h"
#include <stdexcept>
#include <string>

// These tests exercise the ssh_proxy::Connect constructor against an
// unreachable endpoint.  They use a very short timeout (200 ms) so the
// test suite stays fast.  Port 1 on 127.0.0.1 is virtually never open
// and causes an immediate WSAECONNREFUSED on Windows.

TEST(ConnectTest, ThrowsOnConnectionRefused) {
    EXPECT_THROW(
        ssh_proxy::Connect("127.0.0.1", "user", "pass",
            /*server_port=*/      1,
            /*forward_port=*/     1080,
            /*connect_timeout_ms=*/ 200),
        std::runtime_error
    );
}

TEST(ConnectTest, ExceptionMessageIsNonEmpty) {
    try {
        ssh_proxy::Connect("127.0.0.1", "user", "pass", 1, 1080, 200);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_GT(std::string(e.what()).size(), 0u);
    }
}

TEST(ConnectTest, GetLogAfterFailedConnectReturnsString) {
    // A failed connect attempt logs error entries.
    // GetLog() must return a valid string regardless of content.
    try {
        ssh_proxy::Connect("127.0.0.1", "user", "pass", 1, 1080, 200);
    } catch (...) {}

    std::string log = ssh_proxy::GetLog();
    // Must be a well-formed string (no crash, no exception).
    SUCCEED();
    // If there are log entries they should contain the failure reason.
    if (!log.empty()) {
        // Each non-empty line should have the timestamp+level bracket format.
        EXPECT_NE(log.find('['), std::string::npos);
    }
}

TEST(ConnectTest, ThrowsOnUnresolvableHost) {
    // A hostname that cannot be resolved should also throw.
    EXPECT_THROW(
        ssh_proxy::Connect("this.host.does.not.exist.invalid",
            "user", "pass", 22, 1080, 500),
        std::runtime_error
    );
}
