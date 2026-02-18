#include <gtest/gtest.h>
#include "socks5_handler.h"
#include <cstring>

// ── ParseMethodRequest ────────────────────────────────────────────────────────

TEST(Socks5ParseMethod, IncompleteOneByteReturnsZero) {
    uint8_t data[] = {0x05};
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 1, ok), 0);
}

TEST(Socks5ParseMethod, IncompleteMethodsReturnsZero) {
    uint8_t data[] = {0x05, 0x02, 0x00}; // claims 2 methods, only 1 present
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 3, ok), 0);
}

TEST(Socks5ParseMethod, BadVersionReturnsMinusOne) {
    uint8_t data[] = {0x04, 0x01, 0x00};
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 3, ok), -1);
}

TEST(Socks5ParseMethod, NoAuthOfferedSetsFlag) {
    uint8_t data[] = {0x05, 0x01, 0x00}; // 1 method: NO_AUTH
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 3, ok), 3);
    EXPECT_TRUE(ok);
}

TEST(Socks5ParseMethod, MultipleMethodsWithNoAuth) {
    uint8_t data[] = {0x05, 0x03, 0x02, 0x01, 0x00}; // GSSAPI, USERNAME_PW, NO_AUTH
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 5, ok), 5);
    EXPECT_TRUE(ok);
}

TEST(Socks5ParseMethod, NoAuthAbsentClearsFlag) {
    uint8_t data[] = {0x05, 0x02, 0x01, 0x02}; // GSSAPI, USERNAME_PW only
    bool ok = true;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 4, ok), 4);
    EXPECT_FALSE(ok);
}

TEST(Socks5ParseMethod, ZeroMethodsConsumedCorrectly) {
    uint8_t data[] = {0x05, 0x00};
    bool ok = false;
    EXPECT_EQ(Socks5::ParseMethodRequest(data, 2, ok), 2);
    EXPECT_FALSE(ok);
}

// ── BuildMethodResponse ───────────────────────────────────────────────────────

TEST(Socks5BuildMethod, AcceptNoAuth) {
    auto buf = Socks5::BuildMethodResponse(Socks5::AUTH_NONE);
    ASSERT_EQ(buf.size(), 2u);
    EXPECT_EQ(buf[0], uint8_t{0x05});
    EXPECT_EQ(buf[1], uint8_t{0x00});
}

TEST(Socks5BuildMethod, RejectNoAcceptable) {
    auto buf = Socks5::BuildMethodResponse(Socks5::AUTH_NO_ACCEPTABLE);
    ASSERT_EQ(buf.size(), 2u);
    EXPECT_EQ(buf[0], uint8_t{0x05});
    EXPECT_EQ(buf[1], uint8_t{0xFF});
}

// ── ParseConnectRequest ───────────────────────────────────────────────────────

TEST(Socks5ParseConnect, IncompleteReturnsZero) {
    uint8_t data[] = {0x05, 0x01, 0x00}; // missing ATYP
    Socks5::ConnectRequest req{};
    EXPECT_EQ(Socks5::ParseConnectRequest(data, 3, req), 0);
}

TEST(Socks5ParseConnect, BadVersionReturnsMinusOne) {
    uint8_t data[] = {0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x1F, 0x90};
    Socks5::ConnectRequest req{};
    EXPECT_EQ(Socks5::ParseConnectRequest(data, 10, req), -1);
}

TEST(Socks5ParseConnect, UnknownAtypReturnsMinusOne) {
    uint8_t data[] = {0x05, 0x01, 0x00, 0x99, 1, 2, 3, 4, 0x1F, 0x90};
    Socks5::ConnectRequest req{};
    EXPECT_EQ(Socks5::ParseConnectRequest(data, 10, req), -1);
}

TEST(Socks5ParseConnect, IPv4ParsedCorrectly) {
    // VER=5 CMD=CONNECT RSV=0 ATYP=IPv4 addr=192.168.1.1 port=8080
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x1F, 0x90};
    Socks5::ConnectRequest req{};
    int consumed = Socks5::ParseConnectRequest(data, 10, req);
    EXPECT_EQ(consumed, 10);
    EXPECT_EQ(req.atyp, uint8_t{Socks5::ATYP_IPV4});
    EXPECT_EQ(req.port, uint16_t{8080});
    EXPECT_STREQ(req.host.c_str(), "192.168.1.1");
    EXPECT_EQ(req.ipv4[0], uint8_t{192});
    EXPECT_EQ(req.ipv4[3], uint8_t{1});
}

TEST(Socks5ParseConnect, IPv4IncompleteReturnsZero) {
    uint8_t data[] = {0x05, 0x01, 0x00, 0x01, 192, 168}; // addr truncated
    Socks5::ConnectRequest req{};
    EXPECT_EQ(Socks5::ParseConnectRequest(data, 6, req), 0);
}

TEST(Socks5ParseConnect, DomainParsedCorrectly) {
    // VER CMD RSV ATYP len  e  x  a  m  p  l  e  .  c  o  m  port(80)
    uint8_t data[] = {0x05, 0x01, 0x00, 0x03,
                      11, 'e','x','a','m','p','l','e','.','c','o','m',
                      0x00, 0x50};
    Socks5::ConnectRequest req{};
    int consumed = Socks5::ParseConnectRequest(data, sizeof(data), req);
    EXPECT_EQ(consumed, static_cast<int>(sizeof(data)));
    EXPECT_EQ(req.atyp, uint8_t{Socks5::ATYP_DOMAIN});
    EXPECT_STREQ(req.host.c_str(), "example.com");
    EXPECT_EQ(req.port, uint16_t{80});
}

TEST(Socks5ParseConnect, DomainIncompleteReturnsZero) {
    uint8_t data[] = {0x05, 0x01, 0x00, 0x03, 11, 'e'}; // domain truncated
    Socks5::ConnectRequest req{};
    EXPECT_EQ(Socks5::ParseConnectRequest(data, 6, req), 0);
}

// ── BuildConnectReply ─────────────────────────────────────────────────────────

TEST(Socks5BuildReply, SuccessReplyStructure) {
    auto buf = Socks5::BuildConnectReply(Socks5::REP_SUCCESS);
    ASSERT_EQ(buf.size(), 10u); // VER REP RSV ATYP ADDR(4) PORT(2)
    EXPECT_EQ(buf[0], uint8_t{0x05});
    EXPECT_EQ(buf[1], uint8_t{Socks5::REP_SUCCESS});
    EXPECT_EQ(buf[2], uint8_t{0x00}); // RSV
    EXPECT_EQ(buf[3], uint8_t{Socks5::ATYP_IPV4});
}

TEST(Socks5BuildReply, FailureReplyCode) {
    auto buf = Socks5::BuildConnectReply(Socks5::REP_CONNECTION_REFUSED);
    ASSERT_GE(buf.size(), 2u);
    EXPECT_EQ(buf[1], uint8_t{Socks5::REP_CONNECTION_REFUSED});
}

TEST(Socks5BuildReply, WithBindAddress) {
    uint8_t addr[4] = {10, 0, 0, 1};
    auto buf = Socks5::BuildConnectReply(Socks5::REP_SUCCESS, Socks5::ATYP_IPV4, addr, 12345);
    ASSERT_EQ(buf.size(), 10u);
    EXPECT_EQ(buf[4], uint8_t{10});
    EXPECT_EQ(buf[5], uint8_t{0});
    EXPECT_EQ(buf[6], uint8_t{0});
    EXPECT_EQ(buf[7], uint8_t{1});
    EXPECT_EQ(buf[8], uint8_t{(12345 >> 8) & 0xFF});
    EXPECT_EQ(buf[9], uint8_t{12345 & 0xFF});
}

// ── ErrorCodeToSocks5Reply ────────────────────────────────────────────────────

TEST(Socks5ErrorMapping, SuccessMapsToSuccess) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::Success),
              uint8_t{Socks5::REP_SUCCESS});
}

TEST(Socks5ErrorMapping, ConnectionRefusedMaps) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::ConnectionRefused),
              uint8_t{Socks5::REP_CONNECTION_REFUSED});
}

TEST(Socks5ErrorMapping, NetworkUnreachableMaps) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::NetworkUnreachable),
              uint8_t{Socks5::REP_NETWORK_UNREACHABLE});
}

TEST(Socks5ErrorMapping, HostUnreachableMaps) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::HostUnreachable),
              uint8_t{Socks5::REP_HOST_UNREACHABLE});
}

TEST(Socks5ErrorMapping, TimeoutMapsTtlExpired) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::ConnectionTimeout),
              uint8_t{Socks5::REP_TTL_EXPIRED});
}

TEST(Socks5ErrorMapping, GenericErrorMapsToGeneralFailure) {
    EXPECT_EQ(Socks5::ErrorCodeToSocks5Reply(ErrorCode::SocketError),
              uint8_t{Socks5::REP_GENERAL_FAILURE});
}
