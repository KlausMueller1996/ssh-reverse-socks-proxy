#include <gtest/gtest.h>
#include "socks5_session.h"
#include "socks5_handler.h"
#include <memory>
#include <vector>

// ── FakeChannel ───────────────────────────────────────────────────────────────
// Feeds scripted read chunks in order and captures all writes.
class FakeChannel : public IChannel {
public:
    std::vector<std::vector<uint8_t>> chunks;  // queued read payloads
    size_t chunk_idx = 0;
    std::vector<uint8_t> written;
    bool eof_sent   = false;
    bool was_closed = false;

    ErrorCode Read(uint8_t* buf, size_t len, size_t& bytes_read) override {
        if (chunk_idx >= chunks.size()) {
            bytes_read = 0;
            return ErrorCode::Success; // EOF
        }
        const auto& chunk = chunks[chunk_idx++];
        bytes_read = (std::min)(len, chunk.size());
        if (bytes_read > 0)
            memcpy(buf, chunk.data(), bytes_read);
        return ErrorCode::Success;
    }

    ErrorCode Write(const uint8_t* buf, size_t len) override {
        written.insert(written.end(), buf, buf + len);
        return ErrorCode::Success;
    }

    void SendEof() override { eof_sent   = true; }
    void Close()   override { was_closed = true; }
    bool IsEof()   const override { return chunk_idx >= chunks.size(); }
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::vector<uint8_t> MethodRequest(std::initializer_list<uint8_t> methods) {
    std::vector<uint8_t> msg = {0x05, static_cast<uint8_t>(methods.size())};
    msg.insert(msg.end(), methods.begin(), methods.end());
    return msg;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

TEST(Socks5Session, MethodNegotiationAcceptsNoAuth) {
    auto ch = std::make_unique<FakeChannel>();
    FakeChannel* raw = ch.get();

    // Read 1: method request with NO_AUTH
    // Read 2: empty (EOF) — session closes after sending method response
    raw->chunks = {
        MethodRequest({0x00}),
        {}
    };

    auto session = std::make_shared<Socks5Session>(std::move(ch));
    session->Start();

    // Method response: {VER=5, METHOD=0 (AUTH_NONE)}
    ASSERT_GE(raw->written.size(), 2u);
    EXPECT_EQ(raw->written[0], uint8_t{0x05});
    EXPECT_EQ(raw->written[1], uint8_t{0x00});
}

TEST(Socks5Session, MethodNegotiationRejectsIfNoAuthAbsent) {
    auto ch = std::make_unique<FakeChannel>();
    FakeChannel* raw = ch.get();

    // GSSAPI + USERNAME_PW, but no NO_AUTH
    raw->chunks = {MethodRequest({0x01, 0x02})};

    auto session = std::make_shared<Socks5Session>(std::move(ch));
    session->Start();

    ASSERT_GE(raw->written.size(), 2u);
    EXPECT_EQ(raw->written[0], uint8_t{0x05});
    EXPECT_EQ(raw->written[1], uint8_t{0xFF}); // AUTH_NO_ACCEPTABLE
}

TEST(Socks5Session, BadSocksVersionClosesSession) {
    auto ch = std::make_unique<FakeChannel>();
    FakeChannel* raw = ch.get();

    // SOCKS4 version byte — should be rejected
    raw->chunks = {{0x04, 0x01, 0x00}};

    auto session = std::make_shared<Socks5Session>(std::move(ch));
    session->Start();

    ASSERT_GE(raw->written.size(), 2u);
    EXPECT_EQ(raw->written[1], uint8_t{0xFF}); // AUTH_NO_ACCEPTABLE
}

TEST(Socks5Session, MalformedConnectRequestSendsFailure) {
    auto ch = std::make_unique<FakeChannel>();
    FakeChannel* raw = ch.get();

    // Read 1: valid NO_AUTH method selection
    // Read 2: SOCKS4 version in the CONNECT request → parse error
    raw->chunks = {
        MethodRequest({0x00}),
        {0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x1F, 0x90}
    };

    auto session = std::make_shared<Socks5Session>(std::move(ch));
    session->Start();

    // written = method_response(2) + connect_reply(10)
    ASSERT_GE(raw->written.size(), 4u);
    // Method response bytes
    EXPECT_EQ(raw->written[0], uint8_t{0x05});
    EXPECT_EQ(raw->written[1], uint8_t{0x00}); // AUTH_NONE accepted
    // Connect reply REP field is at offset 3 (VER REP RSV ...)
    EXPECT_EQ(raw->written[3], uint8_t{Socks5::REP_GENERAL_FAILURE});
}

TEST(Socks5Session, PartialMethodDataWaitsForMore) {
    auto ch = std::make_unique<FakeChannel>();
    FakeChannel* raw = ch.get();

    // Split the method request across two reads
    raw->chunks = {
        {0x05},           // only VER — incomplete
        {0x01, 0x00},     // NMETHODS=1 METHOD=NO_AUTH — completes the message
        {}                // EOF after method response
    };

    auto session = std::make_shared<Socks5Session>(std::move(ch));
    session->Start();

    ASSERT_GE(raw->written.size(), 2u);
    EXPECT_EQ(raw->written[0], uint8_t{0x05});
    EXPECT_EQ(raw->written[1], uint8_t{0x00}); // AUTH_NONE accepted
}

