#include <gtest/gtest.h>
#include "config.h"
#include <string>
#include <vector>

// Test fixture that safely builds argv arrays pointing into stable strings.
class ParseCLITest : public ::testing::Test {
protected:
    bool Parse(std::initializer_list<const char*> arg_list, CliArgs& args) {
        m_strings.assign(arg_list.begin(), arg_list.end());
        m_ptrs.clear();
        for (auto& s : m_strings)
            m_ptrs.push_back(const_cast<char*>(s.c_str()));
        return ParseCommandLine(static_cast<int>(m_ptrs.size()), m_ptrs.data(), args);
    }

private:
    std::vector<std::string> m_strings;
    std::vector<char*>       m_ptrs;
};

TEST_F(ParseCLITest, AllRequiredArgsSucceeds) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "myhost",
                       "--username", "bob", "--password", "s3cr3t"}, args));
    EXPECT_EQ(args.server_host,           "myhost");
    EXPECT_EQ(args.username,              "bob");
    EXPECT_EQ(args.password,              "s3cr3t");
    EXPECT_EQ(args.server_port,           uint16_t{22});
    EXPECT_EQ(args.forward_port,          uint16_t{1080});
    EXPECT_EQ(args.connect_timeout_ms,    uint32_t{10000});
    EXPECT_EQ(args.keepalive_interval_ms, uint32_t{30000});
    EXPECT_EQ(args.log_level,             ssh_proxy::LogLevel::Info);
}

TEST_F(ParseCLITest, MissingServerReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--username", "u", "--password", "p"}, args));
}

TEST_F(ParseCLITest, MissingUsernameReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--password", "p"}, args));
}

TEST_F(ParseCLITest, MissingPasswordReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u"}, args));
}

TEST_F(ParseCLITest, HelpReturnsTrueWithEmptyHost) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--help"}, args));
    EXPECT_TRUE(args.server_host.empty());
}

TEST_F(ParseCLITest, ShortHelpFlag) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "-h"}, args));
    EXPECT_TRUE(args.server_host.empty());
}

TEST_F(ParseCLITest, PortParsed) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--port", "2222"}, args));
    EXPECT_EQ(args.server_port, uint16_t{2222});
}

TEST_F(ParseCLITest, InvalidPortZeroReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u",
                        "--password", "p", "--port", "0"}, args));
}

TEST_F(ParseCLITest, InvalidPortTooLargeReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u",
                        "--password", "p", "--port", "99999"}, args));
}

TEST_F(ParseCLITest, ForwardPortLongFlag) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--forward-port", "9090"}, args));
    EXPECT_EQ(args.forward_port, uint16_t{9090});
}

TEST_F(ParseCLITest, ForwardPortShortFlag) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "-f", "8888"}, args));
    EXPECT_EQ(args.forward_port, uint16_t{8888});
}

TEST_F(ParseCLITest, ShortUsernameFlag) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "-u", "alice",
                       "--password", "p"}, args));
    EXPECT_EQ(args.username, "alice");
}

TEST_F(ParseCLITest, ShortPasswordFlag) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "-p", "pw"}, args));
    EXPECT_EQ(args.password, "pw");
}

TEST_F(ParseCLITest, LogLevelDebug) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--log-level", "debug"}, args));
    EXPECT_EQ(args.log_level, ssh_proxy::LogLevel::Debug);
}

TEST_F(ParseCLITest, LogLevelWarn) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--log-level", "warn"}, args));
    EXPECT_EQ(args.log_level, ssh_proxy::LogLevel::Warn);
}

TEST_F(ParseCLITest, LogLevelError) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--log-level", "error"}, args));
    EXPECT_EQ(args.log_level, ssh_proxy::LogLevel::Error);
}

TEST_F(ParseCLITest, InvalidLogLevelReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u",
                        "--password", "p", "--log-level", "verbose"}, args));
}

TEST_F(ParseCLITest, UnknownFlagReturnsFalse) {
    CliArgs args;
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u",
                        "--password", "p", "--banana"}, args));
}

TEST_F(ParseCLITest, FlagWithoutValueReturnsFalse) {
    CliArgs args;
    // --password is last with no value following
    EXPECT_FALSE(Parse({"prog", "--server", "h", "--username", "u",
                        "--password"}, args));
}

TEST_F(ParseCLITest, ConnectTimeoutParsed) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--connect-timeout", "5000"}, args));
    EXPECT_EQ(args.connect_timeout_ms, uint32_t{5000});
}

TEST_F(ParseCLITest, KeepaliveIntervalParsed) {
    CliArgs args;
    ASSERT_TRUE(Parse({"prog", "--server", "h", "--username", "u",
                       "--password", "p", "--keepalive-ms", "15000"}, args));
    EXPECT_EQ(args.keepalive_interval_ms, uint32_t{15000});
}
