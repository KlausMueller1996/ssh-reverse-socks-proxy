#include <gtest/gtest.h>
#include "logger.h"
#include <atomic>
#include <string>

class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::SetMinLevel(ssh_proxy::LogLevel::Debug);
        Logger::SetCallback(nullptr);
    }
    void TearDown() override {
        Logger::SetCallback(nullptr);
    }
};

TEST_F(LoggerTest, CallbackFiredForEachEntry) {
    std::atomic<int> count{0};
    Logger::SetCallback([&count](const LogEntry&) { ++count; });
    Logger::Info("test_cb_fired_1");
    Logger::Info("test_cb_fired_2");
    EXPECT_EQ(count.load(), 2);
}

TEST_F(LoggerTest, CallbackReceivesCorrectLevel) {
    LogEntry captured;
    Logger::SetCallback([&captured](const LogEntry& e) { captured = e; });
    Logger::Warn("test_cb_level_check");
    EXPECT_EQ(captured.level, ssh_proxy::LogLevel::Warn);
    EXPECT_STREQ(captured.message.c_str(), "test_cb_level_check");
}

TEST_F(LoggerTest, MinLevelFiltersCallback) {
    Logger::SetMinLevel(ssh_proxy::LogLevel::Error);
    std::atomic<bool> got_info{false};
    std::atomic<bool> got_error{false};
    Logger::SetCallback([&](const LogEntry& e) {
        if (e.level == ssh_proxy::LogLevel::Info)  got_info  = true;
        if (e.level == ssh_proxy::LogLevel::Error) got_error = true;
    });
    Logger::Info("should_be_filtered");
    Logger::Error("should_pass_through");
    EXPECT_FALSE(got_info.load());
    EXPECT_TRUE(got_error.load());
}

TEST_F(LoggerTest, SnapshotContainsLoggedMessage) {
    const std::string unique_msg = "test_snapshot_unique_msg_9f3a";
    Logger::Info("%s", unique_msg.c_str());
    auto snap = Logger::Snapshot();
    bool found = false;
    for (const auto& e : snap) {
        if (e.message == unique_msg) { found = true; break; }
    }
    EXPECT_TRUE(found);
}

TEST_F(LoggerTest, BufferCappedAt100) {
    // Add more than 100 entries; buffer must not grow beyond the cap.
    for (int i = 0; i < 110; ++i)
        Logger::Debug("cap_test_%d", i);
    auto snap = Logger::Snapshot();
    EXPECT_LE(snap.size(), 100u);
}

TEST_F(LoggerTest, GetLogContainsFormattedEntry) {
    const std::string unique_msg = "test_getlog_format_7b2c";
    Logger::Error("%s", unique_msg.c_str());
    std::string log = ssh_proxy::GetLog();
    EXPECT_NE(log.find(unique_msg), std::string::npos);
    EXPECT_NE(log.find("[ERROR]"), std::string::npos);
}

TEST_F(LoggerTest, ClearCallbackOnNull) {
    std::atomic<int> count{0};
    Logger::SetCallback([&count](const LogEntry&) { ++count; });
    Logger::SetCallback(nullptr);
    Logger::Info("should_not_fire_after_clear");
    EXPECT_EQ(count.load(), 0);
}

TEST_F(LoggerTest, TimestampFormatPresent) {
    LogEntry captured;
    Logger::SetCallback([&captured](const LogEntry& e) { captured = e; });
    Logger::Info("ts_format_test");
    // "YYYY-MM-DD HH:MM:SS.mmm" = 23 characters
    ASSERT_EQ(captured.timestamp.size(), 23u);
    EXPECT_EQ(captured.timestamp[4],  '-');
    EXPECT_EQ(captured.timestamp[7],  '-');
    EXPECT_EQ(captured.timestamp[10], ' ');
    EXPECT_EQ(captured.timestamp[13], ':');
    EXPECT_EQ(captured.timestamp[16], ':');
    EXPECT_EQ(captured.timestamp[19], '.');
}
