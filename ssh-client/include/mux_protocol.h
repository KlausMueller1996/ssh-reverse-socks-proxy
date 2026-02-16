#pragma once
#include "common.h"

// Frame types
enum class FrameType : uint8_t {
    ChannelOpen     = 0x01,
    ChannelOpenAck  = 0x02,
    ChannelRequest  = 0x03,
    ChannelRequestAck = 0x04,
    Data            = 0x05,
    ChannelClose    = 0x06,
    ChannelCloseAck = 0x07,
    Ping            = 0x08,
    Pong            = 0x09,
    WindowUpdate    = 0x0A,
};

// Frame flags
static constexpr uint8_t FRAME_FLAG_FIN = 0x01;
static constexpr uint8_t FRAME_FLAG_RST = 0x02;

// Wire format: 8 bytes, little-endian
static constexpr size_t FRAME_HEADER_SIZE = 8;
static constexpr size_t FRAME_MAX_PAYLOAD = 65536;

#pragma pack(push, 1)
struct FrameHeader {
    uint8_t  type;
    uint8_t  flags;
    uint16_t channel_id;
    uint32_t payload_length;
};
#pragma pack(pop)

static_assert(sizeof(FrameHeader) == FRAME_HEADER_SIZE, "FrameHeader must be 8 bytes");

// A decoded frame: header + payload
struct Frame {
    FrameHeader header;
    ByteBuffer  payload;
};

// Accumulates bytes and emits complete frames.
class FrameCodec {
public:
    FrameCodec();

    // Feed raw bytes. Returns frames decoded so far.
    // Partial frames are buffered internally.
    void Feed(const uint8_t* data, size_t len, std::vector<Frame>& out_frames);

    // Encode a frame into wire bytes.
    static ByteBuffer Encode(FrameType type, uint8_t flags, uint16_t channel_id,
                             const uint8_t* payload, uint32_t payload_len);

    // Convenience builders
    static ByteBuffer BuildChannelOpen(uint16_t channel_id);
    static ByteBuffer BuildChannelOpenAck(uint16_t channel_id);
    static ByteBuffer BuildChannelRequest(uint16_t channel_id, const uint8_t* data, uint32_t len);
    static ByteBuffer BuildChannelRequestAck(uint16_t channel_id, const uint8_t* data, uint32_t len);
    static ByteBuffer BuildData(uint16_t channel_id, const uint8_t* data, uint32_t len);
    static ByteBuffer BuildChannelClose(uint16_t channel_id, uint8_t flags = 0);
    static ByteBuffer BuildChannelCloseAck(uint16_t channel_id);
    static ByteBuffer BuildPing();
    static ByteBuffer BuildPong();
    static ByteBuffer BuildWindowUpdate(uint16_t channel_id, uint32_t increment);

private:
    ByteBuffer m_buffer;
    size_t     m_used;
};
