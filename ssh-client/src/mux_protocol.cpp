#include "mux_protocol.h"
#include "logger.h"
#include <cstring>

FrameCodec::FrameCodec()
    : m_used(0)
{
    m_buffer.resize(FRAME_HEADER_SIZE + FRAME_MAX_PAYLOAD);
}

void FrameCodec::Feed(const uint8_t* data, size_t len, std::vector<Frame>& out_frames) {
    size_t offset = 0;

    while (offset < len) {
        // Copy into accumulation buffer
        size_t avail = len - offset;
        size_t space = m_buffer.size() - m_used;
        size_t to_copy = (std::min)(avail, space);
        memcpy(m_buffer.data() + m_used, data + offset, to_copy);
        m_used += to_copy;
        offset += to_copy;

        // Try to parse complete frames
        while (m_used >= FRAME_HEADER_SIZE) {
            FrameHeader hdr;
            memcpy(&hdr, m_buffer.data(), FRAME_HEADER_SIZE);

            if (hdr.payload_length > FRAME_MAX_PAYLOAD) {
                Logger::Error("Frame payload too large: %u", hdr.payload_length);
                m_used = 0; // discard — protocol error
                return;
            }

            size_t total = FRAME_HEADER_SIZE + hdr.payload_length;
            if (m_used < total)
                break; // need more data

            Frame frame;
            frame.header = hdr;
            if (hdr.payload_length > 0) {
                frame.payload.assign(
                    m_buffer.data() + FRAME_HEADER_SIZE,
                    m_buffer.data() + FRAME_HEADER_SIZE + hdr.payload_length);
            }
            out_frames.push_back(std::move(frame));

            // Shift remaining data
            size_t remaining = m_used - total;
            if (remaining > 0) {
                memmove(m_buffer.data(), m_buffer.data() + total, remaining);
            }
            m_used = remaining;
        }
    }
}

ByteBuffer FrameCodec::Encode(FrameType type, uint8_t flags, uint16_t channel_id,
                               const uint8_t* payload, uint32_t payload_len) {
    ByteBuffer buf(FRAME_HEADER_SIZE + payload_len);
    FrameHeader hdr;
    hdr.type = static_cast<uint8_t>(type);
    hdr.flags = flags;
    hdr.channel_id = channel_id;
    hdr.payload_length = payload_len;
    memcpy(buf.data(), &hdr, FRAME_HEADER_SIZE);
    if (payload_len > 0 && payload) {
        memcpy(buf.data() + FRAME_HEADER_SIZE, payload, payload_len);
    }
    return buf;
}

ByteBuffer FrameCodec::BuildChannelOpen(uint16_t channel_id) {
    return Encode(FrameType::ChannelOpen, 0, channel_id, nullptr, 0);
}

ByteBuffer FrameCodec::BuildChannelOpenAck(uint16_t channel_id) {
    return Encode(FrameType::ChannelOpenAck, 0, channel_id, nullptr, 0);
}

ByteBuffer FrameCodec::BuildChannelRequest(uint16_t channel_id, const uint8_t* data, uint32_t len) {
    return Encode(FrameType::ChannelRequest, 0, channel_id, data, len);
}

ByteBuffer FrameCodec::BuildChannelRequestAck(uint16_t channel_id, const uint8_t* data, uint32_t len) {
    return Encode(FrameType::ChannelRequestAck, 0, channel_id, data, len);
}

ByteBuffer FrameCodec::BuildData(uint16_t channel_id, const uint8_t* data, uint32_t len) {
    return Encode(FrameType::Data, 0, channel_id, data, len);
}

ByteBuffer FrameCodec::BuildChannelClose(uint16_t channel_id, uint8_t flags) {
    return Encode(FrameType::ChannelClose, flags, channel_id, nullptr, 0);
}

ByteBuffer FrameCodec::BuildChannelCloseAck(uint16_t channel_id) {
    return Encode(FrameType::ChannelCloseAck, 0, channel_id, nullptr, 0);
}

ByteBuffer FrameCodec::BuildPing() {
    return Encode(FrameType::Ping, 0, 0, nullptr, 0);
}

ByteBuffer FrameCodec::BuildPong() {
    return Encode(FrameType::Pong, 0, 0, nullptr, 0);
}

ByteBuffer FrameCodec::BuildWindowUpdate(uint16_t channel_id, uint32_t increment) {
    uint8_t payload[4];
    memcpy(payload, &increment, 4);
    return Encode(FrameType::WindowUpdate, 0, channel_id, payload, 4);
}
