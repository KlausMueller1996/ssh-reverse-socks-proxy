#include "socks5_handler.h"
#include <cstring>

namespace Socks5 {

int ParseMethodRequest(const uint8_t* data, size_t len, bool& supports_no_auth) {
    supports_no_auth = false;

    if (len < 2) return 0; // incomplete

    if (data[0] != VERSION) return -1;

    uint8_t nmethods = data[1];
    size_t total = 2 + static_cast<size_t>(nmethods);
    if (len < total) return 0; // incomplete

    for (uint8_t i = 0; i < nmethods; ++i) {
        if (data[2 + i] == AUTH_NONE) {
            supports_no_auth = true;
        }
    }

    return static_cast<int>(total);
}

ByteBuffer BuildMethodResponse(uint8_t method) {
    return { VERSION, method };
}

int ParseConnectRequest(const uint8_t* data, size_t len, ConnectRequest& out) {
    // Minimum: VER(1) + CMD(1) + RSV(1) + ATYP(1) + addr(variable) + PORT(2)
    if (len < 4) return 0;

    if (data[0] != VERSION) return -1;

    uint8_t cmd = data[1];
    // uint8_t rsv = data[2]; // reserved
    uint8_t atyp = data[3];
    out.atyp = atyp;

    size_t addr_start = 4;
    size_t addr_len = 0;

    switch (atyp) {
    case ATYP_IPV4:
        addr_len = 4;
        break;
    case ATYP_DOMAIN:
        if (len < 5) return 0;
        addr_len = 1 + static_cast<size_t>(data[4]); // length byte + domain
        break;
    case ATYP_IPV6:
        addr_len = 16;
        break;
    default:
        return -1;
    }

    size_t total = addr_start + addr_len + 2; // +2 for port
    if (len < total) return 0;

    // Parse address
    if (atyp == ATYP_IPV4) {
        memcpy(out.ipv4, data + addr_start, 4);
        char buf[16];
        sprintf_s(buf, "%u.%u.%u.%u", out.ipv4[0], out.ipv4[1], out.ipv4[2], out.ipv4[3]);
        out.host = buf;
    } else if (atyp == ATYP_DOMAIN) {
        uint8_t domain_len = data[addr_start];
        out.host.assign(reinterpret_cast<const char*>(data + addr_start + 1), domain_len);
    } else if (atyp == ATYP_IPV6) {
        memcpy(out.ipv6, data + addr_start, 16);
        // Build IPv6 string
        char buf[48];
        sprintf_s(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            out.ipv6[0], out.ipv6[1], out.ipv6[2], out.ipv6[3],
            out.ipv6[4], out.ipv6[5], out.ipv6[6], out.ipv6[7],
            out.ipv6[8], out.ipv6[9], out.ipv6[10], out.ipv6[11],
            out.ipv6[12], out.ipv6[13], out.ipv6[14], out.ipv6[15]);
        out.host = buf;
    }

    // Port (big-endian)
    size_t port_offset = addr_start + addr_len;
    out.port = (static_cast<uint16_t>(data[port_offset]) << 8) | data[port_offset + 1];

    // Validate command — we only support CONNECT
    if (cmd != CMD_CONNECT) {
        // Still return bytes consumed so caller can send error reply
        return static_cast<int>(total);
    }

    return static_cast<int>(total);
}

ByteBuffer BuildConnectReply(uint8_t reply_code, uint8_t atyp,
                             const uint8_t* bind_addr, uint16_t bind_port) {
    ByteBuffer buf;
    buf.push_back(VERSION);
    buf.push_back(reply_code);
    buf.push_back(0x00); // reserved

    if (atyp == ATYP_IPV4) {
        buf.push_back(ATYP_IPV4);
        if (bind_addr) {
            buf.insert(buf.end(), bind_addr, bind_addr + 4);
        } else {
            buf.insert(buf.end(), 4, 0x00);
        }
    } else if (atyp == ATYP_IPV6) {
        buf.push_back(ATYP_IPV6);
        if (bind_addr) {
            buf.insert(buf.end(), bind_addr, bind_addr + 16);
        } else {
            buf.insert(buf.end(), 16, 0x00);
        }
    } else {
        // Default to IPv4 0.0.0.0
        buf.push_back(ATYP_IPV4);
        buf.insert(buf.end(), 4, 0x00);
    }

    // Port (big-endian)
    buf.push_back(static_cast<uint8_t>(bind_port >> 8));
    buf.push_back(static_cast<uint8_t>(bind_port & 0xFF));

    return buf;
}

uint8_t ErrorCodeToSocks5Reply(ErrorCode ec) {
    switch (ec) {
    case ErrorCode::Success:           return REP_SUCCESS;
    case ErrorCode::NetworkUnreachable: return REP_NETWORK_UNREACHABLE;
    case ErrorCode::HostUnreachable:   return REP_HOST_UNREACHABLE;
    case ErrorCode::ConnectionRefused: return REP_CONNECTION_REFUSED;
    case ErrorCode::ConnectionTimeout: return REP_TTL_EXPIRED;
    default:                           return REP_GENERAL_FAILURE;
    }
}

} // namespace Socks5
