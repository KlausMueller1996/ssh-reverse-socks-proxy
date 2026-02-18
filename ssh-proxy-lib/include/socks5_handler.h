#pragma once
#include "common.h"
#include <string>

// SOCKS5 constants (RFC 1928)
namespace Socks5 {

static constexpr uint8_t VERSION = 0x05;

// Auth methods
static constexpr uint8_t AUTH_NONE = 0x00;
static constexpr uint8_t AUTH_NO_ACCEPTABLE = 0xFF;

// Commands
static constexpr uint8_t CMD_CONNECT = 0x01;

// Address types
static constexpr uint8_t ATYP_IPV4   = 0x01;
static constexpr uint8_t ATYP_DOMAIN = 0x03;
static constexpr uint8_t ATYP_IPV6   = 0x04;

// Reply codes
static constexpr uint8_t REP_SUCCESS               = 0x00;
static constexpr uint8_t REP_GENERAL_FAILURE        = 0x01;
static constexpr uint8_t REP_CONNECTION_NOT_ALLOWED  = 0x02;
static constexpr uint8_t REP_NETWORK_UNREACHABLE     = 0x03;
static constexpr uint8_t REP_HOST_UNREACHABLE        = 0x04;
static constexpr uint8_t REP_CONNECTION_REFUSED       = 0x05;
static constexpr uint8_t REP_TTL_EXPIRED              = 0x06;
static constexpr uint8_t REP_COMMAND_NOT_SUPPORTED    = 0x07;
static constexpr uint8_t REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

// Parsed connect request
struct ConnectRequest {
    uint8_t     atyp;
    std::string host;       // For ATYP_DOMAIN or string form of IP
    uint8_t     ipv4[4];    // For ATYP_IPV4
    uint8_t     ipv6[16];   // For ATYP_IPV6
    uint16_t    port;
};

// Parse the method selection message (VER + NMETHODS + METHODS).
// Returns bytes consumed, or 0 if incomplete, or -1 on error.
// Sets supports_no_auth if AUTH_NONE is offered.
int ParseMethodRequest(const uint8_t* data, size_t len, bool& supports_no_auth);

// Build method selection response (VER + METHOD).
ByteBuffer BuildMethodResponse(uint8_t method);

// Parse the CONNECT request (VER + CMD + RSV + ATYP + DST.ADDR + DST.PORT).
// Returns bytes consumed, or 0 if incomplete, or -1 on error.
int ParseConnectRequest(const uint8_t* data, size_t len, ConnectRequest& out);

// Build connect reply.
// bind_addr/bind_port are the bound address (usually 0.0.0.0:0).
ByteBuffer BuildConnectReply(uint8_t reply_code,
                             uint8_t atyp = ATYP_IPV4,
                             const uint8_t* bind_addr = nullptr,
                             uint16_t bind_port = 0);

// Map a Windows socket error to a SOCKS5 reply code.
uint8_t ErrorCodeToSocks5Reply(ErrorCode ec);

} // namespace Socks5
