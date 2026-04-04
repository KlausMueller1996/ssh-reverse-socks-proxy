//////////////////////////////////////////////////////////////////////////////
//
// Socks5Session — per-channel SOCKS5 state machine
//
// PURPOSE
//   Manages the full SOCKS5 lifecycle for one inbound forwarded-tcpip channel:
//   method negotiation → CONNECT request → async TCP connect → relay.
//
// TWO CONCURRENT DATA FLOWS
//   SSH → TCP  PumpSshRead() is called by the SSH I/O thread every loop
//              iteration.  During negotiation states it feeds the state
//              machine; in Relaying state it forwards bytes directly to m_tcp.
//
//   TCP → SSH  StartRelay() arms a TcpConnection read callback on an IOCP
//              worker thread.  That callback calls m_channel->Write(), which
//              (off the I/O thread) posts to the per-channel write queue and
//              returns without blocking.
//
// OWNERSHIP AND CYCLE PREVENTION
//   Socks5Session owns m_tcp (shared_ptr<TcpConnection>).  All m_tcp
//   callbacks capture weak_ptr<Socks5Session> to prevent the cycle
//   session→m_tcp→callback→session that would block destruction.
//
// THREAD SAFETY OF Close()
//   m_state.exchange(State::Closed) ensures Close() executes exactly once
//   regardless of which thread — IOCP or SSH I/O — arrives first.
//
//////////////////////////////////////////////////////////////////////////////

#include "socks5_session.h"
#include "logger.h"

Socks5Session::Socks5Session(std::unique_ptr<IChannel> channel)
    : m_channel(std::move(channel))
    , m_tcp(std::make_shared<TcpConnection>())
{}

Socks5Session::~Socks5Session()
{
    Close();
}

//
// ── Start ─────────────────────────────────────────────────────────────────────
//
// Intentionally empty.  The full lifecycle — method negotiation, CONNECT
// request, TCP connect, relay — is driven entirely by PumpSshRead() on the
// SSH I/O thread.  Start() exists so callers have a uniform activation point
// if startup work is ever needed.
//

void Socks5Session::Start()
{
    // Full lifecycle (handshake + relay) is driven non-blocking by PumpSshRead().
}

//
// ── OnChannelData ─────────────────────────────────────────────────────────────
//
// Appends newly arrived channel bytes to m_inbound_buf then dispatches to the
// state handler.  Called only in ReadingMethods and ReadingRequest states;
// PumpSshRead forwards directly to m_tcp in Relaying state (bypasses this).
//

void Socks5Session::OnChannelData(const uint8_t* data, size_t len)
{
    m_inbound_buf.insert(m_inbound_buf.end(), data, data + len);

    switch (m_state.load()) {
    case State::ReadingMethods:
        HandleMethodNegotiation(m_inbound_buf.data(), m_inbound_buf.size());
        break;
    case State::ReadingRequest:
        HandleConnectRequest(m_inbound_buf.data(), m_inbound_buf.size());
        break;
    default:
        break;
    }
}

//
// ── HandleMethodNegotiation ───────────────────────────────────────────────────
//
// Completes the method-selection exchange.  Rejects the connection if the
// client did not offer AUTH_NONE — we support no-auth only.  On acceptance,
// advances state to ReadingRequest and immediately processes any leftover
// bytes already in m_inbound_buf (client may pipeline the CONNECT request).
//

void Socks5Session::HandleMethodNegotiation(const uint8_t* data, size_t len)
{
    bool supports_no_auth = false;
    int consumed = Socks5::ParseMethodRequest(data, len, supports_no_auth);

    if (consumed == 0) return;  // need more data; PumpSshRead delivers next iteration

    if (consumed < 0 || !supports_no_auth)
    {
        Logger::Warn("SOCKS5: method negotiation failed (no-auth not offered)");
        auto reply = Socks5::BuildMethodResponse(Socks5::AUTH_NO_ACCEPTABLE);
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    m_inbound_buf.erase(m_inbound_buf.begin(), m_inbound_buf.begin() + consumed);
    auto reply = Socks5::BuildMethodResponse(Socks5::AUTH_NONE);
    m_channel->Write(reply.data(), reply.size());

    m_state.store(State::ReadingRequest);

    // If data was left over in m_inbound_buf, process it immediately.
    if (!m_inbound_buf.empty())
        HandleConnectRequest(m_inbound_buf.data(), m_inbound_buf.size());
}

//
// ── HandleConnectRequest ──────────────────────────────────────────────────────
//
// Parses the CONNECT request and launches the async TCP connect.  An unknown
// address type is caught by ParseConnectRequest (returns -1); an unrecognised
// command would still return the byte count so we can reply before closing.
//

void Socks5Session::HandleConnectRequest(const uint8_t* data, size_t len)
{
    Socks5::ConnectRequest req{};
    int consumed = Socks5::ParseConnectRequest(data, len, req);

    if (consumed == 0) return;  // need more data; PumpSshRead delivers next iteration

    if (consumed < 0)
    {
        Logger::Warn("SOCKS5: malformed connect request");
        auto reply = Socks5::BuildConnectReply(Socks5::REP_GENERAL_FAILURE);
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    // atyp already validated by ParseConnectRequest (returns -1 on unknown type).
    m_inbound_buf.erase(m_inbound_buf.begin(), m_inbound_buf.begin() + consumed);

    Logger::Debug("SOCKS5: CONNECT %s:%u", req.host.c_str(), req.port);
    StartTcpConnect(req);
}

void Socks5Session::StartTcpConnect(const Socks5::ConnectRequest& req)
{
    m_state.store(State::Connecting);

    // Use weak_ptr: TcpConnection must not hold a strong ref back to the session
    // (session owns m_tcp, so that would be a cycle).
    std::weak_ptr<Socks5Session> weak = weak_from_this();
    m_tcp->ConnectAsync(req.host, req.port,
        [weak](ErrorCode connect_ec)
        {
            if (auto self = weak.lock()) self->OnTcpConnected(connect_ec);
        });
    // Errors (DNS failure, socket error) now arrive via the callback above.
}

void Socks5Session::OnTcpConnected(ErrorCode ec)
{
    // This fires on an IOCP worker thread. All m_channel calls go through
    // the post_write / post_io queues and are safe to call here.

    if (ec != ErrorCode::Success)
    {
        Logger::Warn("SOCKS5: target TCP connect failed: %s", ErrorCodeToString(ec));
        auto reply = Socks5::BuildConnectReply(Socks5::ErrorCodeToSocks5Reply(ec));
        m_channel->Write(reply.data(), reply.size());
        Close();
        return;
    }

    // Send SOCKS5 success reply (enqueued → SSH I/O thread drains it).
    auto reply = Socks5::BuildConnectReply(Socks5::REP_SUCCESS);
    m_channel->Write(reply.data(), reply.size());

    m_state.store(State::Relaying);
    StartRelay();
}

void Socks5Session::StartRelay()
{
    // Called from an IOCP thread. Set up the TCP→SSH direction only.
    // The SSH→TCP direction is handled by PumpSshRead(), called by the SSH I/O thread.

    // weak_ptr breaks the ownership cycle: session owns m_tcp (shared_ptr),
    // so m_tcp's callbacks must not hold a strong ref back to the session.
    std::weak_ptr<Socks5Session> weak = weak_from_this();

    m_tcp->StartReading(
        [weak](const uint8_t* data, size_t len)
        {
            if (auto self = weak.lock()) self->m_channel->Write(data, len);
        },
        [weak](ErrorCode)
        {
            if (auto self = weak.lock())
            {
                self->m_channel->SendEof();
                self->Close();
            }
        });
}

bool Socks5Session::PumpSshRead()
{
    // Called on the SSH I/O thread every loop iteration.
    // Drives all states: ReadingMethods, ReadingRequest, Relaying.

    State s = m_state.load();
    if (s == State::Closed) return false;
    if (s == State::Connecting) return true;  // waiting for TCP connect callback

    uint8_t buf[4096];
    size_t bytes_read = 0;
    ErrorCode ec = m_channel->Read(buf, sizeof(buf), bytes_read);

    if (ec == ErrorCode::WouldBlock) return true;  // no data yet, try next iteration

    if (ec != ErrorCode::Success || bytes_read == 0)
    {
        Close();
        return false;
    }

    if (s == State::Relaying)
    {
        m_tcp->Send(buf, bytes_read);
    }
    else
    {
        OnChannelData(buf, bytes_read);
    }

    return m_state.load() != State::Closed;
}

void Socks5Session::Close()
{
    // Atomic exchange ensures Close runs exactly once even if called from both
    // the IOCP thread (TCP close callback) and the SSH I/O thread (PumpSshRead).
    State prev = m_state.exchange(State::Closed);
    if (prev == State::Closed) return;

    m_tcp->Close();
    if (m_channel)
    {
        m_channel->SendEof();
        m_channel->Close();
    }
    Logger::Debug("SOCKS5 session closed");
}
