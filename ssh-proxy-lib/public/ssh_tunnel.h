#pragma once
#include <cstdint>
#include <string>

namespace ssh_tunnel {

// Baut einen SSH Local Port Forward auf:
//   lauscht auf 127.0.0.1:local_port()  (ephemeraler Port, Single-Accept)
//   → öffnet direct_tcpip-Kanal zu target_host:target_port (Sicht des SSH-Servers)
//   → relay: lokaler Socket ↔ SSH-Kanal
//
// Single-Accept: akzeptiert genau eine eingehende TCP-Verbindung.
// Danach kein weiteres Accept — Retry erzeugt eine neue DirectForward-Instanz.
//
// Tunnel-Drop-Propagation: Bricht der SSH-Kanal ab, schließt DirectForward den
// lokalen Socket. NetworkClient::listen() bekommt POLLHUP und beendet die Sitzung.
//
// Konstruktor wirft std::runtime_error bei Fehler (analog ssh_proxy::Connect).
// Kein Reconnect; Retry liegt in main.cpp.
class DirectForward {
public:
    DirectForward(
        std::string  ssh_host,
        std::string  username,
        std::string  password,
        uint16_t     target_port,
        std::string  target_host        = "127.0.0.1",
        uint16_t     ssh_port           = 22,
        uint32_t     connect_timeout_ms = 10000
    );
    ~DirectForward();

    DirectForward(const DirectForward&)            = delete;
    DirectForward& operator=(const DirectForward&) = delete;

    // Gibt den lokalen Port in HOST byte order zurück.
    // Aufrufer muss htons() anwenden bevor er den Wert in ConnectionEndpoint speichert.
    uint16_t local_port() const;

    bool is_alive() const;
    void cancel();

    // Pimpl — exposed so relay_proc (free function) can access internals.
    struct Impl;

private:
    Impl* m_impl;
};

} // namespace ssh_tunnel
