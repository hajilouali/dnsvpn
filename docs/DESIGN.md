# DNS-VPN — Design

A VPN whose data plane rides entirely on DNS (UDP/53). Intended for the case where
normal internet is blocked but recursive DNS resolvers are still reachable and can
reach our authoritative server. Goal: higher throughput than `dnstt` / `MasterDnsVPN`
by using **many recursive resolvers in parallel** with a large in-flight window.

## 1. Why it can be faster

A classic DNS tunnel (dnstt) is essentially one query → one answer at a time against a
single resolver. Throughput is bounded by `window / RTT` of that one path.

We widen the pipe on three axes:

1. **Resolver fan-out.** The client talks to a *pool* of public recursive resolvers
   (8.8.8.8, 1.1.1.1, 9.9.9.9, 8.26.56.26, …). They all recurse to the *same*
   authoritative server (our tunnel subdomain). N resolvers ≈ N independent paths.
2. **Deep in-flight window.** Many queries outstanding at once per resolver. DNS is
   stateless request/response, so parallelism is just "more queries before the first
   answer returns".
3. **Pull-based downstream.** The server cannot push over DNS, so the client keeps a
   bank of outstanding *poll* queries; the server fills their answers with queued
   downstream bytes. Downstream bandwidth ≈ (outstanding polls) × (answer size) / RTT.

Reliability/ordering is **not** done by DNS. We run a reliable datagram transport
(KCP) + stream mux (smux) on top of an unreliable datagram abstraction, exactly the
"Turbo Tunnel" pattern. Each KCP datagram is carried inside one DNS query (upstream)
or one DNS answer (downstream). Packets lost on a bad resolver are retransmitted by
KCP, optionally duplicated across two resolvers for lossy paths.

```
app TCP  ──SOCKS5──▶  smux stream  ──▶  KCP (ARQ, window, congestion)
                                          │ 1 KCP segment = 1 datagram
                                          ▼
                              DNS datagram codec  (QNAME labels ⇄ answer RDATA)
                                          │
                                          ▼
                       resolver dispatcher: pick resolver, keep W in flight
                                          │  (public recursives, UDP/53)
                                          ▼
                 authoritative server for t.example.com  (our Go server, UDP/53)
```

## 2. DNS encoding

- **Tunnel zone:** one delegated subdomain, e.g. `t.example.com`, with `NS` → our server
  and the server's `A` record. The client only ever asks *recursive* resolvers for names
  under this zone; they recurse to us.
- **Upstream (client→server):** payload is base32 (RFC4648, no padding, lowercase) packed
  into QNAME labels: `<b32chunk>.<b32chunk>….<clienttag>.t.example.com`. Each label ≤ 63,
  total name ≤ 255, so useful upstream payload per query ≈ 100–140 bytes depending on the
  zone length. Short zones matter.
- **Downstream (server→client):** answer carries payload in record RDATA. We negotiate the
  best record type per resolver at startup (MTU probe):
  - `TXT` — up to ~255 bytes per string, multiple strings; easy, widely allowed.
  - `NULL` / `CNAME` chains — more bytes, less widely allowed.
  - `EDNS0` advertised UDP size (≈1232–4096) lets a single answer carry far more.
  The server picks the largest shape each resolver reliably returns.
- **Caching defeat:** every query embeds a monotonically increasing nonce, so resolvers
  never serve a cached answer.

## 3. Security

- **Noise `NK` handshake** (client knows server's static public key) → forward secrecy +
  server authentication. All tunnel datagrams are encrypted/authenticated with the
  resulting ChaCha20-Poly1305 keys. A passive observer on port 53 sees only DNS.
- **Per-user auth:** after the Noise handshake the client presents a user token. The server
  checks it against the SQLite user table and enforces per-user limits (quota, expiry,
  concurrent sessions, speed cap).

## 4. Server components

- `engine` — authoritative UDP/53 listener; demux by client tag; per-session KCP/smux;
  bridges smux streams to the open internet (acts as the exit).
- `store` — pure-Go SQLite: users, tokens, quota/expiry/caps, live & historical stats.
- `admin` — HTTP(S) web panel: login, CRUD users, set limits, view live sessions and
  traffic. REST API + embedded static UI (`server/web`).

## 5. Clients

- `client/core` — the tunnel client library (handshake, dispatcher, KCP/smux).
- `client/socks` — local SOCKS5 listener that funnels app traffic into the tunnel.
- Targets: Linux, Windows (same CLI binary), Android (gomobile `.aar` wrapping `core`,
  thin Kotlin UI; or Termux CLI build as a fallback).

## 6. Build order (local first, then deploy via GitHub)

1. `dnswire` — DNS message + base32-label codec (+ tests).
2. `proto` — framing, datagram format, constants.
3. `dnsnet` — the `net.PacketConn` that carries datagrams over DNS (client & server ends).
4. `dispatcher` — multi-resolver pool, in-flight window, latency/loss scoring, duplication.
5. `securechan` — Noise handshake + AEAD.
6. `engine` + `store` + `admin` — server.
7. clients.
8. local end-to-end echo on 127.0.0.1:5353, then real test on a provided server (port 53).

## 7. Dependencies (all pure-Go, cross-compile clean)

- `github.com/xtaci/kcp-go/v5`, `github.com/xtaci/smux` — reliable transport + mux.
- `github.com/flynn/noise` — Noise handshakes.
- `golang.org/x/net/dns/dnsmessage` — DNS wire codec.
- `modernc.org/sqlite` — CGO-free SQLite.
