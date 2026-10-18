# dnsvpn

A VPN whose data plane runs entirely over DNS (UDP/53). It is built for the case where
normal internet is blocked but recursive DNS resolvers are still reachable and can reach
an authoritative server you control. It aims to be faster than classic single-resolver
DNS tunnels by fanning queries out across **many recursive resolvers in parallel** and by
auto-discovering and validating usable resolvers on the client.

> Educational / research use. You are responsible for complying with the laws and the
> terms of service that apply to you.

## How it works

```
app ──SOCKS5──▶ smux stream ──▶ KCP (reliable ARQ, window) ──▶ DNS codec
                                                                  │ 1 KCP segment per query/answer
                                                                  ▼
                                         pool of recursive resolvers (UDP/53)
                                                                  │
                                                                  ▼
                                   your authoritative server for the tunnel zone
                                             (exits to the open internet)
```

- **Upstream** data is base32-packed into the query name; **downstream** data is packed
  into TXT answers, several KCP segments per answer (EDNS0), so one answer carries far
  more than one query.
- Reliability/ordering is handled by KCP+smux on top of the lossy DNS datagram channel
  (the "Turbo Tunnel" pattern), not by DNS itself.
- All tunnel traffic is encrypted/authenticated with a pre-shared key; each user also has
  a token enforced on the server (quota, expiry, concurrency).
- The client **scans** a candidate pool (its OS resolvers + built-in list + any CIDR
  ranges you add), sends each an authenticated probe, and keeps only the fastest resolvers
  that genuinely reach your server — automatically rejecting hijacked/captive answers.

## Requirements

- A server (VPS) reachable on UDP/53, ideally low-latency to your users.
- A domain whose DNS you control, delegating a sub-zone to the server.

## 1. Delegate a tunnel zone

Pick a short sub-zone, e.g. `t.example.com`. At your domain's DNS, add:

| Type | Name            | Value               | Note                         |
|------|-----------------|---------------------|------------------------------|
| A    | `ns1`           | `SERVER_IP`         | **DNS only** (no proxy/CDN)  |
| NS   | `t`             | `ns1.example.com.`  | delegates `t.example.com`    |

The sub-zone (`t`) must be delegated via `NS` to an `ns` host whose `A` record is your
server's IP. Keep the zone short — every character of the zone reduces payload per query.

## 2. Install the server

On a fresh Debian/Ubuntu server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/hajilouali/dnsvpn/main/deploy/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh --zone t.example.com
```

The installer downloads the server binary, frees UDP/53 (disables the systemd-resolved
stub), generates a PSK and admin password, installs a `dnsvpn` systemd service, and prints
the zone-delegation records, the PSK, and the admin URL. Watch logs with
`journalctl -u dnsvpn -f`.

To build from source instead of downloading, run the script from a checkout with Go
installed, or pass your own binary with `--bin ./dnsvpn-server`.

## 3. Manage users

The admin panel is bound to `127.0.0.1:8080` by default. Reach it over SSH:

```bash
ssh -L 8080:127.0.0.1:8080 you@SERVER_IP
# then open http://127.0.0.1:8080  (user: admin, password: from the installer output)
```

Create a user to get a **token**, and set its quota / expiry / max concurrent streams.
Each client needs three things: the **zone**, the **PSK**, and its **token**.

## 4. Clients

Download a client from the [Releases](https://github.com/hajilouali/dnsvpn/releases)
page.

### Windows / Linux

Put the client next to a `config.json`:

```json
{
  "zone": "t.example.com",
  "psk": "<psk from installer>",
  "token": "<user token from admin panel>",
  "socks": "127.0.0.1:1080",
  "workers": 128,
  "scan": true,
  "max_resolvers": 20,
  "max_inflight": 6,
  "query_timeout": "1500ms",
  "candidates": "2.188.21.0/24, 178.22.122.100, 185.51.200.2"
}
```

Run it:

```bash
./dnsvpn-client -config config.json          # Linux
dnsvpn-client.exe -config config.json         # Windows (or double-click run.bat)
```

Then point your browser/app at the **SOCKS5** proxy `127.0.0.1:1080` (in Firefox also tick
"Proxy DNS when using SOCKS v5"). The client auto-discovers resolvers; add your ISP's
resolver ranges to `candidates` (CIDRs allowed) for the best throughput — the more
distinct resolvers that validate, the higher the aggregate speed.

Every setting is also a flag (`-zone`, `-psk`, `-token`, `-candidates`, `-workers`, …);
flags override the config file. Run `dnsvpn-client -h` for the full list.

### Android

Third-party DNS-tunnel apps are **not** compatible — this project uses its own protocol,
so the server only talks to this client. Options:

- **Termux (now):** install Termux, copy `dnsvpn-client-linux-arm64`, run it with a
  `config.json`, and point an app at the SOCKS5 proxy `127.0.0.1:1080`.
- **Native app (roadmap):** a `VpnService` app wrapping the Go core is planned; see
  [docs/android.md](docs/android.md).

## Throughput notes

Speed is dominated by the resolvers, not the tunnel code. Through a fast, nearby,
unthrottled resolver the tunnel sustains hundreds of KB/s; through distant or
rate-limited public resolvers it is much lower. Running the client **on the network where
the users actually are** (so their ISP's own resolvers are nearby) and scanning local
resolver ranges is what unlocks the speed. It is enough for messaging and web browsing;
heavy video will be slow.

## Build from source

```bash
go build ./cmd/server     # server
go build ./cmd/client     # client
go test ./...
```

Go 1.27+. Everything is pure Go and cross-compiles cleanly
(`GOOS=windows GOARCH=amd64 go build ./cmd/client`, etc.).

## License

MIT — see [LICENSE](LICENSE).
