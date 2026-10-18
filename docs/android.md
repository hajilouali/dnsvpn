# Android client

Third-party DNS-tunnel apps (SlowDNS, dnstt-based apps, MasterDnsVPN, etc.) are **not**
compatible with this server. The tunnel uses its own wire protocol (KCP + smux over a
custom DNS codec, authenticated with your PSK and per-user token), so only this project's
client can talk to the server.

## Option A — Termux (works today)

1. Install [Termux](https://f-droid.org/packages/com.termux/) (F-Droid build).
2. Copy `dnsvpn-client-linux-arm64` (from Releases) into Termux and `chmod +x` it.
3. Create a `config.json` with your `zone`, `psk`, and `token`.
4. Run: `./dnsvpn-client-linux-arm64 -config config.json`
5. Point a SOCKS5-capable app at `127.0.0.1:1080`. For system-wide use, a local app that
   turns SOCKS5 into an Android VPN (tun) can route all traffic through it.

This has no GUI and no always-on VPN integration, but it validates the client on a phone
and uses the phone's own ISP resolvers (the ideal case for speed).

## Option B — native VpnService app (roadmap)

A proper Android app would:

- wrap the Go client core (`client/core`) as an `.aar` via `gomobile bind`,
- run a `VpnService` with a `tun` interface and an in-process `tun2socks` that feeds the
  existing SOCKS entry point,
- provide a small Kotlin UI for the zone/psk/token, a connect toggle, per-app split
  tunneling, and the live resolver list from the scanner.

The core already exposes everything this needs (a `Client` that opens streams to arbitrary
destinations and a resolver scanner); the remaining work is the mobile packaging and UI.
