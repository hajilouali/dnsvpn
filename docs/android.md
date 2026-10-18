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

## Option B — native VpnService app

A native app lives in [`android/`](../android). It wraps the Go core as an `.aar`
(`gomobile bind` over the [`mobile`](../mobile) package), runs a `VpnService` with a TUN
and an in-process userspace TCP/IP stack (tun2socks) that feeds the tunnel's SOCKS entry
point, and has a small Kotlin UI for the zone/psk/token with a connect toggle. The Go
client's own resolver sockets are kept off the TUN via a `protect(fd)` callback into the
service, so there is no routing loop.

The APK is built in CI ([.github/workflows/android.yml](../.github/workflows/android.yml))
and attached to each tagged release — download `dnsvpn-android.apk` from Releases, install
it (enable "install from unknown sources"), enter your zone/psk/token, and tap Connect.

**Current limitation:** the tunnel carries **TCP**. Plain-UDP DNS and QUIC are not tunneled
yet, so the VpnService sets a DNS server and apps fall back to TCP; this is the next piece
of work (UDP/DNS over the tunnel). Build locally instead of CI with:

```bash
gomobile bind -target=android -androidapi 21 -javapkg=com.dnsvpn -o android/app/libs/mobile.aar ./mobile
cd android && ./gradlew assembleDebug
```
