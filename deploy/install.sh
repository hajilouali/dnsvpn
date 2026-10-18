#!/usr/bin/env bash
#
# dnsvpn server installer for Debian/Ubuntu.
#
# Installs the authoritative tunnel server as a systemd service, frees UDP/53,
# generates a pre-shared key and admin password, and opens the firewall. Run as root
# on a fresh server that has a delegated tunnel zone pointing at this host (see README).
#
# Usage:
#   sudo ./install.sh --zone t.example.com [--http 127.0.0.1:8080] [--bin ./dnsvpn-server]
#
set -euo pipefail

ZONE=""
HTTP_ADDR="127.0.0.1:8080"
PANEL_DOMAIN=""                  # optional: serve the panel publicly over HTTPS on this domain
BIN_SRC=""                       # optional local binary; otherwise built/downloaded
REPO="hajilouali/dnsvpn"
PREFIX="/usr/local/bin"
DATADIR="/var/lib/dnsvpn"
CONFDIR="/etc/dnsvpn"
USER_NAME="dnsvpn"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --zone) ZONE="$2"; shift 2;;
    --http) HTTP_ADDR="$2"; shift 2;;
    --panel-domain) PANEL_DOMAIN="$2"; shift 2;;
    --bin)  BIN_SRC="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    *) err "unknown argument: $1";;
  esac
done

[ "$(id -u)" = "0" ] || err "run as root (sudo)."
[ -n "$ZONE" ] || err "--zone is required, e.g. --zone t.example.com"
ZONE="${ZONE%.}"

log "Installing dnsvpn server for zone: $ZONE"

# --- obtain the server binary ------------------------------------------------
install -d "$PREFIX" "$DATADIR" "$CONFDIR"
if [ -n "$BIN_SRC" ]; then
  log "Using provided binary: $BIN_SRC"
  install -m 0755 "$BIN_SRC" "$PREFIX/dnsvpn-server"
elif command -v go >/dev/null 2>&1 && [ -f "$(dirname "$0")/../go.mod" ]; then
  log "Building from source with Go..."
  ( cd "$(dirname "$0")/.." && go build -ldflags="-s -w" -o "$PREFIX/dnsvpn-server" ./cmd/server )
else
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) err "unsupported arch $ARCH";; esac
  URL="https://github.com/$REPO/releases/latest/download/dnsvpn-server-linux-$ARCH"
  log "Downloading server binary: $URL"
  curl -fSL "$URL" -o "$PREFIX/dnsvpn-server" || err "download failed; pass --bin <path> instead"
  chmod 0755 "$PREFIX/dnsvpn-server"
fi

# allow binding the privileged DNS port without full root
setcap 'cap_net_bind_service=+ep' "$PREFIX/dnsvpn-server" 2>/dev/null || true

# --- free UDP/53 (disable systemd-resolved stub) -----------------------------
if ss -lunp 2>/dev/null | grep -q '127.0.0.53:53'; then
  log "Freeing UDP/53 from systemd-resolved stub..."
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\nDNS=1.1.1.1 8.8.8.8\n' > /etc/systemd/resolved.conf.d/dnsvpn.conf
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved || true
fi

# --- user, config, secrets ---------------------------------------------------
id "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"

ENV_FILE="$CONFDIR/dnsvpn.env"
if [ ! -f "$ENV_FILE" ]; then
  PSK="$(head -c16 /dev/urandom | xxd -p)"
  ADMIN_PASS="$(head -c12 /dev/urandom | xxd -p)"
  cat > "$ENV_FILE" <<EOF
ZONE=$ZONE
PSK=$PSK
HTTP_ADDR=$HTTP_ADDR
ADMIN_USER=admin
ADMIN_PASS=$ADMIN_PASS
# serve the panel publicly over HTTPS on this domain (auto Let's Encrypt). Empty =
# localhost only (reach it over an SSH tunnel). e.g. PANEL_DOMAIN=panel.example.com
PANEL_DOMAIN=$PANEL_DOMAIN
# default resolver candidates baked into clients' config links (CIDRs allowed), e.g.
# CANDIDATES=2.188.21.0/24,178.22.122.100,185.51.200.2
CANDIDATES=
EOF
  chmod 600 "$ENV_FILE"
  log "Generated new PSK and admin password in $ENV_FILE"
else
  log "Keeping existing $ENV_FILE (PSK/admin unchanged)"
fi
chown -R "$USER_NAME":"$USER_NAME" "$DATADIR" "$CONFDIR"

# --- systemd service ---------------------------------------------------------
cat > /etc/systemd/system/dnsvpn.service <<EOF
[Unit]
Description=dnsvpn authoritative DNS tunnel server
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
EnvironmentFile=$ENV_FILE
ExecStart=/bin/sh -c '$PREFIX/dnsvpn-server -zone "\$ZONE" -psk "\$PSK" -dns :53 -http "\$HTTP_ADDR" -db $DATADIR/users.db -admin-user "\$ADMIN_USER" -admin-pass "\$ADMIN_PASS" -candidates "\$CANDIDATES" -panel-domain "\$PANEL_DOMAIN"'
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATADIR
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dnsvpn.service

# --- firewall ----------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  ufw allow 53/udp  >/dev/null 2>&1 || true
  ufw allow 53/tcp  >/dev/null 2>&1 || true
  ufw allow 22/tcp  >/dev/null 2>&1 || true
  if [ -n "$PANEL_DOMAIN" ]; then
    ufw allow 80/tcp  >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    log "ufw rules added for 22,53,80,443 (enable ufw yourself if desired)."
  else
    log "ufw rules added for 22,53 (enable ufw yourself if desired)."
  fi
fi

sleep 1
# shellcheck disable=SC1090
. "$ENV_FILE"
IP="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"

cat <<EOF

$(printf '\033[1;32m================ dnsvpn server installed ================\033[0m')

  Service : $(systemctl is-active dnsvpn.service)   (journalctl -u dnsvpn -f to watch)
  Zone    : $ZONE
  PSK     : $PSK
  Admin   : $( [ -n "$PANEL_DOMAIN" ] && echo "https://$PANEL_DOMAIN" || echo "http://$HTTP_ADDR (localhost)" )   user: admin   pass: $ADMIN_PASS
            (change the password from the panel; the password above is only the seed)

  DNS delegation — set these at your domain's DNS (replace example.com):
    A    ns1.<parent>    $IP        (DNS only, no proxy/CDN)
    NS   ${ZONE#*.}.<..> ns1.<parent>
  i.e. the parent of "$ZONE" must delegate it to an ns host whose A = $IP.

  Give each user: the zone, the PSK above, and a per-user token you create in the
  admin panel. Clients need all three.

  $( if [ -n "$PANEL_DOMAIN" ]; then
       echo "Point $PANEL_DOMAIN (A record) at $IP; the panel is public over HTTPS."
     else
       echo "The panel is localhost-only. Reach it over SSH:"
       echo "    ssh -L 8088:127.0.0.1:8080 <you>@$IP   then open http://127.0.0.1:8088"
     fi )

$(printf '\033[1;32m=========================================================\033[0m')
EOF
