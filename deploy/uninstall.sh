#!/usr/bin/env bash
# Remove the dnsvpn server service and files. Keeps nothing except what you back up.
set -euo pipefail
[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }

systemctl disable --now dnsvpn.service 2>/dev/null || true
rm -f /etc/systemd/system/dnsvpn.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/dnsvpn-server
rm -f /etc/systemd/resolved.conf.d/dnsvpn.conf

echo "Removed service and binary."
echo "Left in place (delete manually if you want): /etc/dnsvpn (PSK/admin), /var/lib/dnsvpn (user DB)."
echo "To restore the default DNS stub: remove the resolved drop-in above and 'systemctl restart systemd-resolved'."
