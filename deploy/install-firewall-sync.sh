#!/usr/bin/env bash
# Installs a small root service that opens/closes ufw ports for Doorman routes
# whenever the admin panel changes them. Run once: sudo bash deploy/install-firewall-sync.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
VOLUME="${DOORMAN_VOLUME:-$(docker volume ls --format '{{.Name}}' | grep -E '(^|_)admin_data$' | head -1)}"
[ -n "$VOLUME" ] || { echo "Could not find the admin_data Docker volume. Start Doorman first."; exit 1; }
PORTS_FILE="$(docker volume inspect "$VOLUME" --format '{{.Mountpoint}}')/firewall-ports.json"

install -m 0755 "$HERE/firewall-sync.py" /usr/local/bin/doorman-firewall-sync

cat > /etc/systemd/system/doorman-firewall.service <<UNIT
[Unit]
Description=Sync ufw with Doorman route ports

[Service]
Type=oneshot
ExecStart=/usr/local/bin/doorman-firewall-sync $PORTS_FILE
UNIT

cat > /etc/systemd/system/doorman-firewall.path <<UNIT
[Unit]
Description=Watch Doorman route ports

[Path]
PathChanged=$PORTS_FILE
PathModified=$PORTS_FILE

[Install]
WantedBy=multi-user.target
UNIT

# Backup in case a change is ever missed (also covers reboots).
cat > /etc/systemd/system/doorman-firewall.timer <<UNIT
[Unit]
Description=Periodic Doorman firewall sync

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now doorman-firewall.path doorman-firewall.timer >/dev/null
systemctl start doorman-firewall.service
echo "Done. Ports of Doorman routes are now opened in ufw automatically."
echo "Watching: $PORTS_FILE"
ufw status | grep doorman-route || echo "(no extra route ports yet)"
