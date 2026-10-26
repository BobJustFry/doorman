#!/usr/bin/env bash
# Installs fail2ban with the Doorman jails (wrong panel password, requests for hosts without a
# route, scanner-only paths, and "block from the dashboard") plus a small root helper that applies
# the dashboard's block/unblock buttons. Bans are applied through ufw.
# Run once, and again after updates: sudo bash deploy/install-fail2ban.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
VOLUME="${DOORMAN_VOLUME:-$(docker volume ls --format '{{.Name}}' | grep -E '(^|_)admin_data$' | head -1)}"
[ -n "$VOLUME" ] || { echo "Could not find the admin_data Docker volume. Start Doorman first."; exit 1; }
DATA_DIR="$(docker volume inspect "$VOLUME" --format '{{.Mountpoint}}')"
LOGPATH="$DATA_DIR/security.log"

export DEBIAN_FRONTEND=noninteractive
command -v fail2ban-client >/dev/null || { apt-get update -qq && apt-get install -y -qq fail2ban >/dev/null; }

# fail2ban refuses a jail whose log file does not exist yet
[ -e "$LOGPATH" ] || { touch "$LOGPATH"; chmod 644 "$LOGPATH"; }

install -m 0644 "$HERE"/fail2ban/filter.d/doorman-*.conf /etc/fail2ban/filter.d/
sed "s|@LOGPATH@|$LOGPATH|g" "$HERE/fail2ban/jail.doorman.conf" > /etc/fail2ban/jail.d/doorman.conf

# Sanity check: the filters must understand the log format
for f in auth stub probe; do
  printf '%s doorman-%s ip=203.0.113.9\n' "$(date +%s)" "$f" > /tmp/doorman-f2b-test.log
  n=$(fail2ban-regex /tmp/doorman-f2b-test.log "/etc/fail2ban/filter.d/doorman-$f.conf" 2>/dev/null | grep -oE 'Lines: [0-9]+ lines, [0-9]+ ignored, [0-9]+ matched' | grep -oE '[0-9]+ matched' | cut -d' ' -f1 || true)
  [ "${n:-0}" = "1" ] || { echo "Filter doorman-$f did not match its test line"; exit 1; }
done
rm -f /tmp/doorman-f2b-test.log

systemctl enable --now fail2ban >/dev/null
systemctl restart fail2ban
sleep 2

# --- helper for the "Block with fail2ban" / "Unblock" buttons of the dashboard ---------------
install -m 0755 "$HERE/fail2ban-bans.py" /usr/local/bin/doorman-fail2ban-bans

cat > /etc/systemd/system/doorman-bans.service <<UNIT
[Unit]
Description=Apply Doorman dashboard blocks to fail2ban
After=fail2ban.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/doorman-fail2ban-bans $DATA_DIR
UNIT

cat > /etc/systemd/system/doorman-bans.path <<UNIT
[Unit]
Description=Watch Doorman dashboard blocks

[Path]
PathChanged=$DATA_DIR/manual-bans.json
PathModified=$DATA_DIR/manual-bans.json

[Install]
WantedBy=multi-user.target
UNIT

# Also refreshes ban-status.json every minute so the dashboard shows blocks made by the jails.
cat > /etc/systemd/system/doorman-bans.timer <<UNIT
[Unit]
Description=Periodic Doorman ban status

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now doorman-bans.path doorman-bans.timer >/dev/null
systemctl start doorman-bans.service

echo "Done. Active jails:"
fail2ban-client status | sed -n 's/.*Jail list:\s*//p'
fail2ban-client status doorman-manual >/dev/null 2>&1 || { echo "Jail doorman-manual is not running: check 'journalctl -u fail2ban'"; exit 1; }
echo
echo "Useful commands:"
echo "  sudo fail2ban-client status doorman-stub     # who is banned now"
echo "  sudo fail2ban-client set doorman-stub unbanip 1.2.3.4"
echo "The dashboard buttons (Block / Unblock) work through doorman-bans.service."
