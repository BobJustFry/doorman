#!/usr/bin/env bash
# Installs fail2ban with three Doorman jails (wrong panel password, requests for hosts
# without a route, scanner-only paths). Bans are applied through ufw.
# Run once: sudo bash deploy/install-fail2ban.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
VOLUME="${DOORMAN_VOLUME:-$(docker volume ls --format '{{.Name}}' | grep -E '(^|_)admin_data$' | head -1)}"
[ -n "$VOLUME" ] || { echo "Could not find the admin_data Docker volume. Start Doorman first."; exit 1; }
LOGPATH="$(docker volume inspect "$VOLUME" --format '{{.Mountpoint}}')/security.log"

export DEBIAN_FRONTEND=noninteractive
command -v fail2ban-client >/dev/null || { apt-get update -qq && apt-get install -y -qq fail2ban >/dev/null; }

# fail2ban refuses a jail whose log file does not exist yet
[ -e "$LOGPATH" ] || { touch "$LOGPATH"; chmod 644 "$LOGPATH"; }

install -m 0644 "$HERE"/fail2ban/filter.d/doorman-*.conf /etc/fail2ban/filter.d/
sed "s|@LOGPATH@|$LOGPATH|g" "$HERE/fail2ban/jail.doorman.conf" > /etc/fail2ban/jail.d/doorman.conf

# Sanity check: the filters must understand the log format
for f in auth stub probe; do
  printf '%s doorman-%s ip=203.0.113.9\n' "$(date +%s)" "$f" > /tmp/doorman-f2b-test.log
  n=$(fail2ban-regex /tmp/doorman-f2b-test.log "/etc/fail2ban/filter.d/doorman-$f.conf" 2>/dev/null | grep -oE 'Lines: [0-9]+ lines, [0-9]+ ignored, [0-9]+ matched' | grep -oE '[0-9]+ matched' | cut -d' ' -f1)
  [ "${n:-0}" = "1" ] || { echo "Filter doorman-$f did not match its test line"; exit 1; }
done
rm -f /tmp/doorman-f2b-test.log

systemctl enable --now fail2ban >/dev/null
systemctl restart fail2ban
sleep 2
echo "Done. Active jails:"
fail2ban-client status | sed -n 's/.*Jail list:\s*//p'
echo
echo "Useful commands:"
echo "  sudo fail2ban-client status doorman-stub     # who is banned now"
echo "  sudo fail2ban-client set doorman-stub unbanip 1.2.3.4"
