#!/usr/bin/env bash
# Schedules deploy/update-caddy.sh once a week (Sunday, 23:00 server time by default) for the
# current user. No root needed, only membership in the docker group. Run once:
#   bash deploy/install-auto-update.sh            # or: SCHEDULE="0 3 * * 1" bash deploy/...
# Remove: crontab -l | grep -v doorman-update-caddy | crontab -
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCHEDULE="${SCHEDULE:-0 23 * * 0}"
LINE="$SCHEDULE bash $HERE/update-caddy.sh >> \$HOME/doorman-update.log 2>&1 # doorman-update-caddy"

docker info >/dev/null 2>&1 || { echo "This user cannot use Docker (add it to the docker group)."; exit 1; }
chmod +x "$HERE/update-caddy.sh"
{ crontab -l 2>/dev/null | grep -v 'doorman-update-caddy' || true; echo "$LINE"; } | crontab -
echo "Scheduled: $SCHEDULE (server time, $(date +%Z)). Log: ~/doorman-update.log"
crontab -l | grep doorman-update-caddy
