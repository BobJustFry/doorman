#!/usr/bin/env bash
# Updates the Caddy image (the part of Doorman that faces the internet) and rolls back by itself
# if the new version does not come up with the same routes. Run by cron; safe to run by hand:
#   bash deploy/update-caddy.sh
# Needs the docker group, not root. Log: ~/doorman-update.log
set -uo pipefail

cd "$(dirname "$0")/.."
IMAGE="caddy:2"
PREV="caddy:doorman-prev"
ADMIN_API="http://127.0.0.1:2019"

log() { echo "$(date '+%F %T %Z') $*"; }

routes_fingerprint() {
  curl -sf --max-time 5 "$ADMIN_API/config/apps/http/servers" | sha256sum | cut -c1-16
}

healthy() {
  # Same config as before the restart, and HTTPS answers (the stub for the bare IP is fine).
  local want="$1" i
  for i in $(seq 1 30); do
    if [ "$(routes_fingerprint)" = "$want" ]; then
      code=$(curl -sk -o /dev/null --max-time 5 -w '%{http_code}' https://127.0.0.1/)
      [ "$code" != "000" ] && return 0
    fi
    sleep 2
  done
  return 1
}

before_id=$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null)
before_fp=$(routes_fingerprint)
[ -n "$before_fp" ] || { log "Caddy admin API not answering, nothing done"; exit 1; }

docker tag "$IMAGE" "$PREV" 2>/dev/null
if ! docker pull -q "$IMAGE" >/dev/null; then
  log "pull failed (network?), nothing changed"
  exit 1
fi
after_id=$(docker image inspect -f '{{.Id}}' "$IMAGE")
if [ "$before_id" = "$after_id" ]; then
  log "Caddy is up to date ($(docker exec doorman-caddy caddy version | cut -d' ' -f1))"
  exit 0
fi

old_ver=$(docker exec doorman-caddy caddy version | cut -d' ' -f1)
docker compose up -d caddy >/dev/null 2>&1
if healthy "$before_fp"; then
  log "Caddy updated $old_ver -> $(docker exec doorman-caddy caddy version | cut -d' ' -f1)"
  docker image prune -f >/dev/null
  exit 0
fi

log "new Caddy did not come up with the same routes: rolling back to $old_ver"
docker tag "$PREV" "$IMAGE"
docker compose up -d --force-recreate caddy >/dev/null 2>&1
if healthy "$before_fp"; then
  log "rollback done, still on $old_ver"
else
  log "ROLLBACK FAILED: check 'docker compose logs caddy'"
fi
exit 1
