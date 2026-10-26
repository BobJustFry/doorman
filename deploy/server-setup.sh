#!/usr/bin/env bash
# Doorman: prepare a fresh Ubuntu/Debian server (Docker + network/system tuning).
# Safe to run more than once. Usage: sudo bash server-setup.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
RUN_USER="${SUDO_USER:-root}"
export DEBIAN_FRONTEND=noninteractive

echo "==> Packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl ufw unattended-upgrades >/dev/null

echo "==> Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
[ "$RUN_USER" = root ] || usermod -aG docker "$RUN_USER"

mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
  cat > /etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "default-ulimits": { "nofile": { "Name": "nofile", "Hard": 1048576, "Soft": 1048576 } }
}
JSON
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null

echo "==> Kernel / network tuning (BBR, backlog, UDP buffers for HTTP/3)"
cat > /etc/sysctl.d/99-doorman.conf <<'CONF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
fs.file-max = 1048576
vm.swappiness = 10
CONF
sysctl --system >/dev/null

echo "==> Swap (safety net on small servers)"
if [ "$(swapon --show --noheadings | wc -l)" -eq 0 ]; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "==> Time sync and automatic security updates"
timedatectl set-ntp true || true
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true

echo "==> Firewall (SSH is allowed first so you are not locked out)"
ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 443/udp >/dev/null
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  ufw allow from "$net" to any port 8080 proto tcp >/dev/null
done
ufw --force enable >/dev/null

echo
echo "Done. BBR: $(sysctl -n net.ipv4.tcp_congestion_control), swap: $(free -h | awk '/Swap/{print $2}'), docker: $(docker --version)"
[ "$RUN_USER" = root ] || echo "Log out and back in so the 'docker' group applies to $RUN_USER."
