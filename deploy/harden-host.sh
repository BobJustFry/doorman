#!/usr/bin/env bash
# Hardens the server that runs Doorman: SSH, kernel network settings, firewall defaults,
# pending security updates and needless privileges of the login user.
# Idempotent. Run as root:  sudo bash deploy/harden-host.sh
# SSH password logins are switched off ONLY if the invoking user already has an SSH key,
# so this cannot lock you out.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
USER_NAME="${SUDO_USER:-}"
HOME_DIR="$(getent passwd "${USER_NAME:-root}" | cut -d: -f6)"
export DEBIAN_FRONTEND=noninteractive
CHANGED=()

echo "==> SSH"
KEYS="$HOME_DIR/.ssh/authorized_keys"
if [ -s "$KEYS" ] && grep -qE '^(ssh-|ecdsa-|sk-)' "$KEYS"; then
  NOPASS="PasswordAuthentication no"
else
  NOPASS="# PasswordAuthentication left on: no SSH key found in $KEYS"
  echo "   WARNING: no SSH key for ${USER_NAME:-root}; password logins stay enabled. Add a key first."
fi
# sshd uses the FIRST value it reads, and files of sshd_config.d come first: 00- wins over cloud-init's 50-.
cat > /etc/ssh/sshd_config.d/00-doorman-hardening.conf <<CONF
$NOPASS
PermitRootLogin no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
CONF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd
CHANGED+=("ssh")

echo "==> Kernel network hardening"
cat > /etc/sysctl.d/98-doorman-hardening.conf <<'CONF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
CONF
sysctl --system >/dev/null
CHANGED+=("sysctl")

echo "==> Firewall defaults"
ufw allow 22/tcp >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
CHANGED+=("ufw")

echo "==> Login user privileges"
if [ -n "$USER_NAME" ] && id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx lxd; then
  gpasswd -d "$USER_NAME" lxd >/dev/null && echo "   removed $USER_NAME from group lxd (it is equivalent to root and unused here)"
fi

echo "==> Security updates"
apt-get update -qq
apt-get -y -qq -o Dpkg::Options::=--force-confold upgrade >/dev/null
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
CHANGED+=("updates")

echo
echo "Done: ${CHANGED[*]}"
[ -e /var/run/reboot-required ] && echo "A reboot is needed to finish the kernel/library updates:  sudo reboot"
echo "Check SSH keeps working in a SECOND terminal before closing this one."
echo "Note: group 'docker' is root-equivalent by design; only trusted accounts should be in it."
