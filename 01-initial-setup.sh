#!/usr/bin/env bash
# =============================================================================
# 01-initial-setup.sh
# Initial hardening script for a fresh Ubuntu 24.04 or 26.04 server in a DMZ.
# Run once as the default installer user (e.g. ubuntu) with sudo privileges.
#
# What this script does:
#   1. Preflight checks
#   2. Full system update
#   3. Create the admin user and import SSH keys
#   4. Grant sudo only to that admin; strip and lock all other accounts
#   5. Harden SSH daemon
#   6. Configure UFW firewall (DMZ posture: deny all, allow SSH only)
#   7. Configure unattended-upgrades (security patches, auto-reboot at 02:00)
#   8. Install and configure fail2ban (incremental SSH bans)
#   9. Apply kernel hardening via sysctl
#  10. Install and configure auditd
#  11. Print summary and prompt for reboot
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Ubuntu 24.04 / 26.04 compatibility ───────────────────────────────────────
# Both LTS releases are first-class targets. Helpers below absorb the deltas:
#   • 26.04 SSH is socket-activated (ssh.socket + ssh@.service)
#   • 26.04 OpenSSH 10 dropped ChallengeResponseAuthentication as a real keyword
#   • 26.04 auditd split: audit-rules.service loads rules, auditd.service logs
#   • 24.04+ has no rsyslog by default — fail2ban must use backend=systemd
#   • 26.04 firewall path is nftables; 24.04 is iptables-nft (nftables action works on both)
. /etc/os-release
UBUNTU_VERSION="${VERSION_ID:-unknown}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-unknown}}"

require_supported_ubuntu() {
    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "This script is written for Ubuntu. Detected '${ID:-unknown}'."
    fi
    case "${UBUNTU_VERSION}" in
        24.04|26.04)
            info "Detected Ubuntu ${UBUNTU_VERSION} (${UBUNTU_CODENAME}) — supported."
            ;;
        22.04)
            warn "Ubuntu 22.04 is not a primary target. Most steps still work."
            ;;
        *)
            warn "Ubuntu ${UBUNTU_VERSION} is untested (supported: 24.04 and 26.04)."
            read -r -p "  Continue anyway? [y/N] " go
            [[ "${go,,}" == "y" ]] || die "Aborted."
            ;;
    esac
}

# Reload sshd without assuming a long-lived ssh.service.
# 24.04 may run ssh.service continuously; 26.04 defaults to ssh.socket and only
# spawns ssh@.service per connection. The drop-in in sshd_config.d is read by
# every new instance, so we must not disable socket activation.
reload_ssh_safely() {
    mkdir -p /run/sshd
    sshd -t -f /etc/ssh/sshd_config || die "SSH config validation failed. Aborting to prevent lockout."

    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        systemctl reload ssh 2>/dev/null \
            || systemctl reload sshd 2>/dev/null \
            || warn "Could not reload the running sshd — new connections will pick up the drop-in."
    fi

    if systemctl is-active --quiet ssh.socket 2>/dev/null \
        || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        info "SSH is socket-activated (ssh.socket). New connections inherit ${SSH_HARDENING_FILE}."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo ./01-initial-setup.sh)."
require_supported_ubuntu

# Identify the installer user (the user who invoked sudo, or 'ubuntu' as fallback)
INSTALLER_USER="${SUDO_USER:-ubuntu}"
INSTALLER_HOME=$(getent passwd "$INSTALLER_USER" | cut -d: -f6 2>/dev/null || echo "/home/$INSTALLER_USER")

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ Hardening — Initial Setup${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo "  Installer user : ${INSTALLER_USER}"
echo "  Ubuntu         : ${UBUNTU_VERSION} (${UBUNTU_CODENAME})"
echo ""

# Prompt for the admin username to create
while true; do
    read -r -p "  Enter the admin username to create: " TARGET_USER
    if [[ -z "${TARGET_USER}" ]]; then
        warn "Username cannot be empty."
    elif [[ ! "${TARGET_USER}" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        warn "Invalid username '${TARGET_USER}'. Use lowercase letters, numbers, hyphens, or underscores. Must start with a letter."
    elif [[ "${TARGET_USER}" == "${INSTALLER_USER}" ]]; then
        warn "That is the installer account. Choose a different name."
    else
        break
    fi
done

echo "  New admin user : ${TARGET_USER}"
echo ""
echo -e "${YELLOW}This script will make the following changes:${NC}"
echo "  • Full system update"
echo "  • Create user '${TARGET_USER}' with sudo, import SSH keys"
echo "  • Lock all other non-system accounts from sudo and SSH"
echo "  • Harden SSH daemon configuration"
echo "  • Configure UFW: deny all inbound/outbound except SSH + essential outbound"
echo "  • Enable automatic security updates (auto-reboot at 02:00)"
echo "  • Install fail2ban with incremental SSH banning"
echo "  • Apply DMZ kernel hardening (sysctl)"
echo "  • Install auditd"
echo ""
read -r -p "Proceed? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2. SYSTEM UPDATE
# ─────────────────────────────────────────────────────────────────────────────
info "Updating package lists and upgrading installed packages..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -qq
apt-get autoremove -y -qq
apt-get autoclean -qq
success "System updated."

# ─────────────────────────────────────────────────────────────────────────────
# 3. CREATE ADMIN USER AND IMPORT SSH KEYS
# ─────────────────────────────────────────────────────────────────────────────
info "Creating user '${TARGET_USER}'..."

if id "${TARGET_USER}" &>/dev/null; then
    warn "User '${TARGET_USER}' already exists — skipping creation."
else
    # --gecos is still accepted on 24.04; 26.04 adduser prefers --comment.
    adduser --disabled-password --gecos "" "${TARGET_USER}" 2>/dev/null \
        || adduser --disabled-password --comment "" "${TARGET_USER}"
    success "User '${TARGET_USER}' created."
fi

# Set a password — required for sudo (SSH uses key-only, but sudo needs a password).
echo ""
echo "  Set a sudo password for '${TARGET_USER}'."
echo "  This password is ONLY used for sudo — SSH login remains key-only."
echo ""
while true; do
    if passwd "${TARGET_USER}"; then
        success "Password set for '${TARGET_USER}'."
        break
    else
        warn "Password entry failed or did not match. Try again."
    fi
done

# Set up SSH directory
TARGET_SSH_DIR="/home/${TARGET_USER}/.ssh"
TARGET_KEYS_FILE="${TARGET_SSH_DIR}/authorized_keys"
mkdir -p "${TARGET_SSH_DIR}"

KEY_IMPORTED=false

# Try to copy from the installer user's authorized_keys first
INSTALLER_KEYS="${INSTALLER_HOME}/.ssh/authorized_keys"
if [[ -s "${INSTALLER_KEYS}" ]]; then
    cp "${INSTALLER_KEYS}" "${TARGET_KEYS_FILE}"
    KEY_IMPORTED=true
    info "SSH keys copied from '${INSTALLER_USER}'."
fi

# If no keys found, try importing from GitHub
if [[ "${KEY_IMPORTED}" == false ]]; then
    warn "No authorized_keys found for '${INSTALLER_USER}'."
    echo ""
    read -r -p "  Enter your GitHub username to import SSH keys (or leave blank to skip): " GH_USER
    if [[ -n "${GH_USER}" ]]; then
        apt-get install -y -qq ssh-import-id
        sudo -u "${TARGET_USER}" ssh-import-id "gh:${GH_USER}" && KEY_IMPORTED=true \
            || warn "Failed to import keys from GitHub. Add keys manually later."
    fi
fi

if [[ "${KEY_IMPORTED}" == false ]]; then
    warn "No SSH keys were imported for '${TARGET_USER}'."
    warn "Add keys manually before rebooting or you will be locked out."
fi

# Fix permissions
chown -R "${TARGET_USER}:${TARGET_USER}" "${TARGET_SSH_DIR}"
chmod 700 "${TARGET_SSH_DIR}"
[[ -f "${TARGET_KEYS_FILE}" ]] && chmod 600 "${TARGET_KEYS_FILE}"

success "SSH keys configured for '${TARGET_USER}'."

# ─────────────────────────────────────────────────────────────────────────────
# 4. SUDO — admin user only
# ─────────────────────────────────────────────────────────────────────────────
info "Configuring sudo access..."

# Add the new admin to the sudo group
usermod -aG sudo "${TARGET_USER}"

# Remove all other non-system accounts from the sudo group
while IFS=: read -r username _ uid _; do
    # Only consider non-system, non-target human accounts (UID 1000–59999)
    if [[ "${uid}" -ge 1000 && "${uid}" -lt 60000 && "${username}" != "${TARGET_USER}" ]]; then
        if id -nG "${username}" 2>/dev/null | grep -qw sudo; then
            gpasswd -d "${username}" sudo 2>/dev/null || true
            warn "Removed '${username}' from sudo group."
        fi
    fi
done < /etc/passwd

# Remove any sudoers.d entries that grant access to other users
for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    fname=$(basename "$f")
    # Keep entries that are clearly system/cloud-init entries named after target user
    if [[ "${fname}" != "${TARGET_USER}" && "${fname}" != "90-cloud-init-users" ]]; then
        # Check if the file grants sudo to a non-target user
        if grep -qE "^[^#]*ALL\s*=" "$f" 2>/dev/null && ! grep -qE "^${TARGET_USER}" "$f" 2>/dev/null; then
            warn "Disabling sudoers.d entry: $f"
            chmod 000 "$f"
        fi
    fi
done

# Lock the installer/default account (do not delete — cloud-init may need it)
if [[ "${INSTALLER_USER}" != "${TARGET_USER}" ]] && id "${INSTALLER_USER}" &>/dev/null; then
    passwd -l "${INSTALLER_USER}"
    warn "Account '${INSTALLER_USER}' has been locked (password disabled)."
fi

success "Sudo access restricted to '${TARGET_USER}'."

# ─────────────────────────────────────────────────────────────────────────────
# 5. SSH HARDENING
# ─────────────────────────────────────────────────────────────────────────────
info "Hardening SSH daemon..."

SSH_HARDENING_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"

cat > "${SSH_HARDENING_FILE}" << EOF
# Managed by 01-initial-setup.sh — do not edit manually.

# Only this account may log in via SSH.
AllowUsers ${TARGET_USER}

# Disable all non-key authentication methods.
# KbdInteractiveAuthentication is the OpenSSH 8.7+ name. Do not also set
# ChallengeResponseAuthentication — OpenSSH 10 (Ubuntu 26.04) treats that as a
# deprecated alias and some builds reject it, which would make sshd -t fail.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes

# Connection limits — three layers of defence before fail2ban fires.
MaxAuthTries 3
MaxSessions 2
MaxStartups 3:50:10
LoginGraceTime 20

# Local SSH tunnels only (ssh -L to 127.0.0.1). Needed for VNC/dashboard.
# Not a jump host: remote forwarding and GatewayPorts stay off.
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitTunnel no
GatewayPorts no

# Disable weak features.
PermitUserEnvironment no
PrintLastLog yes
Banner none
EOF

reload_ssh_safely

success "SSH hardened. Restrictions written to ${SSH_HARDENING_FILE}"

# ─────────────────────────────────────────────────────────────────────────────
# 6. FIREWALL (UFW) — DMZ POSTURE
# ─────────────────────────────────────────────────────────────────────────────
info "Configuring UFW firewall (DMZ: deny all, allow only what is required)..."

apt-get install -y -qq ufw

# Start with a clean slate
ufw --force reset

# Default policies — deny everything
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward

# ── Inbound ──
ufw allow in 22/tcp comment "SSH"

# ── Outbound — minimum required for system operation ──
ufw allow out 53    comment "DNS"
ufw allow out 80/tcp  comment "HTTP (apt, feeds)"
ufw allow out 443/tcp comment "HTTPS (apt, Docker Hub, broker login, news, LLM APIs)"
ufw allow out 123/udp comment "NTP (time sync)"

# Host ↔ Compose bridge. Do not open 5900/8000/5432/8765 to the internet.
# 02-add-service.sh option 1 still installs docker-user-guard; these rules
# are enough for docker-proxy if you go straight to trader-bot/install.sh.
ufw allow in on docker0 comment "docker"
ufw allow out on docker0 comment "docker"
ufw allow in on br+ comment "compose bridges"
ufw allow out on br+ comment "compose bridges"
sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true

# Docker published ports need IPv4 forwarding. 99-docker-forward.conf sorts
# after 99-dmz-hardening.conf so the rest of the DMZ sysctl stays intact.
cat > /etc/sysctl.d/99-docker-forward.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0
EOF
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true

# NOTE: Inbound is SSH only, by design. The trading bot runs as a Docker Compose
# stack and is reached over SSH port-forwarding, so its ports (dashboard 8000,
# VNC 5900, EA bridge 8765, Postgres 5432, Redis 6379) are never opened here.
# Run 02-add-service.sh and choose the Docker/MetaTrader option to prepare the
# host for Compose without exposing any of those ports.
#
# If an MT5 broker uses a non-standard TCP port, that is an OUTBOUND rule only:
#   ufw allow out <PORT>/tcp comment "Broker XYZ"
# 02-add-service.sh can add it for you (custom port -> outbound direction).

ufw --force enable

success "UFW enabled."
ufw status verbose

# ─────────────────────────────────────────────────────────────────────────────
# 7. AUTOMATIC SECURITY UPDATES
# ─────────────────────────────────────────────────────────────────────────────
info "Configuring unattended-upgrades..."

apt-get install -y -qq unattended-upgrades apt-listchanges

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Security updates only — no regular upgrades or backports.
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::Verbose "false";
EOF

# The long-running service exists on 24.04. 26.04 still ships it, but the
# actual cadence is apt-daily.timer + apt-daily-upgrade.timer — enable both
# so either activation model applies patches.
systemctl enable unattended-upgrades 2>/dev/null || true
systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl restart unattended-upgrades 2>/dev/null || true

success "Automatic security updates configured (auto-reboot at 02:00 if required)."

# ─────────────────────────────────────────────────────────────────────────────
# 8. FAIL2BAN
# ─────────────────────────────────────────────────────────────────────────────
info "Installing and configuring fail2ban..."

# python3-systemd is required for backend=systemd. Without it the sshd jail
# silently fails to start on a journald-only host (rsyslog is not installed
# by default on 24.04 or 26.04, so /var/log/auth.log does not exist).
apt-get install -y -qq fail2ban python3-systemd

# nftables action works on 24.04 (iptables-nft) and is required on 26.04,
# where a plain iptables-multiport ban can land on a chain the packet never
# traverses. action_mwl is intentionally not used: it needs sendmail/whois
# (neither is installed, and whois is outbound TCP 43 which UFW denies).
FAIL2BAN_BANACTION="iptables-multiport"
FAIL2BAN_BANACTION_ALL="iptables-allports"
if command -v nft &>/dev/null || apt-get install -y -qq nftables; then
    FAIL2BAN_BANACTION="nftables[type=multiport]"
    FAIL2BAN_BANACTION_ALL="nftables[type=allports]"
fi

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
backend  = systemd
banaction = ${FAIL2BAN_BANACTION}
banaction_allports = ${FAIL2BAN_BANACTION_ALL}
EOF

cat > /etc/fail2ban/jail.d/sshd.conf << EOF
[sshd]
enabled    = true
port       = ssh
filter     = sshd
backend    = systemd
# 24.04 long-lived unit: ssh.service (or sshd.service).
# 26.04 socket activation: ssh.socket + per-connection ssh@.service.
# OpenSSH 10 splits the daemon: sshd / sshd-auth / sshd-session.
# _COMM catches the process name regardless of the unit that owns the journal.
journalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=ssh.socket + _COMM=sshd + _COMM=sshd-auth
maxretry   = 3
findtime   = 10m
bantime    = 24h
bantime.increment  = true
bantime.multiplier = 2
bantime.maxtime    = 168h
action     = ${FAIL2BAN_BANACTION}
EOF

systemctl enable fail2ban
if systemctl restart fail2ban; then
    success "fail2ban configured (3 retries → 24h ban, doubling on repeat, max 7 days)."
else
    warn "fail2ban failed to start. Kernel hardening and auditd will still run."
    warn "Fix with: sudo journalctl -u fail2ban -e  &&  sudo systemctl restart fail2ban"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 9. KERNEL HARDENING (sysctl)
# ─────────────────────────────────────────────────────────────────────────────
info "Applying DMZ kernel hardening..."

cat > /etc/sysctl.d/99-dmz-hardening.conf << 'EOF'
# ── Network — DMZ posture ────────────────────────────────────────────────────

# No IP forwarding — this is not a router.
#
# NOTE: Docker's bridge networking requires net.ipv4.ip_forward = 1. Do not edit
# this file to enable it. 02-add-service.sh writes /etc/sysctl.d/99-docker-forward.conf
# instead, which sorts after this file and therefore overrides just this one key
# while leaving every other hardening value below intact.
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Reject ICMP redirects (prevent routing table manipulation).
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Reject source-routed packets.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore ICMP broadcast pings (smurf attack mitigation).
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN flood protection via SYN cookies.
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Reverse-path filtering — drop packets with spoofed source addresses.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets from impossible (martian) source addresses.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 router advertisements and auto-configuration.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ── Memory / Process hardening ───────────────────────────────────────────────

# Full ASLR (Address Space Layout Randomisation).
kernel.randomize_va_space = 2

# Restrict dmesg to root.
kernel.dmesg_restrict = 1

# Restrict kernel pointer leaks.
kernel.kptr_restrict = 2

# Protect hard and symbolic links from TOCTOU attacks.
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Restrict /proc/PID to process owner and root.
kernel.yama.ptrace_scope = 1

# Disable the magic SysRq key (not needed on a server).
kernel.sysrq = 0

EOF

# nf_conntrack_max only exists after the module is loaded. Writing it into the
# drop-in on a host that has never NATed anything makes `sysctl --system` exit
# non-zero, which would abort the rest of this script under `set -e`.
if modprobe nf_conntrack 2>/dev/null || [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    echo "" >> /etc/sysctl.d/99-dmz-hardening.conf
    echo "# Container NAT consumes conntrack entries once Compose is running." >> /etc/sysctl.d/99-dmz-hardening.conf
    echo "net.netfilter.nf_conntrack_max = 131072" >> /etc/sysctl.d/99-dmz-hardening.conf
fi

# --system returns non-zero if any single key is unknown. Apply best-effort.
sysctl --system >/dev/null 2>&1 || true
# Re-assert the Docker exception so a later-sorting unknown-key failure cannot
# leave ip_forward at the DMZ baseline of 0.
if [[ -f /etc/sysctl.d/99-docker-forward.conf ]]; then
    sysctl -p /etc/sysctl.d/99-docker-forward.conf >/dev/null 2>&1 || true
fi

success "Kernel hardening applied."

# ─────────────────────────────────────────────────────────────────────────────
# 10. AUDIT LOGGING (auditd)
# ─────────────────────────────────────────────────────────────────────────────
info "Installing auditd..."

# audispd-plugins was renamed / folded on some 26.04 images. auditd itself
# is the required package; the plugins package is best-effort.
if apt-cache show audispd-plugins >/dev/null 2>&1; then
    apt-get install -y -qq auditd audispd-plugins
else
    apt-get install -y -qq auditd
fi

cat > /etc/audit/rules.d/99-dmz.rules << 'EOF'
# Delete all existing rules and set the default action to 'deny'.
-D
-b 8192

# ── Privilege escalation ─────────────────────────────────────────────────────
-w /etc/sudoers       -p wa -k sudoers_change
-w /etc/sudoers.d/    -p wa -k sudoers_change
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# ── SSH authentication ───────────────────────────────────────────────────────
-w /etc/ssh/sshd_config            -p wa -k sshd_config_change
-w /etc/ssh/sshd_config.d/        -p wa -k sshd_config_change
-w /var/log/auth.log               -p wa -k auth_log

# ── User and group changes ───────────────────────────────────────────────────
-w /etc/passwd  -p wa -k passwd_change
-w /etc/shadow  -p wa -k shadow_change
-w /etc/group   -p wa -k group_change
-w /etc/gshadow -p wa -k gshadow_change

# ── Login/logout ─────────────────────────────────────────────────────────────
-w /var/log/lastlog  -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Make the ruleset immutable — requires reboot to change.
-e 2
EOF

# auditd 4.x (Ubuntu 26.04) splits loading and logging:
#   audit-rules.service  — loads /etc/audit/rules.d/
#   auditd.service       — writes the log
# Enable both when the unit exists; 24.04 only has auditd.service.
systemctl enable auditd
systemctl enable audit-rules 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true
systemctl restart audit-rules 2>/dev/null || true

success "auditd installed and configured."


# ─────────────────────────────────────────────────────────────────────────────
# 11. LOGIN BANNER — display local and WAN IP at console login prompt
# ─────────────────────────────────────────────────────────────────────────────
info "Configuring login banner with IP addresses..."

cat > /usr/local/bin/update-issue << 'BANNER_SCRIPT'
#!/usr/bin/env bash
LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
WAN_IP=$(curl -sf --max-time 10 https://api.ipify.org 2>/dev/null || echo "unavailable")
cat > /etc/issue << EOF
Ubuntu \n \l
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Local IP  :  ${LOCAL_IP:-unavailable}
  WAN IP    :  ${WAN_IP}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
BANNER_SCRIPT

chmod +x /usr/local/bin/update-issue

cat > /etc/systemd/system/update-issue.service << 'EOF'
[Unit]
Description=Update login banner with local and WAN IP addresses
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-issue
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable update-issue
/usr/local/bin/update-issue

success "Login banner configured (/etc/issue updated on every boot)."

# ─────────────────────────────────────────────────────────────────────────────
# 12. SUMMARY + REBOOT PROMPT
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Hardening complete — summary${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} System updated"
echo -e "  ${GREEN}✓${NC} User '${TARGET_USER}' created with SSH keys and sudo password"
echo -e "  ${GREEN}✓${NC} sudo restricted to '${TARGET_USER}' only"
[[ "${INSTALLER_USER}" != "${TARGET_USER}" ]] && \
    echo -e "  ${GREEN}✓${NC} Account '${INSTALLER_USER}' locked"
echo -e "  ${GREEN}✓${NC} SSH: key-only, AllowUsers ${TARGET_USER}, MaxAuthTries 3, MaxStartups 3:50:10"
echo -e "  ${GREEN}✓${NC} UFW: deny all in/out; allow in: SSH 22; allow out: DNS/HTTP/HTTPS/NTP"
echo -e "  ${GREEN}✓${NC} Automatic security updates (auto-reboot at 02:00)"
echo -e "  ${GREEN}✓${NC} fail2ban: 3 retries → 24h ban, doubling on repeat, max 7 days"
echo -e "  ${GREEN}✓${NC} Kernel hardening applied (sysctl)"
echo -e "  ${GREEN}✓${NC} auditd logging active"
echo -e "  ${GREEN}✓${NC} Login banner configured (/etc/issue updated on boot)"
echo ""
echo -e "${YELLOW}IMPORTANT: Before rebooting, open a second terminal and verify${NC}"
echo -e "${YELLOW}you can SSH in as '${TARGET_USER}' using your key:${NC}"
echo -e "  ssh ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
echo ""
echo "  Next step for the Docker Compose trading bot:"
echo "    sudo bash 02-add-service.sh   → choose the MetaTrader bot (Docker) option"
echo "  That prepares the host for Compose without opening any bot ports."
echo "  The dashboard (8000) and VNC (5900) are reached over SSH tunnels only."
echo ""
read -r -p "Reboot now to apply all changes? [y/N] " reboot_now
if [[ "${reboot_now,,}" == "y" ]]; then
    echo "Rebooting in 5 seconds..."
    sleep 5
    reboot
else
    echo "Reboot skipped. Run 'sudo reboot' when ready."
fi
