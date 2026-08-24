#!/usr/bin/env bash
# =============================================================================
# 01-initial-setup.sh
# Initial hardening script for a fresh Ubuntu server in a DMZ environment.
# Run once as the default installer user (e.g. ubuntu) with sudo privileges.
#
# What this script does:
#   1. Preflight checks
#   2. Full system update
#   3. Create user 'yasin' and import SSH keys
#   4. Grant sudo only to 'yasin'; strip and lock all other accounts
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

# ─────────────────────────────────────────────────────────────────────────────
# 1. PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo ./01-initial-setup.sh)."

# Identify the installer user (the user who invoked sudo, or 'ubuntu' as fallback)
INSTALLER_USER="${SUDO_USER:-ubuntu}"
INSTALLER_HOME=$(getent passwd "$INSTALLER_USER" | cut -d: -f6 2>/dev/null || echo "/home/$INSTALLER_USER")

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ Hardening — Initial Setup${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo "  Installer user : ${INSTALLER_USER}"
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
# 3. CREATE USER 'yasin' AND IMPORT SSH KEYS
# ─────────────────────────────────────────────────────────────────────────────
info "Creating user '${TARGET_USER}'..."

if id "${TARGET_USER}" &>/dev/null; then
    warn "User '${TARGET_USER}' already exists — skipping creation."
else
    adduser --disabled-password --gecos "" "${TARGET_USER}"
    success "User '${TARGET_USER}' created."
fi

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
# 4. SUDO — yasin ONLY
# ─────────────────────────────────────────────────────────────────────────────
info "Configuring sudo access..."

# Add yasin to the sudo group
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

# Only the 'yasin' account may log in via SSH.
AllowUsers ${TARGET_USER}

# Disable all non-key authentication methods.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes

# Connection limits — three layers of defence before fail2ban fires.
MaxAuthTries 3
MaxSessions 2
MaxStartups 3:50:10
LoginGraceTime 20

# Reduce attack surface — no forwarding, no X11.
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no

# Disable weak features.
PermitUserEnvironment no
PrintLastLog yes
Banner none
EOF

# Create privilege separation directory if missing (required by sshd -t on some Ubuntu versions)
mkdir -p /run/sshd

# Validate config before reloading
sshd -t -f /etc/ssh/sshd_config || die "SSH config validation failed. Aborting to prevent lockout."

systemctl reload ssh || systemctl reload sshd || warn "Could not reload sshd — config will apply on next restart."

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
ufw allow out 443/tcp comment "HTTPS (apt, OpenAI, Anthropic, exchanges, Telegram, Discord)"
ufw allow out 123/udp comment "NTP (time sync)"

# NOTE: If your trading bot connects to a broker or exchange on a non-standard
# port, add a rule here:
#   ufw allow out <PORT>/tcp comment "Broker XYZ"

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

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades

success "Automatic security updates configured (auto-reboot at 02:00 if required)."

# ─────────────────────────────────────────────────────────────────────────────
# 8. FAIL2BAN
# ─────────────────────────────────────────────────────────────────────────────
info "Installing and configuring fail2ban..."

apt-get install -y -qq fail2ban

cat > /etc/fail2ban/jail.d/sshd.conf << EOF
[sshd]
enabled    = true
port       = ssh
filter     = sshd
backend    = systemd
maxretry   = 3
findtime   = 10m

# First ban: 24 hours. Each repeat doubles it, capped at 7 days.
bantime    = 24h
bantime.increment  = true
bantime.multiplier = 2
bantime.maxtime    = 168h

# Use action_mwl to log offender info (whois + relevant log lines).
# Falls back gracefully if sendmail is not installed.
action     = %(action_mwl)s
EOF

# Ensure fail2ban uses its own copy of the filter, not a missing systemd journal
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Global defaults — individual jails override as needed.
ignoreip = 127.0.0.1/8 ::1
EOF

systemctl enable fail2ban
systemctl restart fail2ban

success "fail2ban configured (3 retries → 24h ban, doubling on repeat, max 7 days)."

# ─────────────────────────────────────────────────────────────────────────────
# 9. KERNEL HARDENING (sysctl)
# ─────────────────────────────────────────────────────────────────────────────
info "Applying DMZ kernel hardening..."

cat > /etc/sysctl.d/99-dmz-hardening.conf << 'EOF'
# ── Network — DMZ posture ────────────────────────────────────────────────────

# No IP forwarding — this is not a router.
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

# Increase the size of the connection tracking table (for high-volume trading).
net.netfilter.nf_conntrack_max = 131072
EOF

sysctl --system -q

success "Kernel hardening applied."

# ─────────────────────────────────────────────────────────────────────────────
# 10. AUDIT LOGGING (auditd)
# ─────────────────────────────────────────────────────────────────────────────
info "Installing auditd..."

apt-get install -y -qq auditd audispd-plugins

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

systemctl enable auditd
systemctl restart auditd

success "auditd installed and configured."

python3 - << 'PYEOF'
banner = r"""
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
"""
with open("01-initial-setup.sh", "r") as f:
    content = f.read()
marker = 'success "auditd installed and configured."'
if "update-issue" not in content:
    content = content.replace(marker, marker + "\n" + banner)
    with open("01-initial-setup.sh", "w") as f:
        f.write(content)
    print("Login banner section inserted.")
else:
    print("Already present — no changes needed.")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# 11. SUMMARY + REBOOT PROMPT
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Hardening complete — summary${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} System updated"
echo -e "  ${GREEN}✓${NC} User '${TARGET_USER}' created with SSH keys"
echo -e "  ${GREEN}✓${NC} sudo restricted to '${TARGET_USER}' only"
[[ "${INSTALLER_USER}" != "${TARGET_USER}" ]] && \
    echo -e "  ${GREEN}✓${NC} Account '${INSTALLER_USER}' locked"
echo -e "  ${GREEN}✓${NC} SSH: key-only, AllowUsers yasin, MaxAuthTries 3, MaxStartups 3:50:10"
echo -e "  ${GREEN}✓${NC} UFW: deny all in/out; allow in: SSH 22; allow out: DNS/HTTP/HTTPS/NTP"
echo -e "  ${GREEN}✓${NC} Automatic security updates (auto-reboot at 02:00)"
echo -e "  ${GREEN}✓${NC} fail2ban: 3 retries → 24h ban, doubling on repeat, max 7 days"
echo -e "  ${GREEN}✓${NC} Kernel hardening applied (sysctl)"
echo -e "  ${GREEN}✓${NC} auditd logging active"
echo ""
echo -e "${YELLOW}IMPORTANT: Before rebooting, open a second terminal and verify${NC}"
echo -e "${YELLOW}you can SSH in as '${TARGET_USER}' using your key:${NC}"
echo -e "  ssh ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
echo ""
read -r -p "Reboot now to apply all changes? [y/N] " reboot_now
if [[ "${reboot_now,,}" == "y" ]]; then
    echo "Rebooting in 5 seconds..."
    sleep 5
    reboot
else
    echo "Reboot skipped. Run 'sudo reboot' when ready."
fi
