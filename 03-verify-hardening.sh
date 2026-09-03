#!/usr/bin/env bash
# =============================================================================
# 03-verify-hardening.sh
# Verifies that all hardening applied by 01-initial-setup.sh is still in effect.
# Run as the admin user (with sudo) at any time to audit the server's security
# posture — after a reboot, after a package upgrade, or on a routine schedule.
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
# =============================================================================

set -uo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass()  { echo -e "  ${GREEN}[PASS]${NC}  $*"; (( PASS_COUNT++ )) || true; }
fail()  { echo -e "  ${RED}[FAIL]${NC}  $*"; (( FAIL_COUNT++ )) || true; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
info()  { echo -e "  ${CYAN}[INFO]${NC}  $*"; }
header(){ echo ""; echo -e "${CYAN}── $* ──${NC}"; }

PASS_COUNT=0
FAIL_COUNT=0

# Ports belonging to the Docker Compose trading bot. None of these may be
# reachable from the WAN — the dashboard and VNC are reached over SSH tunnels.
#   8000 dashboard │ 5900 VNC │ 8765 EA bridge │ 5432 timescaledb │ 6379 redis
BOT_PORTS=(5432 6379 5900 8765 8000)
DOCKER_FORWARD_SYSCTL="/etc/sysctl.d/99-docker-forward.conf"

# Docker needs net.ipv4.ip_forward = 1. Treat that as acceptable only when the
# documented drop-in written by 02-add-service.sh is present.
DOCKER_EXCEPTION=false
[[ -f "${DOCKER_FORWARD_SYSCTL}" ]] && DOCKER_EXCEPTION=true

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || { echo -e "${RED}[FAIL]${NC}  Run as root: sudo bash 03-verify-hardening.sh" >&2; exit 1; }

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ Hardening — Verification Report${NC}"
echo -e "${CYAN}============================================================${NC}"
. /etc/os-release
UBUNTU_VERSION="${VERSION_ID:-unknown}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-unknown}}"

echo "  Host    : $(hostname)"
echo "  Date    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Kernel  : $(uname -r)"
echo "  Ubuntu  : ${UBUNTU_VERSION} (${UBUNTU_CODENAME})"
echo "  OS      : $(lsb_release -ds 2>/dev/null || echo "${PRETTY_NAME:-unknown}")"

case "${UBUNTU_VERSION}" in
    24.04|26.04) ;;
    *) warn "Untested Ubuntu ${UBUNTU_VERSION}. Supported releases: 24.04 and 26.04." ;;
esac

# ── Prompt for admin username to validate ────────────────────────────────────
echo ""
while true; do
    read -r -p "  Admin username to verify (e.g. the name you entered in 01-initial-setup.sh): " TARGET_USER
    if [[ -z "${TARGET_USER}" ]]; then
        echo "  Username cannot be empty."
    elif ! id "${TARGET_USER}" &>/dev/null; then
        echo "  User '${TARGET_USER}' does not exist on this system. Try again."
    else
        break
    fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. USER ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────
header "1. User accounts"

# Admin user exists
if id "${TARGET_USER}" &>/dev/null; then
    pass "User '${TARGET_USER}' exists."
else
    fail "User '${TARGET_USER}' does not exist."
fi

# Admin user is in sudo group
if id -nG "${TARGET_USER}" 2>/dev/null | grep -qw sudo; then
    pass "'${TARGET_USER}' is in the sudo group."
else
    fail "'${TARGET_USER}' is NOT in the sudo group."
fi

# No other non-system accounts have sudo
OTHER_SUDO=()
while IFS=: read -r username _ uid _; do
    if [[ "${uid}" -ge 1000 && "${uid}" -lt 60000 && "${username}" != "${TARGET_USER}" ]]; then
        if id -nG "${username}" 2>/dev/null | grep -qw sudo; then
            OTHER_SUDO+=("${username}")
        fi
    fi
done < /etc/passwd

if [[ ${#OTHER_SUDO[@]} -eq 0 ]]; then
    pass "No other non-system accounts are in the sudo group."
else
    fail "Unexpected sudo members: ${OTHER_SUDO[*]}"
fi

# Installer/ubuntu account is locked
for locked_candidate in ubuntu; do
    if id "${locked_candidate}" &>/dev/null 2>&1 && [[ "${locked_candidate}" != "${TARGET_USER}" ]]; then
        lock_status=$(passwd -S "${locked_candidate}" 2>/dev/null | awk '{print $2}')
        if [[ "${lock_status}" == "L" ]]; then
            pass "Account '${locked_candidate}' is locked."
        else
            warn "Account '${locked_candidate}' exists and is NOT locked (status: ${lock_status})."
        fi
    fi
done

# Admin has at least one SSH authorized key
KEYS_FILE="/home/${TARGET_USER}/.ssh/authorized_keys"
if [[ -s "${KEYS_FILE}" ]]; then
    # Count real key lines, not just those containing "ssh-" (ecdsa-sha2-nistp256
    # and sk-ecdsa keys do not).
    KEY_COUNT=$(grep -cE '^(ssh-|ecdsa-|sk-)' "${KEYS_FILE}" 2>/dev/null || true)
    pass "'${TARGET_USER}' has ${KEY_COUNT} SSH authorized key(s)."
else
    fail "No SSH authorized_keys found for '${TARGET_USER}' — login will require a password or fail entirely."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. SSH DAEMON
# ─────────────────────────────────────────────────────────────────────────────
header "2. SSH daemon"

# Collect effective sshd configuration
SSHD_T=$(sshd -T 2>/dev/null)

check_sshd() {
    local key="$1" expected="$2" label="$3"
    local actual
    actual=$(echo "${SSHD_T}" | grep -i "^${key} " | awk '{print tolower($2)}')
    if [[ "${actual}" == "${expected}" ]]; then
        pass "${label} (${key} = ${actual})"
    else
        fail "${label} — expected '${expected}', got '${actual:-<not set>}'"
    fi
}

check_sshd "permitrootlogin"             "no"  "Root login disabled"
check_sshd "passwordauthentication"      "no"  "Password authentication disabled"
check_sshd "pubkeyauthentication"        "yes" "Public key authentication enabled"
check_sshd "x11forwarding"              "no"  "X11 forwarding disabled"
check_sshd "allowagentforwarding"       "no"  "Agent forwarding disabled"
# 01 sets AllowTcpForwarding local so ssh -L to 127.0.0.1 works (VNC / dashboard).
# "no" is also acceptable on a host that never needed tunnels.
ALLOW_TCP=$(echo "${SSHD_T}" | grep -i '^allowtcpforwarding ' | awk '{print tolower($2)}')
if [[ "${ALLOW_TCP}" == "local" || "${ALLOW_TCP}" == "no" ]]; then
    pass "TCP forwarding is ${ALLOW_TCP} (local tunnels only, or fully disabled)."
else
    fail "TCP forwarding — expected 'local' or 'no', got '${ALLOW_TCP:-<not set>}'"
fi
check_sshd "permittunnel"               "no"  "Tunnel disabled"
check_sshd "kbdinteractiveauthentication" "no" "Keyboard-interactive auth disabled"

# AllowUsers contains our target user
ALLOW_USERS=$(echo "${SSHD_T}" | grep -i '^allowusers ' | awk '{$1=""; print tolower($0)}' | tr -s ' ')
if echo "${ALLOW_USERS}" | grep -qw "${TARGET_USER,,}"; then
    pass "AllowUsers includes '${TARGET_USER}'."
else
    fail "AllowUsers does not include '${TARGET_USER}' (got:${ALLOW_USERS:-<empty>})."
fi

# MaxAuthTries
MAX_AUTH=$(echo "${SSHD_T}" | grep -i '^maxauthtries ' | awk '{print $2}')
if [[ -n "${MAX_AUTH}" && "${MAX_AUTH}" -le 3 ]]; then
    pass "MaxAuthTries = ${MAX_AUTH} (≤ 3)."
else
    fail "MaxAuthTries = ${MAX_AUTH:-<not set>} (should be ≤ 3)."
fi

# LoginGraceTime
GRACE=$(echo "${SSHD_T}" | grep -i '^logingracetime ' | awk '{print $2}')
if [[ -n "${GRACE}" && "${GRACE}" -le 30 ]]; then
    pass "LoginGraceTime = ${GRACE}s (≤ 30 s)."
else
    warn "LoginGraceTime = ${GRACE:-<not set>} (recommended ≤ 30 s)."
fi

# Hardening drop-in: 00- sorts first (OpenSSH first-wins). 99- is the old name
# and loses to 50-cloud-init.conf (PasswordAuthentication yes).
if [[ -f /etc/ssh/sshd_config.d/00-hardening.conf ]]; then
    pass "Hardening drop-in exists: /etc/ssh/sshd_config.d/00-hardening.conf"
elif [[ -f /etc/ssh/sshd_config.d/99-hardening.conf ]]; then
    fail "Only 99-hardening.conf exists — 50-cloud-init.conf wins (passwords stay on). Re-run 01."
else
    fail "Hardening drop-in NOT found (expected /etc/ssh/sshd_config.d/00-hardening.conf)."
fi

if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]] \
    && grep -qE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config.d/50-cloud-init.conf; then
    fail "50-cloud-init.conf still has PasswordAuthentication yes — OpenSSH first-wins keeps passwords on."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. FIREWALL (UFW)
# ─────────────────────────────────────────────────────────────────────────────
header "3. Firewall (UFW)"

UFW_STATUS=$(ufw status verbose 2>/dev/null)

if echo "${UFW_STATUS}" | grep -q "Status: active"; then
    pass "UFW is active."
else
    fail "UFW is NOT active."
fi

if echo "${UFW_STATUS}" | grep -q "Default: deny (incoming)"; then
    pass "Default inbound policy: deny."
else
    fail "Default inbound policy is NOT 'deny'."
fi

if echo "${UFW_STATUS}" | grep -q "Default: deny (outgoing)"; then
    pass "Default outbound policy: deny."
else
    fail "Default outbound policy is NOT 'deny'."
fi

# Required inbound
if echo "${UFW_STATUS}" | grep -qE "22/(tcp|v6)\s+ALLOW IN"; then
    pass "Inbound SSH (22/tcp) is allowed."
else
    fail "Inbound SSH (22/tcp) is NOT explicitly allowed."
fi

# Required outbound
for rule_desc in "53.*ALLOW OUT.*DNS" "80/tcp.*ALLOW OUT" "443/tcp.*ALLOW OUT" "123/udp.*ALLOW OUT"; do
    if echo "${UFW_STATUS}" | grep -qE "${rule_desc}"; then
        label=$(echo "${rule_desc}" | grep -oE '[0-9]+(/(tcp|udp))?' | head -1)
        pass "Outbound ${label} is allowed."
    else
        label=$(echo "${rule_desc}" | grep -oE '[0-9]+(/(tcp|udp))?' | head -1)
        fail "Outbound ${label} is NOT allowed."
    fi
done

# ── Trading bot ports must never be allowed inbound from Anywhere ────────────
# A source-restricted rule (ALLOW IN ... FROM 203.0.113.4) is a deliberate
# choice, so only an unrestricted "Anywhere" rule is treated as a failure.
UFW_NUMBERED=$(ufw status numbered 2>/dev/null)
for port in "${BOT_PORTS[@]}"; do
    # The From column must be "Anywhere" to count as WAN-exposed. The trailing
    # (#.*)? matters: every rule these scripts create carries a comment, and
    # anchoring on "Anywhere$" alone would silently miss all of them.
    exposed=$(echo "${UFW_NUMBERED}" \
        | grep -E "(^|[^0-9])${port}(/(tcp|udp))?[[:space:]]" \
        | grep 'ALLOW IN' \
        | grep -E 'Anywhere( \(v6\))?[[:space:]]*(#.*)?$' || true)

    if [[ -z "${exposed}" ]]; then
        pass "Bot port ${port} is not allowed inbound from Anywhere."
    else
        fail "Bot port ${port} IS allowed inbound from Anywhere — remove it, use an SSH tunnel."
        echo "         ${exposed}" | head -2
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# 4. FAIL2BAN
# ─────────────────────────────────────────────────────────────────────────────
header "4. fail2ban"

if systemctl is-active --quiet fail2ban; then
    pass "fail2ban service is running."
else
    fail "fail2ban service is NOT running."
fi

if systemctl is-enabled --quiet fail2ban; then
    pass "fail2ban is enabled at boot."
else
    fail "fail2ban is NOT enabled at boot."
fi

SSH_JAIL=$(fail2ban-client status sshd 2>/dev/null)
if [[ -n "${SSH_JAIL}" ]]; then
    CURRENTLY_BANNED=$(echo "${SSH_JAIL}" | grep -i 'Currently banned' | awk -F: '{print $2}' | tr -d ' ')
    TOTAL_BANNED=$(echo "${SSH_JAIL}" | grep -i 'Total banned' | awk -F: '{print $2}' | tr -d ' ')
    pass "sshd jail active — currently banned: ${CURRENTLY_BANNED:-0}, total: ${TOTAL_BANNED:-0}."
else
    fail "sshd fail2ban jail is NOT active (fail2ban-client status sshd failed)."
fi

# 24.04/26.04 have no /var/log/auth.log unless rsyslog is installed. A file
# backend jail will sit idle. backend=systemd is required.
F2B_BACKEND=$(fail2ban-client get sshd backend 2>/dev/null || true)
if echo "${F2B_BACKEND}" | grep -qw systemd; then
    pass "sshd jail reads systemd-journald (backend = systemd)."
elif [[ -n "${F2B_BACKEND}" ]]; then
    fail "sshd jail backend is not systemd (${F2B_BACKEND}) — bans will miss journal-only SSH logs."
fi

if ! dpkg -s python3-systemd >/dev/null 2>&1; then
    warn "python3-systemd is not installed — backend=systemd cannot query the journal."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. AUTOMATIC SECURITY UPDATES
# ─────────────────────────────────────────────────────────────────────────────
header "5. Automatic security updates"

# 24.04: unattended-upgrades.service is a long-running unit.
# 26.04: the same unit may be oneshot/inactive between runs; the timers are
# what actually fire. Accept either activation model.
if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null \
    || systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null; then
    pass "Automatic upgrades are enabled (unattended-upgrades and/or apt-daily-upgrade.timer)."
else
    fail "Neither unattended-upgrades nor apt-daily-upgrade.timer is enabled."
fi

if systemctl is-active --quiet unattended-upgrades \
    || systemctl is-active --quiet apt-daily-upgrade.timer; then
    pass "Automatic-upgrade path is active."
else
    warn "unattended-upgrades is not running right now (oneshot units look inactive between runs)."
fi

if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    pass "/etc/apt/apt.conf.d/20auto-upgrades exists."
else
    fail "/etc/apt/apt.conf.d/20auto-upgrades is missing."
fi

if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    if grep -q 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/50unattended-upgrades; then
        REBOOT_TIME=$(grep 'Automatic-Reboot-Time' /etc/apt/apt.conf.d/50unattended-upgrades | grep -oE '"[^"]*"')
        pass "Auto-reboot enabled (scheduled at ${REBOOT_TIME:-02:00})."
    else
        warn "Auto-reboot is not enabled in 50unattended-upgrades."
    fi
else
    fail "/etc/apt/apt.conf.d/50unattended-upgrades is missing."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. KERNEL HARDENING (sysctl)
# ─────────────────────────────────────────────────────────────────────────────
header "6. Kernel hardening (sysctl)"

check_sysctl() {
    local key="$1" expected="$2" label="$3"
    local actual
    actual=$(sysctl -n "${key}" 2>/dev/null)
    if [[ "${actual}" == "${expected}" ]]; then
        pass "${label} (${key} = ${actual})"
    else
        fail "${label} — expected ${expected}, got '${actual:-<not set>}'"
    fi
}

# IPv4 forwarding is the one DMZ value Docker legitimately needs to flip.
# It counts as a PASS only when the documented drop-in from 02-add-service.sh
# explains why — an unexplained ip_forward = 1 is still a failure.
IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [[ "${DOCKER_EXCEPTION}" == true ]]; then
    if [[ "${IP_FORWARD}" == "1" ]]; then
        pass "IPv4 forwarding enabled — Docker exception ($(basename "${DOCKER_FORWARD_SYSCTL}"))."
    else
        fail "Docker exception file exists but ip_forward = ${IP_FORWARD:-<not set>}; Docker bridge networking will not work."
    fi
elif [[ "${IP_FORWARD}" == "0" ]]; then
    pass "IPv4 forwarding disabled (net.ipv4.ip_forward = 0)."
else
    fail "IPv4 forwarding is enabled with no documented Docker exception."
    echo "         Expected ${DOCKER_FORWARD_SYSCTL} to exist. If this host runs"
    echo "         the Docker bot, run 02-add-service.sh option 1. Otherwise set it back to 0."
fi

check_sysctl "net.ipv6.conf.all.forwarding"           "0" "IPv6 forwarding disabled"
check_sysctl "net.ipv4.conf.all.send_redirects"       "0" "ICMP redirects (send) disabled"
check_sysctl "net.ipv4.conf.all.accept_redirects"     "0" "ICMP redirects (accept, IPv4) disabled"
check_sysctl "net.ipv6.conf.all.accept_redirects"     "0" "ICMP redirects (accept, IPv6) disabled"
check_sysctl "net.ipv4.conf.all.accept_source_route"  "0" "Source routing disabled"
check_sysctl "net.ipv4.tcp_syncookies"                "1" "SYN cookies enabled"
check_sysctl "net.ipv4.conf.all.rp_filter"            "1" "Reverse-path filtering enabled"
check_sysctl "net.ipv4.conf.all.log_martians"         "1" "Martian packet logging enabled"
check_sysctl "net.ipv6.conf.all.accept_ra"            "0" "IPv6 router advertisements disabled"
check_sysctl "kernel.randomize_va_space"              "2" "Full ASLR enabled"
check_sysctl "kernel.dmesg_restrict"                  "1" "dmesg restricted to root"
check_sysctl "kernel.kptr_restrict"                   "2" "Kernel pointer leaks restricted"
check_sysctl "fs.protected_hardlinks"                 "1" "Hard link protection enabled"
check_sysctl "fs.protected_symlinks"                  "1" "Symbolic link protection enabled"
check_sysctl "kernel.yama.ptrace_scope"               "1" "ptrace scope restricted"
check_sysctl "kernel.sysrq"                           "0" "SysRq key disabled"

SYSCTL_FILE="/etc/sysctl.d/99-dmz-hardening.conf"
if [[ -f "${SYSCTL_FILE}" ]]; then
    pass "sysctl config file exists: ${SYSCTL_FILE}"
else
    fail "sysctl config file NOT found: ${SYSCTL_FILE}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. AUDIT LOGGING (auditd)
# ─────────────────────────────────────────────────────────────────────────────
header "7. Audit logging (auditd)"

if systemctl is-active --quiet auditd; then
    pass "auditd service is running."
else
    fail "auditd service is NOT running."
fi

if systemctl is-enabled --quiet auditd; then
    pass "auditd is enabled at boot."
else
    fail "auditd is NOT enabled at boot."
fi

# auditd 4.x (Ubuntu 26.04) loads rules from a separate unit. Skip on 24.04
# where the unit does not exist.
if systemctl list-unit-files audit-rules.service &>/dev/null \
    && systemctl list-unit-files audit-rules.service | grep -q audit-rules; then
    if systemctl is-enabled --quiet audit-rules 2>/dev/null; then
        pass "audit-rules.service is enabled (26.04 rules loader)."
    else
        fail "audit-rules.service exists but is not enabled — rules may not load on boot."
    fi
    if systemctl is-active --quiet audit-rules 2>/dev/null \
        || systemctl show -p Result --value audit-rules 2>/dev/null | grep -q success; then
        pass "audit-rules.service has loaded (or last run succeeded)."
    else
        warn "audit-rules.service is not active — check 'systemctl status audit-rules'."
    fi
fi

AUDIT_RULES_FILE="/etc/audit/rules.d/99-dmz.rules"
if [[ -f "${AUDIT_RULES_FILE}" ]]; then
    pass "Audit rules file exists: ${AUDIT_RULES_FILE}"
else
    fail "Audit rules file NOT found: ${AUDIT_RULES_FILE}"
fi

# Confirm rules are loaded and the ruleset is immutable (-e 2)
AUDIT_STATUS=$(auditctl -s 2>/dev/null || true)
if echo "${AUDIT_STATUS}" | grep -q "enabled 2"; then
    pass "Audit ruleset is immutable (-e 2)."
elif echo "${AUDIT_STATUS}" | grep -q "enabled 1"; then
    warn "Audit ruleset is active but NOT immutable (-e 2 not set)."
else
    fail "Could not confirm auditd enabled status."
fi

LOADED_RULES=$(auditctl -l 2>/dev/null | wc -l)
if [[ "${LOADED_RULES}" -gt 5 ]]; then
    pass "${LOADED_RULES} audit rules loaded."
else
    fail "Only ${LOADED_RULES} audit rules loaded — expected more. Check /etc/audit/rules.d/."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. LOGIN BANNER
# ─────────────────────────────────────────────────────────────────────────────
header "8. Login banner"

if [[ -x /usr/local/bin/update-issue ]]; then
    pass "/usr/local/bin/update-issue script exists and is executable."
else
    warn "/usr/local/bin/update-issue not found — login banner not configured."
fi

if systemctl is-enabled --quiet update-issue 2>/dev/null; then
    pass "update-issue service is enabled at boot."
else
    warn "update-issue service is NOT enabled at boot."
fi

if [[ -f /etc/issue ]]; then
    if grep -qE 'Local IP[[:space:]]*:[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /etc/issue; then
        pass "/etc/issue shows a local IPv4 address."
    else
        warn "/etc/issue has no local IPv4 (still 'unavailable'?). Run: sudo /usr/local/bin/update-issue"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 9. DOCKER CONTAINMENT
# ─────────────────────────────────────────────────────────────────────────────
# Only meaningful once Docker is installed. Published container ports are DNAT'd
# and traverse FORWARD, so UFW's INPUT rules never see them — "deny incoming"
# does not hide a container published on 0.0.0.0. These checks look at the two
# things that actually contain it: the loopback bind and the DOCKER-USER guard.
header "9. Docker containment"

if ! command -v docker &>/dev/null; then
    info "Docker is not installed — skipping container checks."
else
    if systemctl is-active --quiet docker; then
        pass "Docker daemon is running."
    else
        warn "Docker is installed but the daemon is not running."
    fi

    # ── DOCKER-USER guard ──
    if [[ -x /usr/local/bin/docker-user-guard ]]; then
        pass "DOCKER-USER guard script is installed."
    else
        warn "DOCKER-USER guard not installed. Run 02-add-service.sh option 1."
    fi

    if systemctl is-enabled --quiet docker-user-guard 2>/dev/null; then
        pass "docker-user-guard service is enabled."
    else
        warn "docker-user-guard service is NOT enabled — rules will be lost on Docker restart."
    fi

    # Confirm the DROP rules are actually loaded. 24.04 uses iptables DOCKER-USER;
    # 26.04 / Docker 29 may only have the nftables table we install alongside it.
    GUARD_OK=false
    if command -v iptables &>/dev/null; then
        DOCKER_USER_RULES=$(iptables -S DOCKER-USER 2>/dev/null || true)
        if echo "${DOCKER_USER_RULES}" | grep -q 'multiport.*DROP'; then
            pass "iptables DOCKER-USER chain contains the bot-port DROP rules."
            GUARD_OK=true
        fi
    fi
    if command -v nft &>/dev/null; then
        if nft list table inet hardening-docker-user >/dev/null 2>&1; then
            pass "nftables table hardening-docker-user is loaded (26.04 Docker nft backend)."
            GUARD_OK=true
        fi
    fi
    if [[ "${GUARD_OK}" == false ]]; then
        if systemctl is-active --quiet docker; then
            fail "No live bot-port DROP rules found (iptables DOCKER-USER or nftables hardening-docker-user)."
            echo "         Run 02-add-service.sh option 1 so the guard is applied."
        else
            warn "No live bot-port DROP rules (Docker is not running, so the chains are empty)."
            echo "         They are applied by docker-user-guard.service when Docker starts."
        fi
    fi

    # ── Published ports must be loopback-bound ──
    # 0.0.0.0 or [::] in the host side of a published port means WAN-reachable.
    if systemctl is-active --quiet docker; then
        PUBLISHED=$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null || true)
        if [[ -z "${PUBLISHED}" ]]; then
            info "No running containers to inspect."
        else
            WIDE_OPEN=$(echo "${PUBLISHED}" | grep -E '0\.0\.0\.0:|\[::\]:' || true)
            if [[ -z "${WIDE_OPEN}" ]]; then
                pass "No running container publishes a port on all interfaces."
            else
                fail "Container port(s) published on all interfaces:"
                echo "${WIDE_OPEN}" | while IFS= read -r line; do
                    [[ -n "${line}" ]] && echo "         ${line}"
                done
                echo "         Re-publish as 127.0.0.1:HOST:CONTAINER and recreate the container."
            fi
        fi
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 10. PENDING SECURITY UPDATES
# ─────────────────────────────────────────────────────────────────────────────
header "10. Pending security updates"

apt-get update -qq 2>/dev/null || warn "apt-get update failed — could not check for pending updates."
PENDING=$(apt-get --just-print upgrade 2>/dev/null \
    | grep -c '^Inst' || true)
if [[ "${PENDING}" -eq 0 ]]; then
    pass "No pending package upgrades."
else
    warn "${PENDING} package upgrade(s) pending. Run: sudo apt-get upgrade"
fi

SECURITY_PENDING=$(apt-get --just-print upgrade 2>/dev/null \
    | grep '^Inst' | grep -c 'security' || true)
if [[ "${SECURITY_PENDING}" -eq 0 ]]; then
    pass "No pending security upgrades."
else
    fail "${SECURITY_PENDING} security upgrade(s) pending — apply immediately."
fi

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Verification Summary${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  ${GREEN}Passed : ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed : ${FAIL_COUNT}${NC}"
echo ""

if [[ ${FAIL_COUNT} -eq 0 ]]; then
    echo -e "  ${GREEN}All checks passed. Server hardening posture is intact.${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}${FAIL_COUNT} check(s) failed. Review the output above and remediate.${NC}"
    echo ""
    exit 1
fi
