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

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || { echo -e "${RED}[FAIL]${NC}  Run as root: sudo bash 03-verify-hardening.sh" >&2; exit 1; }

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ Hardening — Verification Report${NC}"
echo -e "${CYAN}============================================================${NC}"
echo "  Host    : $(hostname)"
echo "  Date    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Kernel  : $(uname -r)"
echo "  OS      : $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"

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
    KEY_COUNT=$(grep -c 'ssh-' "${KEYS_FILE}" 2>/dev/null || true)
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
check_sshd "allowtcpforwarding"         "no"  "TCP forwarding disabled"
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

# Hardening drop-in file exists
SSH_DROP_IN="/etc/ssh/sshd_config.d/99-hardening.conf"
if [[ -f "${SSH_DROP_IN}" ]]; then
    pass "Hardening drop-in exists: ${SSH_DROP_IN}"
else
    fail "Hardening drop-in NOT found: ${SSH_DROP_IN}"
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

# ─────────────────────────────────────────────────────────────────────────────
# 5. AUTOMATIC SECURITY UPDATES
# ─────────────────────────────────────────────────────────────────────────────
header "5. Automatic security updates"

if systemctl is-active --quiet unattended-upgrades; then
    pass "unattended-upgrades service is running."
else
    fail "unattended-upgrades service is NOT running."
fi

if systemctl is-enabled --quiet unattended-upgrades; then
    pass "unattended-upgrades is enabled at boot."
else
    fail "unattended-upgrades is NOT enabled at boot."
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

check_sysctl "net.ipv4.ip_forward"                    "0" "IPv4 forwarding disabled"
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

# ─────────────────────────────────────────────────────────────────────────────
# 9. PENDING SECURITY UPDATES
# ─────────────────────────────────────────────────────────────────────────────
header "9. Pending security updates"

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
