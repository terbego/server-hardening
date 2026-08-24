#!/usr/bin/env bash
# =============================================================================
# 02-add-service.sh
# Interactive script to expose a new service on the server.
# Run as yasin (with sudo) any time a new service is added.
#
# For each service this script will:
#   • Open the required UFW ports (scoped to a source IP where appropriate)
#   • Install the service package if not already present
#   • Apply service-specific hardening
#   • Add a fail2ban jail where applicable
#   • Reload UFW and the service
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo ./02-add-service.sh)."
command -v ufw &>/dev/null || die "UFW is not installed. Run 01-initial-setup.sh first."

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# Ask for an optional source IP/CIDR restriction.
# Returns the value in SOURCE_IP (empty = any).
prompt_source_ip() {
    echo ""
    echo "  Restrict inbound access to a specific source IP or CIDR?"
    echo "  Leave blank to allow from any IP (not recommended for DMZ)."
    read -r -p "  Source IP/CIDR (e.g. 203.0.113.10 or 10.0.0.0/24) [blank = any]: " SOURCE_IP
}

# Opens an inbound port, optionally restricted to a source IP.
open_port() {
    local proto="$1" port="$2" comment="$3"
    if [[ -n "${SOURCE_IP:-}" ]]; then
        ufw allow from "${SOURCE_IP}" to any port "${port}" proto "${proto}" comment "${comment}"
    else
        ufw allow in "${port}/${proto}" comment "${comment}"
    fi
}

# Adds a fail2ban jail file and restarts fail2ban.
add_fail2ban_jail() {
    local jail_name="$1"
    local jail_config="$2"
    echo "${jail_config}" > "/etc/fail2ban/jail.d/${jail_name}.conf"
    systemctl restart fail2ban
    success "fail2ban jail '${jail_name}' enabled."
}

reload_ufw() {
    ufw --force reload
    success "UFW reloaded."
    ufw status numbered
}

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

setup_nginx() {
    local mode="${1:-webserver}"  # webserver | reverseproxy

    info "Installing nginx..."
    apt-get update -qq
    apt-get install -y -qq nginx certbot python3-certbot-nginx

    # ── UFW ──
    prompt_source_ip
    open_port tcp 80  "HTTP"
    open_port tcp 443 "HTTPS"

    # ── nginx hardening ──
    info "Applying nginx security hardening..."

    cat > /etc/nginx/conf.d/security.conf << 'EOF'
# Hide nginx version from error pages and response headers.
server_tokens off;

# Security headers applied to all virtual hosts.
add_header X-Frame-Options           "SAMEORIGIN"   always;
add_header X-Content-Type-Options    "nosniff"      always;
add_header X-XSS-Protection          "1; mode=block" always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header Permissions-Policy        "geolocation=(), microphone=(), camera=()" always;

# TLS hardening — applied globally; individual server blocks may override.
ssl_protocols       TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_cache   shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# Rate limiting — protect against DoS on public endpoints.
limit_req_zone $binary_remote_addr zone=global:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
EOF

    if [[ "${mode}" == "reverseproxy" ]]; then
        info "Creating reverse proxy site template..."
        cat > /etc/nginx/sites-available/reverse-proxy << 'EOF'
# Reverse proxy template — edit upstream and server_name, then enable with:
#   ln -s /etc/nginx/sites-available/reverse-proxy /etc/nginx/sites-enabled/
#   certbot --nginx -d yourdomain.com
#   nginx -t && systemctl reload nginx

upstream backend {
    server 127.0.0.1:8000;  # Change to your app's port
    keepalive 32;
}

server {
    listen 80;
    server_name yourdomain.com;  # Change to your domain

    # Redirect all HTTP to HTTPS — certbot will fill this in automatically.
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;  # Change to your domain

    # TLS — certbot will inject certificate paths here.
    # ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    limit_req  zone=global burst=60 nodelay;
    limit_conn conn_limit 20;

    location / {
        proxy_pass         http://backend;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
EOF
        warn "Reverse proxy template written to /etc/nginx/sites-available/reverse-proxy"
        warn "Edit server_name and upstream, then enable the site and run certbot."
    fi

    nginx -t && systemctl enable nginx && systemctl reload nginx

    # ── fail2ban for nginx ──
    add_fail2ban_jail "nginx-http-auth" "
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
maxretry = 5
bantime  = 1h
"
    add_fail2ban_jail "nginx-limit-req" "
[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
maxretry = 10
bantime  = 10m
"

    success "nginx installed and hardened."
    echo ""
    echo "  Next step: run certbot to obtain a TLS certificate:"
    echo "    sudo certbot --nginx -d yourdomain.com"
}

setup_python_api() {
    echo ""
    read -r -p "  Port your FastAPI/uvicorn app listens on [8000]: " API_PORT
    API_PORT="${API_PORT:-8000}"

    read -r -p "  App name (used for comments/labels) [trading-api]: " APP_NAME
    APP_NAME="${APP_NAME:-trading-api}"

    prompt_source_ip
    open_port tcp "${API_PORT}" "${APP_NAME}"

    # ── fail2ban rate-limiting jail ──
    # There is no built-in filter for uvicorn; we use a generic TCP one.
    add_fail2ban_jail "${APP_NAME}" "
[${APP_NAME}]
enabled  = true
port     = ${API_PORT}
filter   = sshd
maxretry = 20
findtime = 1m
bantime  = 30m
"

    success "Port ${API_PORT} opened for '${APP_NAME}'."
    warn "If uvicorn is not already running as a systemd service, consider:"
    echo "    sudo nano /etc/systemd/system/${APP_NAME}.service"
}

setup_postgres() {
    echo ""
    echo "  PostgreSQL is best kept on the loopback interface for a DMZ server."
    echo "  Only open port 5432 if a remote host must connect directly."
    echo ""
    read -r -p "  Open port 5432 externally? [y/N]: " open_pg
    if [[ "${open_pg,,}" != "y" ]]; then
        info "PostgreSQL stays on loopback — no UFW rule needed."
        info "Ensuring PostgreSQL binds to 127.0.0.1 only..."
        apt-get install -y -qq postgresql
        PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
        if [[ -n "${PG_CONF}" ]]; then
            sed -i "s/^#*listen_addresses\s*=.*/listen_addresses = 'localhost'/" "${PG_CONF}"
            systemctl restart postgresql
            success "PostgreSQL configured to listen on localhost only."
        else
            warn "PostgreSQL not installed yet. Install it and ensure listen_addresses = 'localhost' in postgresql.conf."
        fi
        return
    fi

    prompt_source_ip
    if [[ -z "${SOURCE_IP:-}" ]]; then
        warn "Exposing PostgreSQL to 0.0.0.0 is strongly discouraged in a DMZ."
        read -r -p "  Are you sure? [y/N]: " really
        [[ "${really,,}" == "y" ]] || { info "Skipping PostgreSQL external exposure."; return; }
    fi
    open_port tcp 5432 "PostgreSQL"

    add_fail2ban_jail "postgres" "
[postgres]
enabled  = true
port     = 5432
filter   = postgresql
maxretry = 5
bantime  = 1h
"
    success "Port 5432 opened."
    warn "Ensure pg_hba.conf allows connections only from ${SOURCE_IP:-your trusted IP}."
}

setup_mysql() {
    echo ""
    echo "  MySQL/MariaDB is best kept on the loopback interface for a DMZ server."
    echo "  Only open port 3306 if a remote host must connect directly."
    echo ""
    read -r -p "  Open port 3306 externally? [y/N]: " open_mysql
    if [[ "${open_mysql,,}" != "y" ]]; then
        info "MySQL stays on loopback — no UFW rule needed."
        info "Ensuring MySQL binds to 127.0.0.1 only..."
        DB_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
        if [[ -f "${DB_CONF}" ]]; then
            sed -i "s/^#*bind-address\s*=.*/bind-address = 127.0.0.1/" "${DB_CONF}"
            systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null || true
            success "MySQL configured to listen on localhost only."
        else
            warn "MySQL config not found. Install MySQL/MariaDB and set bind-address = 127.0.0.1."
        fi
        return
    fi

    prompt_source_ip
    if [[ -z "${SOURCE_IP:-}" ]]; then
        warn "Exposing MySQL to 0.0.0.0 is strongly discouraged in a DMZ."
        read -r -p "  Are you sure? [y/N]: " really
        [[ "${really,,}" == "y" ]] || { info "Skipping MySQL external exposure."; return; }
    fi
    open_port tcp 3306 "MySQL/MariaDB"

    add_fail2ban_jail "mysqld-auth" "
[mysqld-auth]
enabled  = true
port     = 3306
filter   = mysqld-auth
maxretry = 5
bantime  = 1h
"
    success "Port 3306 opened."
}

setup_custom_port() {
    echo ""
    read -r -p "  Port number: " CUSTOM_PORT
    [[ "${CUSTOM_PORT}" =~ ^[0-9]+$ && "${CUSTOM_PORT}" -ge 1 && "${CUSTOM_PORT}" -le 65535 ]] \
        || die "Invalid port number."

    read -r -p "  Protocol (tcp/udp) [tcp]: " CUSTOM_PROTO
    CUSTOM_PROTO="${CUSTOM_PROTO:-tcp}"
    [[ "${CUSTOM_PROTO}" == "tcp" || "${CUSTOM_PROTO}" == "udp" ]] \
        || die "Protocol must be 'tcp' or 'udp'."

    read -r -p "  Comment/label for this rule: " CUSTOM_COMMENT
    CUSTOM_COMMENT="${CUSTOM_COMMENT:-custom}"

    prompt_source_ip
    open_port "${CUSTOM_PROTO}" "${CUSTOM_PORT}" "${CUSTOM_COMMENT}"
    success "Port ${CUSTOM_PORT}/${CUSTOM_PROTO} opened."
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ — Add Service${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo "  Current UFW status:"
ufw status | sed 's/^/    /'
echo ""

while true; do
    echo ""
    echo -e "${CYAN}What service do you want to add?${NC}"
    echo "  1) Web server (nginx)                  — opens 80, 443; hardens nginx; configures Certbot"
    echo "  2) Reverse proxy (nginx)               — same as above; adds proxy_pass template for your app"
    echo "  3) FastAPI / Python API (uvicorn)      — opens a custom port; adds fail2ban jail"
    echo "  4) PostgreSQL                          — locks to loopback (recommended) or opens 5432"
    echo "  5) MySQL / MariaDB                     — locks to loopback (recommended) or opens 3306"
    echo "  6) Custom port                         — opens any port/protocol with optional source IP"
    echo "  7) Show current UFW rules"
    echo "  8) Exit"
    echo ""
    read -r -p "Choice [1-8]: " CHOICE

    case "${CHOICE}" in
        1) setup_nginx "webserver"   ; reload_ufw ;;
        2) setup_nginx "reverseproxy"; reload_ufw ;;
        3) setup_python_api          ; reload_ufw ;;
        4) setup_postgres                         ;;
        5) setup_mysql                            ;;
        6) setup_custom_port         ; reload_ufw ;;
        7) ufw status numbered ;;
        8) echo "Done."; exit 0 ;;
        *) warn "Invalid choice. Enter a number between 1 and 8." ;;
    esac

    echo ""
    read -r -p "Add another service? [y/N]: " another
    [[ "${another,,}" == "y" ]] || { echo "Done."; exit 0; }
done
