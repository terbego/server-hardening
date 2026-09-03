#!/usr/bin/env bash
# =============================================================================
# 02-add-service.sh
# Interactive script to expose a new service on the server.
# Run as the admin user (with sudo) any time a new service is added.
#
# For each service this script will:
#   • Open the required UFW ports (scoped to a source IP where appropriate)
#   • Install the service package if not already present
#   • Apply service-specific hardening
#   • Add a fail2ban jail where applicable
#   • Reload UFW and the service
#
# The Docker/MetaTrader option is different by design: it opens NO inbound
# ports at all. It only prepares the host to run a Docker Compose stack whose
# ports stay bound to 127.0.0.1 and are reached over SSH port-forwarding.
# =============================================================================

set -euo pipefail

# Ports belonging to the Docker Compose trading bot. These must never be
# reachable from the WAN: the dashboard and VNC are reached over SSH tunnels,
# and the databases plus the EA bridge stay inside the Compose network.
#   8000 dashboard (FastAPI) │ 5900 VNC │ 8765 EA bridge
#   5432 timescaledb         │ 6379 redis
BOT_PORTS="5432,6379,5900,8765,8000"
DOCKER_FORWARD_SYSCTL="/etc/sysctl.d/99-docker-forward.conf"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

. /etc/os-release
UBUNTU_VERSION="${VERSION_ID:-unknown}"
UBUNTU_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-unknown}}"

# fail2ban ban action that works on both LTS releases.
# 24.04: iptables-nft. 26.04: native nftables. The nftables action is valid on both.
fail2ban_banaction() {
    if command -v nft &>/dev/null; then
        echo "nftables[type=multiport]"
    else
        echo "iptables-multiport"
    fi
}

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
    if systemctl restart fail2ban; then
        success "fail2ban jail '${jail_name}' enabled."
    else
        warn "Wrote /etc/fail2ban/jail.d/${jail_name}.conf but fail2ban failed to restart."
        warn "Check: sudo journalctl -u fail2ban -e"
    fi
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
        # Ubuntu 24.04 = nginx 1.24: `listen 443 ssl http2;`
        # Ubuntu 26.04 = nginx 1.28: the http2 listen parameter is gone; use `http2 on;`.
        local nginx_listen nginx_http2
        nginx_listen="    listen 443 ssl http2;"
        nginx_http2=""
        if nginx -v 2>&1 | grep -qE 'nginx/1\.(2[5-9]|[3-9])|nginx/[2-9]'; then
            nginx_listen="    listen 443 ssl;"
            nginx_http2=$'    http2 on;\n'
        fi
        cat > /etc/nginx/sites-available/reverse-proxy << EOF
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
    return 301 https://\$host\$request_uri;
}

server {
${nginx_listen}
${nginx_http2}    server_name yourdomain.com;  # Change to your domain

    # TLS — certbot will inject certificate paths here.
    # ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    limit_req  zone=global burst=60 nodelay;
    limit_conn conn_limit 20;

    location / {
        proxy_pass         http://backend;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
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

    read -r -p "  App name / systemd service name (used for labels) [trading-api]: " APP_NAME
    APP_NAME="${APP_NAME:-trading-api}"

    prompt_source_ip

    # Use 'ufw limit' to rate-limit the port (blocks IPs with >6 new connections
    # in 30 seconds via the iptables recent module) in addition to opening it.
    if [[ -n "${SOURCE_IP:-}" ]]; then
        ufw allow from "${SOURCE_IP}" to any port "${API_PORT}" proto tcp comment "${APP_NAME}"
    else
        ufw limit "${API_PORT}/tcp" comment "${APP_NAME}"
    fi

    # ── fail2ban jail backed by the systemd journal ──
    # Requires the app to run as a systemd unit named <APP_NAME>.service.
    # The filter parses 4xx/5xx lines from the uvicorn access log written to the
    # journal; adjust journalmatch if your service unit name differs.
    add_fail2ban_jail "${APP_NAME}" "
[${APP_NAME}]
enabled      = true
port         = ${API_PORT}
backend      = systemd
journalmatch = _SYSTEMD_UNIT=${APP_NAME}.service
filter       = ${APP_NAME}
maxretry     = 20
findtime     = 1m
bantime      = 30m
action       = $(fail2ban_banaction)
"

    # Write a minimal fail2ban filter that matches uvicorn's access-log format.
    # Uvicorn logs: INFO:     <ip>:<port> - "METHOD /path HTTP/1.1" <status>
    cat > "/etc/fail2ban/filter.d/${APP_NAME}.conf" << EOF
[Definition]
failregex = ^INFO:\s+<HOST>:\d+ - "(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) .+ HTTP/\d\.\d" (?:4[0-9]{2}|5[0-9]{2}) \d+$
ignoreregex =
EOF

    success "Port ${API_PORT} opened and rate-limited for '${APP_NAME}'."
    warn "If uvicorn is not already running as a systemd service, create one:"
    echo "    sudo nano /etc/systemd/system/${APP_NAME}.service"
    echo "  The fail2ban jail targets _SYSTEMD_UNIT=${APP_NAME}.service — update"
    echo "  /etc/fail2ban/jail.d/${APP_NAME}.conf if your unit name differs."
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

setup_redis() {
    echo ""
    echo "  Redis is best kept on the loopback interface for a DMZ server."
    echo "  Only open port 6379 if a remote host must connect directly."
    echo ""
    read -r -p "  Open port 6379 externally? [y/N]: " open_redis
    if [[ "${open_redis,,}" != "y" ]]; then
        info "Redis stays on loopback — no UFW rule needed."
        info "Installing Redis and locking it to 127.0.0.1..."
        apt-get install -y -qq redis-server

        REDIS_CONF="/etc/redis/redis.conf"
        if [[ -f "${REDIS_CONF}" ]]; then
            # Bind to loopback only
            sed -i 's/^bind .*/bind 127.0.0.1 -::1/' "${REDIS_CONF}"
            # Disable protected-mode warning (bind already restricts access)
            sed -i 's/^protected-mode .*/protected-mode yes/' "${REDIS_CONF}"

            # Prompt for a Redis password (requirepass)
            echo ""
            read -r -p "  Set a Redis password? (strongly recommended) [y/N]: " set_pass
            if [[ "${set_pass,,}" == "y" ]]; then
                read -r -s -p "  Redis password: " REDIS_PASS
                echo ""
                if [[ -n "${REDIS_PASS}" ]]; then
                    # Remove any existing requirepass line, then append
                    sed -i '/^requirepass /d' "${REDIS_CONF}"
                    echo "requirepass ${REDIS_PASS}" >> "${REDIS_CONF}"
                    success "Redis password set."
                else
                    warn "Empty password entered — skipping requirepass."
                fi
            fi

            # Disable dangerous commands
            cat >> "${REDIS_CONF}" << 'REDIS_HARDENING'

# Hardening — disable commands that can overwrite files or crash the server.
rename-command FLUSHALL ""
rename-command FLUSHDB  ""
rename-command DEBUG    ""
rename-command CONFIG   ""
rename-command SHUTDOWN SHUTDOWN_RESTRICTED
REDIS_HARDENING

            systemctl enable redis-server
            systemctl restart redis-server
            success "Redis configured to listen on localhost only with hardening applied."
        else
            warn "Redis config not found at ${REDIS_CONF}. Install redis-server manually."
        fi
        return
    fi

    prompt_source_ip
    if [[ -z "${SOURCE_IP:-}" ]]; then
        warn "Exposing Redis to 0.0.0.0 is strongly discouraged in a DMZ."
        read -r -p "  Are you sure? [y/N]: " really
        [[ "${really,,}" == "y" ]] || { info "Skipping Redis external exposure."; return; }
    fi
    open_port tcp 6379 "Redis"

    add_fail2ban_jail "redis" "
[redis]
enabled  = true
port     = 6379
filter   = redis-auth
maxretry = 5
bantime  = 1h
"
    success "Port 6379 opened."
    warn "Ensure Redis has 'requirepass' set and 'bind' includes only trusted interfaces."
}

# ─────────────────────────────────────────────────────────────────────────────
# DOCKER / METATRADER BOT — localhost only, reached over SSH tunnels
# ─────────────────────────────────────────────────────────────────────────────

# Enables IPv4 forwarding for Docker's bridge/NAT without touching any other
# value in 99-dmz-hardening.conf. The filename sorts after that file, so only
# this single key is overridden.
enable_docker_forwarding() {
    info "Enabling IPv4 forwarding for Docker bridge networking..."

    cat > "${DOCKER_FORWARD_SYSCTL}" << 'EOF'
# Managed by 02-add-service.sh — Docker exception to the DMZ sysctl baseline.
#
# Docker's bridge networking NATs container traffic through the host, which
# requires IPv4 forwarding. 99-dmz-hardening.conf sets ip_forward = 0; this
# file sorts after it, so it overrides that one key and nothing else.
#
# Inbound exposure is still controlled by UFW (default deny) plus the
# DOCKER-USER guard installed by this script. Enabling forwarding does not
# publish anything on its own.
net.ipv4.ip_forward = 1

# IPv6 forwarding stays disabled — the Compose stack is IPv4 only.
net.ipv6.conf.all.forwarding = 0
EOF

    # Same trap as 01: --system exits non-zero if any key is unknown
    # (nf_conntrack_max before the module is loaded). Do not abort option 1.
    sysctl --system >/dev/null 2>&1 || true
    sysctl -p "${DOCKER_FORWARD_SYSCTL}" >/dev/null 2>&1 || true
    local actual
    actual=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "${actual}" == "1" ]]; then
        success "IPv4 forwarding enabled via ${DOCKER_FORWARD_SYSCTL}"
    else
        warn "ip_forward is still '${actual}'. Check for a later-sorting file in /etc/sysctl.d/."
    fi
}

# Docker publishes ports by inserting DNAT rules that are traversed BEFORE UFW's
# INPUT chain, so `ufw default deny incoming` does NOT hide a container port that
# was published on 0.0.0.0. Binding to 127.0.0.1 in compose.yml is the primary
# defence; this guard is the backstop for when someone forgets.
#
# Two backends:
#   24.04 / Docker iptables  — DOCKER-USER chain (iptables-nft)
#   26.04 / Docker 29 nft    — native nftables table, because DOCKER-USER may
#                              not exist on the iptables compatibility layer
install_docker_user_guard() {
    info "Installing DOCKER-USER guard (backstop for ports published on 0.0.0.0)..."

    command -v nft &>/dev/null || apt-get install -y -qq nftables || true
    command -v iptables &>/dev/null || apt-get install -y -qq iptables || true

    cat > /usr/local/bin/docker-user-guard << GUARD
#!/usr/bin/env bash
# Managed by 02-add-service.sh — do not edit manually.
#
# Docker's published ports bypass UFW's INPUT chain because container traffic is
# forwarded, not delivered locally. Apply the same policy on both firewall
# backends so this works on Ubuntu 24.04 (iptables-nft) and 26.04 (nftables).
set -uo pipefail

PORTS="${BOT_PORTS}"

# ── iptables / iptables-nft (DOCKER-USER) ────────────────────────────────────
# Rules are inserted with -I because Docker seeds DOCKER-USER with a single
# '-j RETURN'; anything appended after that RETURN would be unreachable.
# Every insert is guarded by -C so re-running this script is idempotent.
if command -v iptables >/dev/null 2>&1; then
    iptables -N DOCKER-USER 2>/dev/null || true
    ins() {
        iptables -C DOCKER-USER "\$@" 2>/dev/null || iptables -I DOCKER-USER "\$@"
    }
    ins -p udp -m multiport --dports "\${PORTS}" -j DROP
    ins -p tcp -m multiport --dports "\${PORTS}" -j DROP
    ins -s 10.0.0.0/8      -j RETURN
    ins -s 192.168.0.0/16  -j RETURN
    ins -s 172.16.0.0/12   -j RETURN
    ins -s 127.0.0.0/8     -j RETURN
    ins -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
fi

# ── nftables (Docker 29 native backend on Ubuntu 26.04) ──────────────────────
# Own table, hook forward at priority -15 so it runs before Docker's chains.
# Idempotent: delete + recreate the table on every run.
if command -v nft >/dev/null 2>&1; then
    nft delete table inet hardening-docker-user 2>/dev/null || true
    nft -f - << NFT
table inet hardening-docker-user {
    chain forward {
        type filter hook forward priority -15; policy accept;
        ct state established,related accept
        ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
        ip6 saddr { ::1, fc00::/7 } accept
        tcp dport { \${PORTS} } drop
        udp dport { \${PORTS} } drop
    }
}
NFT
fi
GUARD

    chmod +x /usr/local/bin/docker-user-guard

    # Bound to docker.service: Docker rebuilds its iptables chains whenever it
    # restarts, so the guard has to be re-applied at that point too.
    cat > /etc/systemd/system/docker-user-guard.service << 'EOF'
[Unit]
Description=Block WAN access to Docker-published trading bot ports
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/docker-user-guard
RemainAfterExit=yes

[Install]
WantedBy=docker.service multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable docker-user-guard.service &>/dev/null || true

    if systemctl is-active --quiet docker; then
        systemctl start docker-user-guard.service \
            && success "DOCKER-USER guard active (ports ${BOT_PORTS} blocked from WAN)." \
            || warn "Guard installed but failed to apply now — it will run on next Docker start."
    else
        success "DOCKER-USER guard installed; it will apply when Docker starts."
    fi
}

install_docker_engine() {
    if command -v docker &>/dev/null && docker compose version &>/dev/null; then
        success "Docker Engine and the Compose plugin are already installed."
        return
    fi

    echo ""
    echo "  Docker Engine and/or the Compose plugin are not installed."
    read -r -p "  Install them from Docker's official apt repository? [y/N]: " do_install
    if [[ "${do_install,,}" != "y" ]]; then
        warn "Skipping Docker install. Install it yourself before starting the stack."
        return
    fi

    info "Installing Docker Engine (this uses outbound HTTPS, already allowed by 01)..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc \
        || die "Could not fetch Docker's GPG key. Check outbound HTTPS (443)."
    chmod a+r /etc/apt/keyrings/docker.asc

    # arch is resolved at runtime so this works on both arm64 and amd64 hosts.
    # Suite: prefer this release's codename (noble on 24.04, resolute on 26.04).
    # Docker's index for a brand-new LTS sometimes 404s for weeks; noble packages
    # are binary-compatible and are the documented fallback.
    local arch suite
    arch=$(dpkg --print-architecture)
    suite="${UBUNTU_CODENAME}"
    # HEAD is not reliable here (some CDNs return 403/405 for Packages).
    # Probe the small InRelease file with GET and accept only HTTP 200.
    local docker_probe
    docker_probe=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 \
        "https://download.docker.com/linux/ubuntu/dists/${suite}/InRelease" || echo "000")
    if [[ "${docker_probe}" != "200" ]]; then
        warn "Docker has no '${suite}' apt index (HTTP ${docker_probe}) — falling back to 'noble' (24.04)."
        suite="noble"
    fi
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${suite} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin \
        || die "Docker install failed. Review the apt output above."

    systemctl enable docker
    systemctl start docker
    success "Docker Engine ${arch} installed and started."
}

# The mt5 container image is linux/amd64. On an ARM64 host it only runs if a
# qemu-x86_64 binfmt handler is registered for the kernel to hand it off to.
setup_qemu_emulation() {
    local host_arch
    host_arch=$(uname -m)

    if [[ "${host_arch}" != "aarch64" && "${host_arch}" != "arm64" ]]; then
        info "Host is ${host_arch} — no emulation needed for the linux/amd64 mt5 image."
        return
    fi

    info "Host is ${host_arch}. The mt5 image is linux/amd64 and needs QEMU emulation."
    apt-get install -y -qq qemu-user-static binfmt-support \
        || warn "Could not install qemu-user-static from apt."

    systemctl restart systemd-binfmt &>/dev/null || true

    # Confirm the handler actually works rather than assuming the package did it.
    if [[ -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]]; then
        success "binfmt handler qemu-x86_64 is registered."
    else
        warn "qemu-x86_64 binfmt handler not registered by apt."
        echo "  Register it through Docker instead:"
        echo "    sudo docker run --privileged --rm tonistiigi/binfmt --install amd64"
    fi

    if command -v docker &>/dev/null && systemctl is-active --quiet docker; then
        echo ""
        read -r -p "  Verify amd64 emulation now with a test container? [y/N]: " do_verify
        if [[ "${do_verify,,}" == "y" ]]; then
            local emulated
            emulated=$(docker run --rm --platform linux/amd64 alpine uname -m 2>/dev/null || true)
            if [[ "${emulated}" == "x86_64" ]]; then
                success "Emulation verified — linux/amd64 containers report x86_64."
            else
                warn "Emulation check did not return x86_64 (got: '${emulated:-no output}')."
                echo "  The mt5 container will not start until this works. Try:"
                echo "    sudo docker run --privileged --rm tonistiigi/binfmt --install amd64"
            fi
        fi
    fi

    warn "Emulated amd64 under QEMU is significantly slower than native."
    echo "  Keep the mt5 container to MT5 + the EA bridge; run the bot logic in the"
    echo "  native arm64 'bot' container so only the terminal pays the QEMU cost."
}

setup_docker_bot() {
    echo ""
    echo -e "${CYAN}  MetaTrader bot — Docker Compose, localhost only${NC}"
    echo ""
    echo "  This option prepares the host to run the Compose stack:"
    echo "    timescaledb (5432) │ redis (6379) │ mt5 (5900 VNC, 8765 bridge) │ bot (8000)"
    echo ""
    echo "  It deliberately opens NO inbound ports. Access stays SSH-only:"
    echo "    • dashboard 8000 and VNC 5900 → SSH port-forwarding"
    echo "    • 5432 / 6379 / 8765          → internal to the Compose network"
    echo ""
    echo "  What it changes:"
    echo "    1. Enables net.ipv4.ip_forward for Docker bridge networking"
    echo "    2. Installs Docker Engine + Compose plugin (only if missing)"
    echo "    3. Registers QEMU binfmt so the linux/amd64 mt5 image runs on ARM64"
    echo "    4. Installs a DOCKER-USER guard so a stray 0.0.0.0 publish is still blocked"
    echo "    5. Optionally adds an OUTBOUND rule for a non-443 broker port"
    echo ""
    echo "  SSH, fail2ban, unattended-upgrades and the rest of the DMZ posture are"
    echo "  left untouched."
    echo ""
    read -r -p "  Proceed? [y/N]: " confirm
    [[ "${confirm,,}" == "y" ]] || { info "Skipped."; return; }

    enable_docker_forwarding
    install_docker_engine
    setup_qemu_emulation
    install_docker_user_guard

    # Let the admin drive Compose without sudo on every command. This is not a
    # privilege increase — the account already has full sudo — but it is worth
    # stating plainly, since docker group access is equivalent to root.
    local admin_user="${SUDO_USER:-}"
    if [[ -n "${admin_user}" ]] && id "${admin_user}" &>/dev/null; then
        if id -nG "${admin_user}" 2>/dev/null | grep -qw docker; then
            success "'${admin_user}' is already in the docker group."
        else
            echo ""
            echo "  Adding '${admin_user}' to the docker group allows 'docker compose'"
            echo "  without sudo. Note that docker group access is root-equivalent."
            read -r -p "  Add '${admin_user}' to the docker group? [y/N]: " add_grp
            if [[ "${add_grp,,}" == "y" ]]; then
                usermod -aG docker "${admin_user}"
                success "'${admin_user}' added to the docker group."
                warn "Log out and back in for the new group to take effect."
            fi
        fi
    fi

    # ── Optional outbound-only broker port ──
    echo ""
    echo "  Most MT5 brokers connect over HTTPS 443, which 01 already allows."
    read -r -p "  Does your broker need a non-443 outbound TCP port? [y/N]: " need_broker
    if [[ "${need_broker,,}" == "y" ]]; then
        read -r -p "  Broker port number: " broker_port
        if [[ "${broker_port}" =~ ^[0-9]+$ && "${broker_port}" -ge 1 && "${broker_port}" -le 65535 ]]; then
            read -r -p "  Broker name (for the rule comment) [Broker]: " broker_name
            broker_name="${broker_name:-Broker}"
            # Outbound only — this never makes the host reachable on that port.
            ufw allow out "${broker_port}/tcp" comment "${broker_name} (MT5 outbound)"
            success "Outbound TCP ${broker_port} allowed for '${broker_name}'. No inbound rule added."
        else
            warn "Invalid port '${broker_port}' — skipped. Re-run and use the custom port option."
        fi
    fi

    # ── Closing guidance ──
    local host_ip admin_hint
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    admin_hint="${admin_user:-<admin-user>}"

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Host ready for the Compose stack${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo -e "${YELLOW}  Publish every port on the loopback interface only:${NC}"
    echo ""
    echo "      ports:"
    echo "        - \"127.0.0.1:8000:8000\"   # dashboard"
    echo "        - \"127.0.0.1:5900:5900\"   # VNC"
    echo ""
    echo -e "${RED}  Never use \"8000:8000\" or \"0.0.0.0:8000:8000\".${NC}"
    echo "  That form publishes on every interface, and because Docker's DNAT is"
    echo "  evaluated before UFW's INPUT chain, 'ufw default deny incoming' will"
    echo "  not hide it. The DOCKER-USER guard blocks ports ${BOT_PORTS}"
    echo "  as a backstop, but the loopback bind is what you should rely on."
    echo ""
    echo "  Better still, publish nothing for redis, timescaledb and the EA bridge."
    echo "  Containers reach each other by service name on the Compose network."
    echo ""
    echo "  Reach the dashboard and VNC from your workstation with one tunnel:"
    echo ""
    echo -e "${CYAN}      ssh -L 15900:127.0.0.1:5900 -L 8000:127.0.0.1:8000 ${admin_hint}@${host_ip:-<vm-ip>}${NC}"
    echo ""
    echo "  Then browse to http://localhost:8000 and point your VNC client at"
    echo "  localhost:15900 (local 15900, not 5900 — 5900 is often already taken"
    echo "  on the workstation). Both travel inside the SSH session."
    echo ""
    echo "  Start the stack from the bot repo (not managed by this repo):"
    echo "      cd ~/metatrader && docker compose up -d      # or ./run.sh"
    echo "      docker compose ps"
    echo "      docker compose logs -f bot"
    echo ""
    echo "  Set 'restart: unless-stopped' on every service so the stack returns"
    echo "  after the 02:00 UTC unattended-upgrades reboot."
    echo ""
    echo "  Confirm nothing leaked onto the WAN:"
    echo "      sudo bash 03-verify-hardening.sh"
    echo "      docker compose ps --format '{{.Service}} {{.Ports}}'"
}

setup_custom_port() {
    echo ""
    echo "  Direction:"
    echo "    1) Outbound — let this host reach a remote service"
    echo "       (use this for an MT5 broker on a non-443 port; adds no inbound exposure)"
    echo "    2) Inbound  — let remote hosts reach a service on this host"
    echo ""
    read -r -p "  Choice [1/2]: " CUSTOM_DIR
    case "${CUSTOM_DIR}" in
        1) CUSTOM_DIR="out" ;;
        2) CUSTOM_DIR="in"  ;;
        *) die "Invalid direction. Choose 1 (outbound) or 2 (inbound)." ;;
    esac

    read -r -p "  Port number: " CUSTOM_PORT
    [[ "${CUSTOM_PORT}" =~ ^[0-9]+$ && "${CUSTOM_PORT}" -ge 1 && "${CUSTOM_PORT}" -le 65535 ]] \
        || die "Invalid port number."

    read -r -p "  Protocol (tcp/udp) [tcp]: " CUSTOM_PROTO
    CUSTOM_PROTO="${CUSTOM_PROTO:-tcp}"
    [[ "${CUSTOM_PROTO}" == "tcp" || "${CUSTOM_PROTO}" == "udp" ]] \
        || die "Protocol must be 'tcp' or 'udp'."

    read -r -p "  Comment/label for this rule: " CUSTOM_COMMENT
    CUSTOM_COMMENT="${CUSTOM_COMMENT:-custom}"

    if [[ "${CUSTOM_DIR}" == "out" ]]; then
        ufw allow out "${CUSTOM_PORT}/${CUSTOM_PROTO}" comment "${CUSTOM_COMMENT}"
        success "Outbound ${CUSTOM_PORT}/${CUSTOM_PROTO} allowed. No inbound rule added."
        return
    fi

    # Inbound — refuse to expose a trading bot port on the WAN.
    if [[ ",${BOT_PORTS}," == *",${CUSTOM_PORT},"* ]]; then
        warn "Port ${CUSTOM_PORT} belongs to the Docker trading bot stack."
        echo "  The dashboard and VNC are meant to be reached over an SSH tunnel:"
        echo "    ssh -L 15900:127.0.0.1:5900 -L 8000:127.0.0.1:8000 <user>@<vm-ip>"
        echo "  Opening it inbound would expose it to the WAN."
        read -r -p "  Open it inbound anyway? [y/N]: " force_bot_port
        [[ "${force_bot_port,,}" == "y" ]] || { info "Skipped — use an SSH tunnel instead."; return; }
        warn "Proceeding against recommendation. 03-verify-hardening.sh will flag this."
    fi

    prompt_source_ip
    open_port "${CUSTOM_PROTO}" "${CUSTOM_PORT}" "${CUSTOM_COMMENT}"
    success "Inbound ${CUSTOM_PORT}/${CUSTOM_PROTO} opened."
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Ubuntu DMZ — Add Service${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo "  Ubuntu         : ${UBUNTU_VERSION} (${UBUNTU_CODENAME})"
echo "  Current UFW status:"
ufw status | sed 's/^/    /'
echo ""

while true; do
    echo ""
    echo -e "${CYAN}What service do you want to add?${NC}"
    echo ""
    echo -e "  ${GREEN}Docker Compose trading bot${NC}"
    echo "  1) MetaTrader bot (Docker)             — no inbound ports; SSH tunnels only"
    echo ""
    echo -e "  ${CYAN}Host-installed services${NC}"
    echo "  2) Web server (nginx)                  — opens 80, 443; hardens nginx; configures Certbot"
    echo "  3) Reverse proxy (nginx)               — same as above; adds proxy_pass template for your app"
    echo "  4) FastAPI / Python API (uvicorn)      — opens a custom port; rate-limits; adds fail2ban jail"
    echo "  5) PostgreSQL                          — locks to loopback (recommended) or opens 5432"
    echo "  6) MySQL / MariaDB                     — locks to loopback (recommended) or opens 3306"
    echo "  7) Redis                               — locks to loopback (recommended) or opens 6379"
    echo ""
    echo -e "  ${CYAN}Other${NC}"
    echo "  8) Custom port                         — inbound or outbound; optional source IP"
    echo "  9) Show current UFW rules"
    echo " 10) Exit"
    echo ""
    echo -e "  ${YELLOW}Running the Docker bot? Use option 1 only.${NC}"
    echo "  Options 4-7 install services on the host and are not needed: the bot"
    echo "  ships its own FastAPI, Postgres and Redis inside the Compose stack."
    echo ""
    read -r -p "Choice [1-10]: " CHOICE

    case "${CHOICE}" in
        1) setup_docker_bot                       ;;
        2) setup_nginx "webserver"   ; reload_ufw ;;
        3) setup_nginx "reverseproxy"; reload_ufw ;;
        4) setup_python_api          ; reload_ufw ;;
        5) setup_postgres                         ;;
        6) setup_mysql                            ;;
        7) setup_redis                            ;;
        8) setup_custom_port         ; reload_ufw ;;
        9) ufw status numbered ;;
       10) echo "Done."; exit 0 ;;
        *) warn "Invalid choice. Enter a number between 1 and 10." ;;
    esac

    echo ""
    read -r -p "Add another service? [y/N]: " another
    [[ "${another,,}" == "y" ]] || { echo "Done."; exit 0; }
done
