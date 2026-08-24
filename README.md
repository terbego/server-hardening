# Ubuntu Server Hardening Scripts

Automated hardening scripts for a fresh Ubuntu server deployed in a DMZ (demilitarized zone) environment. Designed for a single-admin setup where only one trusted account (`JOHN`) has system access.

## What is included

| Script | Purpose |
|---|---|
| `01-initial-setup.sh` | Run once after installation. Creates the admin user, restricts sudo, hardens SSH, configures the firewall, sets up automatic security updates, applies kernel hardening, and configures a login banner. |
| `02-add-service.sh` | Run any time you add a new service. Interactively opens only the required ports and applies service-specific hardening. |
| `03-verify-hardening.sh` | Run at any time to audit whether all hardening from `01-initial-setup.sh` is still in effect. Prints a pass/fail report and exits non-zero if any check fails. |

---

## Prerequisites

- Fresh Ubuntu 22.04 LTS or 24.04 LTS server
- A default installer account with sudo (typically `ubuntu`)
- SSH keys already present in `~ubuntu/.ssh/authorized_keys` (imported via GitHub during installation, or added manually)
- Run as root or via `sudo`

---

## Script 1 — Initial Setup

### What it does

1. **Prompts for the admin username** — you choose the account name at runtime (e.g. `JOHN`). The script validates the input (lowercase, starts with a letter, no spaces) and rejects the installer account name.
2. Updates and upgrades all installed packages
3. Creates the chosen admin user, prompts for a **sudo password** (used only for `sudo` — SSH stays key-only), and copies SSH keys from the installer account (`ubuntu`). If no keys are found, prompts for a GitHub username and imports them via `ssh-import-id`.
4. Grants sudo only to the new admin — removes all other accounts from the sudo group and locks the `ubuntu` account
5. Hardens the SSH daemon (`/etc/ssh/sshd_config.d/99-hardening.conf`):
   - Key-only authentication, no passwords, no root login
   - `AllowUsers <your-username>` — no other account can SSH in
   - `MaxAuthTries 3` / `MaxStartups 3:50:10` / `MaxSessions 2`
6. Configures UFW (DMZ posture):
   - Default deny all inbound and outbound
   - Inbound: SSH (22) only
   - Outbound: DNS (53), HTTP (80), HTTPS (443), NTP (123)
7. Enables `unattended-upgrades` for security patches, auto-reboot at 02:00
8. Installs `fail2ban` — SSH bans: 3 retries → 24 h, doubling on repeat, max 7 days
9. Applies kernel hardening (`/etc/sysctl.d/99-dmz-hardening.conf`): disables IP forwarding, ICMP redirects, source routing; enables SYN cookies, reverse-path filtering, ASLR, and more
10. Installs `auditd` with rules for privilege escalation, SSH events, and sudoers changes
11. Configures a login banner (`/etc/issue`) that displays the server's local and WAN IP on every boot via a `systemd` one-shot service

### How to run

```bash
sudo bash 01-initial-setup.sh
```

The script will prompt:
```
Enter the admin username to create: yourname
```

Type the username you want (e.g. `JOHN`). The script validates it and proceeds.

> **Before rebooting**, open a second terminal and verify you can log in as your new user:
> ```bash
> ssh yourname@<server-ip>
> ```
> Only reboot once you have confirmed access.

---

## Script 2 — Add a Service

Run this any time you need to expose a new service through the firewall.

### How to run

```bash
sudo bash 02-add-service.sh
```

### Available options

| Option | What it does |
|---|---|
| Web server (nginx) | Opens 80 + 443; installs nginx; applies security headers, TLS hardening, and rate limiting; adds fail2ban jails; sets up Certbot |
| Reverse proxy (nginx) | Same as above; writes a hardened `proxy_pass` template for your app |
| FastAPI / Python API (uvicorn) | Opens a custom port; applies UFW rate-limiting (`ufw limit`); adds a fail2ban jail with a journal-backed uvicorn filter |
| PostgreSQL | Locks to loopback (recommended) or opens 5432 with source IP restriction |
| MySQL / MariaDB | Locks to loopback (recommended) or opens 3306 with source IP restriction |
| Redis | Locks to loopback (recommended) with password and dangerous-command hardening, or opens 6379 with source IP restriction |
| Custom port | Opens any port/protocol with an optional source IP restriction |

---

## Firewall rules after `01-initial-setup.sh`

```
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere        # SSH

53                         ALLOW OUT   Anywhere        # DNS
80/tcp                     ALLOW OUT   Anywhere        # HTTP
443/tcp                    ALLOW OUT   Anywhere        # HTTPS
123/udp                    ALLOW OUT   Anywhere        # NTP
```

All other inbound and outbound traffic is **denied by default**.

> For the trading bot (`metatrader`): all outbound connections (OpenAI, Anthropic, exchange REST/WebSocket APIs, Telegram, Discord, RSS feeds) use HTTPS port 443 and are already allowed. Local PostgreSQL and Redis use the loopback interface and are unaffected by UFW. If you later discover a broker that uses a non-standard port, open it with `02-add-service.sh` option 6.

---

## Verifying the hardening

The easiest way to verify all hardening is still in place is to run the dedicated audit script:

```bash
sudo bash 03-verify-hardening.sh
```

It runs every check listed below automatically, prints a coloured pass/fail report, and exits with code `1` if anything is wrong.

### Manual checks

If you prefer to run individual checks:

```bash
# Confirm only your admin user is in the sudo group
getent group sudo

# Confirm SSH is key-only and AllowUsers is set correctly
sudo sshd -T | grep -E "passwordauthentication|permitrootlogin|allowusers|maxauthtries|maxstartups"

# Check UFW status
sudo ufw status verbose

# Check fail2ban is running and the sshd jail is active
sudo fail2ban-client status sshd

# Check unattended-upgrades is enabled
systemctl is-enabled unattended-upgrades

# Check sysctl hardening is applied
sudo sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies kernel.randomize_va_space

# Check auditd is running
sudo systemctl status auditd

# View recent audit events (privilege escalation)
sudo ausearch -k privilege_escalation | tail -20
```

---

## Adding the trading bot as a systemd service

Once your bot code is deployed to the server, create a service unit so it runs on boot and restarts automatically:

```bash
sudo nano /etc/systemd/system/metatrader.service
```

```ini
[Unit]
Description=MetaTrader Trading Bot
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=<your-admin-username>
WorkingDirectory=/home/<your-admin-username>/metatrader
EnvironmentFile=/home/<your-admin-username>/metatrader/.env
ExecStart=/home/<your-admin-username>/.venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now metatrader
sudo journalctl -u metatrader -f
```

If the FastAPI/uvicorn server also needs to be publicly accessible, run `02-add-service.sh` and choose option 3.

---

## Security notes

- The `ubuntu` account is **locked** (not deleted). Cloud-init may require it to exist. Do not delete it.
- Automatic reboots for kernel updates happen at **02:00 UTC**. Plan your trading hours accordingly or change `Unattended-Upgrade::Automatic-Reboot-Time` in `/etc/apt/apt.conf.d/50unattended-upgrades`.
- Audit logs are written to `/var/log/audit/audit.log`. The ruleset is made immutable (`-e 2`) — changing audit rules requires a reboot.
- fail2ban ban history persists across restarts. To manually unban an IP: `sudo fail2ban-client set sshd unbanip <IP>`.
