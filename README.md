# Ubuntu Server Hardening Scripts

Automated hardening scripts for a fresh Ubuntu server deployed in a DMZ (demilitarized zone) environment. Designed for a single-admin setup where only one trusted account has system access.

The intended workload is a **Docker Compose trading bot** on the same VM, reached over SSH port-forwarding only. Inbound stays SSH-only before and after the bot is deployed — no web server, no public API, no exposed database.

## What is included

| Script | Purpose |
|---|---|
| `01-initial-setup.sh` | Run once after installation. Creates the admin user, restricts sudo, hardens SSH, configures the firewall, sets up automatic security updates, applies kernel hardening, and configures a login banner. |
| `02-add-service.sh` | Run when adding a service. Option 1 prepares the host for the Docker Compose bot **without opening any ports**; the remaining options are for host-installed services. |
| `03-verify-hardening.sh` | Run at any time to audit whether all hardening from `01-initial-setup.sh` is still in effect, including Docker containment. Prints a pass/fail report and exits non-zero if any check fails. |

## Quick start

```bash
sudo bash 01-initial-setup.sh     # harden the host, then reboot
sudo bash 02-add-service.sh       # option 1: MetaTrader bot (Docker)
sudo bash 03-verify-hardening.sh  # confirm nothing is exposed
```

Then reach the bot from your workstation:

```bash
ssh -L 15900:127.0.0.1:5900 -L 8000:127.0.0.1:8000 <your-admin-username>@<vm-ip>
```

---

## Prerequisites

- Fresh **Ubuntu 24.04 LTS or 26.04 LTS** server (**ARM64** or amd64). 22.04 still mostly works but is not a primary target.
- A default installer account with sudo (typically `ubuntu`)
- SSH keys already present in `~ubuntu/.ssh/authorized_keys` (imported via GitHub during installation, or added manually)
- Run as root or via `sudo`

The trading bot's own repository is deployed separately. These scripts only prepare and audit the host — they never install the bot's code.

---

## Script 1 — Initial Setup

### What it does

1. **Prompts for the admin username** — you choose the account name at runtime (e.g. `JOHN`). The script validates the input (lowercase, starts with a letter, no spaces) and rejects the installer account name.
2. Updates and upgrades all installed packages
3. Creates the chosen admin user, prompts for a **sudo password** (used only for `sudo` — SSH stays key-only), and copies SSH keys from the installer account (`ubuntu`). If no keys are found, prompts for a GitHub username and imports them via `ssh-import-id`.
4. Grants sudo only to the new admin — removes all other accounts from the sudo group and locks the `ubuntu` account
5. Hardens the SSH daemon (`/etc/ssh/sshd_config.d/00-hardening.conf` — must sort *before* cloud-init's `50-cloud-init.conf`, because OpenSSH first-wins):
   - Key-only authentication, no passwords, no root login
   - `AllowUsers <your-username>` — no other account can SSH in
   - `AllowTcpForwarding local` — `ssh -L` to localhost only (VNC/dashboard). Not a jump host
   - `MaxAuthTries 3` / `MaxStartups 3:50:10` / `MaxSessions 2`
   - Works with Ubuntu 26.04 socket-activated SSH (`ssh.socket`) and with a long-lived `ssh.service` on 24.04. Does not disable socket activation.
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

This script opens **inbound SSH only**. It does not open any trading bot ports — see [Running the trading bot](#running-the-trading-bot-docker-compose) for the Docker setup that follows.

---

## Script 2 — Add a Service

Run this when you need to prepare the host for a new workload.

For the Docker Compose trading bot, use **option 1**, which opens no ports at all. The other options open ports through the firewall for services installed directly on the host.

### How to run

```bash
sudo bash 02-add-service.sh
```

### Available options

| # | Option | What it does |
|---|---|---|
| 1 | **MetaTrader bot (Docker)** | **Opens no ports.** Enables IP forwarding for Docker's bridge, installs Docker + Compose if missing, registers QEMU for the `linux/amd64` MT5 image on ARM64, installs a `DOCKER-USER` guard, and prints the SSH tunnel command |
| 2 | Web server (nginx) | Opens 80 + 443; installs nginx; applies security headers, TLS hardening, and rate limiting; adds fail2ban jails; sets up Certbot |
| 3 | Reverse proxy (nginx) | Same as above; writes a hardened `proxy_pass` template for your app |
| 4 | FastAPI / Python API (uvicorn) | Opens a custom port; applies UFW rate-limiting (`ufw limit`); adds a fail2ban jail with a journal-backed uvicorn filter |
| 5 | PostgreSQL | Locks to loopback (recommended) or opens 5432 with source IP restriction |
| 6 | MySQL / MariaDB | Locks to loopback (recommended) or opens 3306 with source IP restriction |
| 7 | Redis | Locks to loopback (recommended) with password and dangerous-command hardening, or opens 6379 with source IP restriction |
| 8 | Custom port | Opens any port/protocol **inbound or outbound**, with an optional source IP restriction. Use outbound for a non-443 broker port |

> **Running the Docker bot? Use option 1 only.** Options 4–7 install services directly on the host, which this bot does not need — it ships its own FastAPI, Postgres and Redis inside the Compose stack. Option 8 refuses to open a bot port inbound without an explicit override.

---

## Firewall rules after `01-initial-setup.sh`

```
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere        # SSH
Anywhere on docker0        ALLOW IN    Anywhere        # docker bridge (not WAN)
Anywhere on br+            ALLOW IN    Anywhere        # compose bridges (not WAN)

53                         ALLOW OUT   Anywhere        # DNS
80/tcp                     ALLOW OUT   Anywhere        # HTTP
443/tcp                    ALLOW OUT   Anywhere        # HTTPS
123/udp                    ALLOW OUT   Anywhere        # NTP
```

All other inbound and outbound traffic is **denied by default**. The `docker0` / `br+` rules are interface-scoped so containers can talk to the host; they do not publish 8000/5900/5432 on the WAN. Inbound from the internet stays SSH-only even after the trading bot is running.

> For the trading bot: every outbound connection it needs (broker login, Docker Hub image pulls, news feeds, optional LLM APIs) uses HTTPS 443, which is already allowed. Postgres, Redis and the EA bridge talk to each other inside the Compose network, so UFW never sees that traffic. If your MT5 broker uses a non-standard port, add it as an **outbound** rule only — `02-add-service.sh` option 8, direction "outbound". It is never an inbound rule.

---

## Verifying the hardening

The easiest way to verify all hardening is still in place is to run the dedicated audit script:

```bash
sudo bash 03-verify-hardening.sh
```

It runs every check listed below automatically, prints a coloured pass/fail report, and exits with code `1` if anything is wrong.

It is Docker-aware:

- `net.ipv4.ip_forward = 1` is a **pass** when `/etc/sysctl.d/99-docker-forward.conf` exists (a documented Docker exception), and a **fail** when it does not.
- Any bot port (5432, 6379, 5900, 8765, 8000) allowed inbound from `Anywhere` is a **fail**. A source-restricted rule is treated as a deliberate choice.
- The `DOCKER-USER` guard must be installed, enabled, and present in the live iptables chain.
- Any running container publishing on `0.0.0.0` or `[::]` is a **fail**.

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

## Running the trading bot (Docker Compose)

The bot is **not** a host systemd unit and there is no host Python virtualenv. It is a Docker Compose stack, and Compose already handles start-on-boot and restart-on-failure through `restart:` policies. Do not write a `metatrader.service` unit for it.

The stack lives in its own repository. This repo only prepares the host.

| Service | Port | Exposure |
|---|---|---|
| `timescaledb` | 5432 | Internal to the Compose network |
| `redis` | 6379 | Internal to the Compose network — do not publish |
| `mt5` | 5900 (VNC), 8765 (EA bridge) | `127.0.0.1` only; VNC via SSH tunnel |
| `bot` | 8000 (FastAPI dashboard) | `127.0.0.1` only; via SSH tunnel |

### Step 1 — Prepare the host

After `01-initial-setup.sh` and a reboot:

```bash
sudo bash 02-add-service.sh    # choose option 1: MetaTrader bot (Docker)
```

That option opens **no inbound ports**. It enables IP forwarding for Docker's bridge, installs Docker Engine and the Compose plugin if missing, registers QEMU so the `linux/amd64` MT5 image runs on ARM64, and installs a `DOCKER-USER` guard.

> Do **not** use options 4–7 (FastAPI, PostgreSQL, MySQL, Redis) for this bot. Those install services on the host and open ports. The stack ships its own FastAPI, Postgres and Redis in containers.

### Step 2 — Publish ports on loopback only

In your `compose.yml`, every published port must be bound to `127.0.0.1`:

```yaml
services:
  bot:
    ports:
      - "127.0.0.1:8000:8000"    # dashboard — tunnel only
    restart: unless-stopped

  mt5:
    ports:
      - "127.0.0.1:5900:5900"    # VNC — tunnel only
    restart: unless-stopped

  timescaledb:
    # No ports section at all. The bot reaches it as timescaledb:5432
    # over the Compose network.
    restart: unless-stopped

  redis:
    # No ports section either.
    restart: unless-stopped
```

**Never write `"8000:8000"` or `"0.0.0.0:8000:8000"`.** That publishes on every interface, and Docker's DNAT rules are evaluated *before* UFW's `INPUT` chain — so `ufw default deny incoming` will **not** hide it. The `DOCKER-USER` guard installed by option 1 blocks ports 5432, 6379, 5900, 8765 and 8000 from the WAN as a backstop, but the loopback bind is the control you should actually rely on.

Set `restart: unless-stopped` on every service so the stack comes back after the 02:00 UTC unattended-upgrades reboot.

### Step 3 — Start the stack

```bash
cd ~/metatrader
docker compose up -d          # or ./run.sh
docker compose ps
docker compose logs -f bot
```

### Step 4 — Reach the dashboard and VNC over SSH

Nothing is published to the WAN, so admin access goes through one SSH tunnel from your workstation:

```bash
ssh -L 15900:127.0.0.1:5900 -L 8000:127.0.0.1:8000 <your-admin-username>@<vm-ip>
```

While that session is open:

- Dashboard → <http://localhost:8000>
- VNC client → `localhost:15900` (the tunnel binds local 15900 because 5900 is often already taken on the workstation)

Both travel inside the SSH connection. Close the session and the access is gone.

### ARM64 and the MT5 container

The `mt5` image is `linux/amd64` (Wine + Xvfb + VNC), so on an ARM64 VM it runs under QEMU emulation. Option 1 installs `qemu-user-static` and registers the `binfmt` handler. Verify it with:

```bash
docker run --rm --platform linux/amd64 alpine uname -m    # must print x86_64
```

If that fails, register the handler through Docker instead:

```bash
sudo docker run --privileged --rm tonistiigi/binfmt --install amd64
```

Emulated amd64 is substantially slower than native, so keep the `mt5` container limited to the MT5 terminal and the EA bridge, and run the trading logic in the native arm64 `bot` container.

### If MT5 cannot reach the broker

Most brokers connect over HTTPS 443, which is already allowed. If yours needs a different TCP port, add it as **outbound only**:

```bash
sudo bash 02-add-service.sh    # option 8 (custom port) → direction: outbound
```

This never makes the VM reachable on that port. Do not add an inbound rule for a broker.

---

## Security notes

- The `ubuntu` account is **locked** (not deleted). Cloud-init may require it to exist. Do not delete it.
- Audit logs are written to `/var/log/audit/audit.log`. The ruleset is made immutable (`-e 2`) — changing audit rules requires a reboot. On Ubuntu 26.04, `audit-rules.service` loads the rules and `auditd.service` writes the log — both must be enabled.
- fail2ban ban history persists across restarts. To manually unban an IP: `sudo fail2ban-client set sshd unbanip <IP>`.
- Supported releases are **Ubuntu 24.04 LTS and 26.04 LTS**. The scripts detect the version at runtime and pick the matching SSH reload path, fail2ban backend, Docker apt suite, and firewall action (nftables on both; iptables-nft still works on 24.04).

### Ubuntu 24.04 vs 26.04

| Area | 24.04 | 26.04 | What the scripts do |
|---|---|---|---|
| SSH | `ssh.service` may stay running | Socket-activated (`ssh.socket` + `ssh@.service`). `systemctl status sshd` looks "dead" while SSH still works | Write `00-hardening.conf` (not `99-`) so it wins over cloud-init's `PasswordAuthentication yes`. Reload only if a daemon is running. Never disable `ssh.socket`. |
| OpenSSH | 9.6 | 10.2 (split `sshd` / `sshd-auth` / `sshd-session`) | No `ChallengeResponseAuthentication` (rejected or ignored on 10.x). Use `KbdInteractiveAuthentication no`. |
| fail2ban | journald, no `/var/log/auth.log` | Same, plus socket-activated SSH units and OpenSSH 10 `sshd-session` | `backend = systemd`, install `python3-systemd`, `journalmatch` covers `ssh.service`, `ssh.socket`, and `_COMM=sshd` / `sshd-auth` / `sshd-session`. Ban with nftables. |
| auditd | Single `auditd.service` | `audit-rules.service` + `auditd.service` | Enable both when the unit exists. |
| Docker apt | `noble` index | `resolute` index, sometimes 404 for a while | Probe the suite; fall back to `noble` packages if the current codename has no Packages file. |
| Docker firewall | iptables-nft, `DOCKER-USER` | Docker 29 can use native nftables (no `DOCKER-USER`) | Guard writes iptables `DOCKER-USER` **and** an `inet hardening-docker-user` table at priority `-200` (before Docker's filter-FORWARD). |
| nginx HTTP/2 | `listen 443 ssl http2;` | Parameter removed; `http2 on;` | Detect nginx version and write the matching listen block. |

### Automatic reboot at 02:00 UTC can interrupt a trading session

Unattended-upgrades reboots the VM at **02:00 UTC** when a kernel update requires it. That falls inside active trading hours for gold and other instruments, and an open position will be running unattended through the restart.

The reboot time is intentionally left as-is — security patches should not be deferred on a DMZ host. Mitigate it instead:

- Set `restart: unless-stopped` on every Compose service so the stack comes back automatically.
- Make sure the bot reconciles open positions with the broker on startup rather than assuming its in-memory state survived.
- Check `docker compose ps` after any overnight reboot.

If you must move the window, edit `Unattended-Upgrade::Automatic-Reboot-Time` in `/etc/apt/apt.conf.d/50unattended-upgrades` — but do not disable automatic reboots outright, or kernel patches will silently never take effect.

### Docker bypasses UFW — this is the one thing to keep in mind

UFW filters the `INPUT` chain. Docker publishes ports with DNAT rules that are traversed on the `FORWARD` path, which is consulted **before** `INPUT`. A container published on `0.0.0.0` is therefore reachable from the WAN even though `ufw status` reports `Default: deny (incoming)`.

Two defences are in place:

1. **Bind published ports to `127.0.0.1`** in `compose.yml`. This is the control that matters.
2. **The `DOCKER-USER` guard** (`/usr/local/bin/docker-user-guard`, installed by option 1) drops WAN traffic to 5432, 6379, 5900, 8765 and 8000 on the forward path. It is re-applied whenever Docker restarts, because Docker rebuilds its iptables chains at that point.

`03-verify-hardening.sh` checks both, and flags any running container publishing on `0.0.0.0` or `[::]`.

### The Docker IP-forwarding exception

Docker's bridge networking requires `net.ipv4.ip_forward = 1`, which conflicts with the DMZ baseline in `/etc/sysctl.d/99-dmz-hardening.conf`. Rather than editing that file, option 1 writes `/etc/sysctl.d/99-docker-forward.conf`. That filename sorts *after* `99-dmz-hardening.conf`, so it overrides that single key and leaves every other hardening value intact. IPv6 forwarding stays off.

`03-verify-hardening.sh` treats `ip_forward = 1` as a pass **only** when that drop-in exists, so an undocumented change is still reported as a failure.
