# Deploying DepRadar on a server

`deploy/depradarctl` installs and operates DepRadar on one Linux machine: a VPS, a cloud VM, or a
server in your office. One command takes a fresh server to a running HTTPS dashboard with an owner
account and daily verified backups. The same tool then handles status, upgrades with automatic
rollback, backups and restores, diagnostics, and removal.

## Requirements

| | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux on x86_64 or arm64 with Python 3.9+ | Ubuntu 22.04/24.04, Debian 12, Fedora, RHEL/Rocky/Alma 9 |
| Memory | 1 GiB (the tool adds swap for builds) | 2 GiB or more |
| Disk | 6 GiB free | 20 GiB |
| Network | Outbound HTTPS to Docker Hub, GitHub, and `api.osv.dev` | |
| HTTPS mode | A DNS record for your domain pointing to the server; ports 80 and 443 open | |

Docker Engine with the Compose plugin is installed automatically from Docker's official repository
on Debian, Ubuntu, Fedora, and RHEL-family systems. Elsewhere, install it first.

## Install

```sh
sudo git clone https://github.com/roxm337/depradar.git /opt/depradar
sudo /opt/depradar/deploy/depradarctl install
```

The installer checks the server, asks how DepRadar should be reached, shows the settings for
review, then builds and starts everything, waits until every service is healthy, verifies the
public address, and creates the owner account (you type its password; it never leaves the API
container). It finishes with the dashboard address and the next steps.

Every step can be repeated. If the installation is interrupted (network, power, Ctrl-C), run the
same command again: it resumes with the saved settings.

### Modes

| Mode | Use it when | Listens on |
| --- | --- | --- |
| `https` (default) | The server is on the internet with a domain. Certificates come from Let's Encrypt and renew automatically. | 80, 443 |
| `tls-internal` | A LAN or staging server. HTTPS with Caddy's private certificate authority; browsers warn until you trust its root. | 80, 443 |
| `proxy` | Another web server (Nginx, Traefik, a load balancer) already terminates TLS. Point it at the local port. | `127.0.0.1:<port>` |
| `http` | A trusted private network only. Passwords and tokens travel unencrypted. | `<bind>:<port>` |

### Unattended installation

Every question has a flag. Secrets are read from files, never from the command line:

```sh
printf '%s\n' 'a-long-owner-password' > /root/owner.pw && chmod 600 /root/owner.pw
sudo /opt/depradar/deploy/depradarctl install --yes \
  --mode https --domain depradar.example.com --email ops@example.com \
  --owner-password-file /root/owner.pw
shred -u /root/owner.pw
```

Other options: `--smtp-password-file`, `--telegram-token-file`, `--no-backups`,
`--keep-backups N`, `--no-firewall`, `--no-swap`; for `proxy` mode `--public-url` and `--port`;
for `http` mode `--host`, `--port`, and `--bind`. Run `depradarctl install --help` for the list.

## What gets installed

| Path | Contents |
| --- | --- |
| `/opt/depradar` | The source checkout the images are built from |
| `/etc/depradar/depradar.env` | Generated database password and bootstrap token, public URL, alert secrets (0600) |
| `/etc/depradar/Caddyfile`, `compose.ports.yaml` | Generated edge proxy and port settings for the chosen mode |
| `/etc/depradar/install.json` | Mode, address, installed version, backup policy |
| `/var/backups/depradar` | Verified backup archives (0600) |
| `/var/log/depradar/depradarctl.log` | Every command the tool ran and its output (no secrets) |
| `/usr/local/bin/depradarctl` | Link to the tool |
| `depradar-backup.timer` | systemd timer for the daily backup (03:15 ± 20 min) |

The containers are those of `compose.yaml` plus `deploy/compose.production.yaml`: PostgreSQL,
migrations, the API, the worker, the isolated scanner, the web interface, and Caddy. Only Caddy
publishes ports. It serves the dashboard, routes `/api/*` and `/health/*` to the API so pipelines
can use the same address, caps request bodies at 11 MB, and adds security headers (HSTS in `https`
mode). Every service restarts automatically after a crash or a reboot.

## Operate

| Command | What it does |
| --- | --- |
| `sudo depradarctl status` | Services, endpoint and latency, certificate expiry, backups (`--json` for monitoring) |
| `sudo depradarctl doctor` | Checks the host, configuration, services, and endpoint, and shows recent errors |
| `sudo depradarctl logs [service] [-f]` | Logs of `api`, `worker`, `scanner`, `web`, `proxy`, `db`, or `migrate` |
| `sudo depradarctl configure` | Change the mode, domain, alert secrets, or backup policy, then apply them |
| `sudo depradarctl start`, `stop`, `restart` | Lifecycle of all services |
| `sudo depradarctl owner setup` | Create the owner account if the installer could not |
| `sudo depradarctl owner reset-password` | New owner password; every session is signed out |

## Upgrade

```sh
sudo depradarctl upgrade            # the remote's default branch
sudo depradarctl upgrade --ref v1.2.0
```

The upgrade shows the incoming commits and warns when the database schema changes. It then:

1. creates a verified backup,
2. checks out the new version,
3. rebuilds the images,
4. restarts the services, applying migrations,
5. waits for every service to become healthy and checks the endpoint.

If anything fails, it checks out the previous version and starts it again. When the new version
had already migrated the database, it prints the exact `restore` command for the pre-upgrade
backup.

## Back up and restore

`sudo depradarctl backup` writes an archive and proves it by restoring it into a temporary schema
(see [BACKUPS.md](BACKUPS.md)). The daily timer keeps the newest 14 scheduled archives; backups
taken before an upgrade or restore are kept until you delete them. Copy archives off the server, and
keep a private copy of `/etc/depradar/depradar.env`: archives deliberately exclude secrets.

```sh
sudo depradarctl restore /var/backups/depradar/depradar-20261104T031500Z.tar.gz
```

Restore asks you to type `restore`, backs up the current data first, replaces the database and
inventories with the archive, and restarts. Sessions and pipeline tokens are not restored: sign in
again and create new CI tokens.

To move to a new server, install there, then restore the archive and copy the alert secrets with
`depradarctl configure`.

## Remove

```sh
sudo depradarctl uninstall            # containers only; data and settings stay
sudo depradarctl uninstall --purge    # also the database, certificates, and settings
```

`--purge` asks you to type `delete`. Backups in `/var/backups/depradar` are never deleted for you.

## Troubleshooting

- **Certificate not issued:** the domain must resolve to this server and ports 80 and 443 must be
  open in the cloud provider's firewall. `depradarctl logs proxy` shows Let's Encrypt's answer.
  Caddy keeps retrying, so nothing needs to be reinstalled once DNS is fixed.
- **Port 80 or 443 in use:** another web server is running. Stop it, or use `--mode proxy` and
  point that server at DepRadar's local port.
- **Build killed or very slow on a small VPS:** the build needs about 2 GiB of memory. Accept the
  installer's swap file offer, or add memory.
- **Anything else:** run `sudo depradarctl doctor`, then read
  `/var/log/depradar/depradarctl.log`.
