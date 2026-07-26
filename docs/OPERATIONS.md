# Production operations runbook

Production traffic must use Nginx TLS; development HTTP must never cross an
untrusted network. Replace `monitor.example.com` and AWS region values below.

## Two-instance topology

Use separate Ubuntu 24.04 Lightsail instances:

- the **monitoring instance** runs `monitorozo-server`, Nginx, SQLite and SMTP;
- the **production instance** runs only `monitorozo-agent`.

The agent initiates outbound HTTPS reports to the monitoring instance. The
monitoring service never needs an inbound connection to the production host.

Build in CI or on a trusted build host and verify `SHA256SUMS` before copying
the matching release binary and repository files to each instance. For
Graviton instances, use the `linux-arm64` binary.

## Monitoring-instance installation

On the monitoring instance:

```bash
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx sqlite3 ca-certificates
sudo install -d -m 0755 /opt/monitorozo
sudo cp -a . /opt/monitorozo/source
cd /opt/monitorozo/source
sudo install -d -m 0755 bin
sudo install -m 0755 dist/monitorozo-server-linux-amd64 bin/monitorozo-server
sudo ./scripts/install.sh server
sudo install -o root -g monitorozo-server -m 0640 config/server.example.yaml /etc/monitorozo/server.yaml
```

Generate credentials on this instance:

```bash
openssl rand -hex 32
/usr/local/bin/monitorozo-server hash-token 'PASTE_AGENT_TOKEN'
/usr/local/bin/monitorozo-server hash-password 'PASTE_LONG_ADMIN_PASSWORD'
/usr/local/bin/monitorozo-server generate-secret
```

Place the token hash, password hash and session secret in `server.yaml`. Keep
only the SMTP password in the protected environment file:

```bash
sudo sh -c 'printf "%s\n" "MONITOROZO_SMTP_PASSWORD=PASTE_SMTP_PASSWORD" > /etc/monitorozo/server.env'
sudo chown root:monitorozo-server /etc/monitorozo/server.env
sudo chmod 0640 /etc/monitorozo/server.env
sudo systemctl enable --now monitorozo-server
curl --fail http://127.0.0.1:8080/readyz
```

Complete the Nginx/TLS and firewall sections below before configuring the
agent.

## Production-instance agent installation

Copy the same repository revision and only the agent release binary to the
production instance:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates
sudo install -d -m 0755 /opt/monitorozo
sudo cp -a . /opt/monitorozo/source
cd /opt/monitorozo/source
sudo install -d -m 0755 bin
sudo install -m 0755 dist/monitorozo-agent-linux-amd64 bin/monitorozo-agent
sudo ./scripts/install.sh agent
sudo install -o root -g monitorozo-agent -m 0640 config/agent.example.yaml /etc/monitorozo/agent.yaml
sudo sh -c 'printf "%s\n" "MONITOROZO_AGENT_TOKEN=PASTE_AGENT_TOKEN" > /etc/monitorozo/agent.env'
sudo chown root:monitorozo-agent /etc/monitorozo/agent.env
sudo chmod 0640 /etc/monitorozo/agent.env
sudo systemctl enable --now monitorozo-agent
sudo systemctl status monitorozo-agent
sudo journalctl -u monitorozo-agent --since "5 minutes ago" --no-pager
```

Set `server_url` in `agent.yaml` to the monitoring instance's public HTTPS
report endpoint and give the host a stable, unique `agent_id`. EnvironmentFile
values do not support arbitrary shell escaping. Generate URL-safe secrets and
avoid spaces or quotes.

`queue_size` is the maximum number of durable report files, not an unbounded
memory queue. At the 10-second default, `60` retains roughly ten minutes.
`spool_directory` defaults to `/var/lib/monitorozo-agent/spool`; it must remain
inside the agent's writable state directory. The server accepts ordered
backfill for up to `max_report_age: 24h`. Increase these together only after
checking disk capacity and the 256 KiB per-report cap.

## Docker Compose deployment

For a containerized central server, copy generated production configuration
next to the Compose file, keep it mode `0600`, and start only the server:

```bash
sudo install -o root -g root -m 0600 /etc/monitorozo/server.yaml deploy/docker/server.yaml
docker compose -f deploy/docker/docker-compose.yml config --quiet
docker compose -f deploy/docker/docker-compose.yml up -d --build server
docker compose -f deploy/docker/docker-compose.yml ps
```

Compose overrides the internal listen address but publishes it only on host
loopback for Nginx. The image is distroless, non-root, read-only, capability
free, resource limited and database-readiness checked.

The opt-in host agent profile is available when native systemd installation is
not possible:

```bash
sudo install -o root -g root -m 0600 /etc/monitorozo/agent.yaml deploy/docker/agent.yaml
docker compose -f deploy/docker/docker-compose.yml --profile agent up -d --build agent
```

This profile uses the host PID/UTS namespaces and read-only `/proc`, `/sys` and
root bind mounts so filesystem statistics describe the host. It never mounts
`docker.sock`, but exposes more host metadata than the native dedicated-user
service. The distroless agent image has no `systemctl`; leave
`systemd_services` empty in container mode. Native systemd is the preferred
production agent deployment.

## AWS / Lightsail firewall

Inbound rules for the monitoring server:

| Protocol/port | Source | Purpose |
|---|---|---|
| TCP 443 | agent egress IPs and administrator CIDRs; `0.0.0.0/0` only if necessary | dashboard and ingestion |
| TCP 80 | `0.0.0.0/0`, temporarily/permanently | ACME HTTP-01 and HTTPS redirect |
| TCP 22 | administrator VPN/bastion CIDR only | administration |

Do **not** expose TCP 8080. The agent needs only outbound TCP 443. The server
needs outbound TCP 587 for SES/SMTP and TCP 53/UDP 53 DNS as appropriate.
Use the same rules in the Lightsail networking firewall. On the production
agent instance, expose no Monitorozo port: allow only its outbound HTTPS to the
monitoring instance's public DNS name.

## Nginx and Let's Encrypt

Create the DNS A/AAAA record first. Install the supplied virtual host, obtain
the certificate, test, then reload:

```bash
sudo cp deploy/nginx/monitorozo.conf /etc/nginx/sites-available/monitorozo
sudo sed -i 's/monitor\.example\.com/your.monitor.name/g' /etc/nginx/sites-available/monitorozo
sudo ln -s /etc/nginx/sites-available/monitorozo /etc/nginx/sites-enabled/monitorozo
sudo nginx -t
sudo certbot --nginx -d your.monitor.name --redirect --agree-tos -m ops@example.com
sudo nginx -t
sudo systemctl reload nginx
sudo certbot renew --dry-run
```

Set `public_url`, `server_url` and `trusted_proxy: 127.0.0.0/8` consistently.

## SMTP and Amazon SES

For SES, verify the sender identity/domain, request production access, create
SMTP credentials in the same region, and set:

```yaml
smtp:
  enabled: true
  address: email-smtp.eu-central-1.amazonaws.com:587
  username: SES_SMTP_USERNAME
  password: ""
  from: alerts@verified.example.com
  to: operator@example.com
```

Put the SES SMTP password in `MONITOROZO_SMTP_PASSWORD`. Port 587 must advertise
STARTTLS; Monitorozo refuses plaintext SMTP. For another provider, use its
STARTTLS submission endpoint. Restart the server after configuration changes.

## Retention and capacity

The default `raw_retention: 168h` keeps ten-second reports for seven days.
Completed hours are aggregated and retained by `aggregate_retention: 2160h`
for 90 days. Maintenance runs hourly and applies both deletions transactionally.
Size the volume with headroom; Monitorozo's disk alerts protect the monitored
agent, so monitor the central server volume externally as well. Changing
retention takes effect at the next maintenance run.

## Alert defaults

CPU and memory must remain above 90% for five minutes before firing. Disk usage
fires warning above 85% and critical above 95%. An agent is offline after 120
seconds without a report. Failed/inactive configured systemd units, stopped or
unhealthy Docker containers, three consecutive HTTP failures, and TLS
certificates with at most 14 days remaining also fire alerts.
`alert_cooldown` defaults to 30 minutes. These values are configurable in
`server.yaml`; `http_failure_count`, `tls_warning_days` and
`tls_critical_days` tune the probe rules. Restart the server after changes.

## Optional agent checks

Configure only the checks needed on the production host. Every HTTP/TCP/Docker
operation has a deadline; HTTP URLs must not contain embedded credentials and
query strings are redacted from stored telemetry. The agent calls
`systemctl show` without a shell for each configured service.

```yaml
systemd_services:
  - nginx.service
docker:
  enabled: false
  socket: /var/run/docker.sock
  timeout: 3s
http_checks:
  - name: public-site
    url: https://example.com/health
    timeout: 3s
tcp_checks:
  - name: local-postgresql
    address: 127.0.0.1:5432
    timeout: 3s
```

The base agent remains healthy when Docker is disabled or its socket is
unavailable. A typical systemd unit status query needs no extra privilege.
Docker socket access is different: membership in the `docker` group normally
grants root-equivalent control. Prefer leaving Docker checks disabled or
placing a separately maintained, read-only authorization proxy in front of the
daemon; never expose the unauthenticated Docker API over TCP.

## Inspect services

On the monitoring instance:

```bash
sudo systemctl status monitorozo-server
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
sudo journalctl -u monitorozo-server -f
sudo journalctl -u monitorozo-server --since "1 hour ago" --no-pager
```

On the production instance:

```bash
sudo systemctl status monitorozo-agent
sudo journalctl -u monitorozo-agent -f
```

## Update and rollback

Build and test the release first, verify `SHA256SUMS`, and put the new binaries
in `bin/` on the corresponding instance. The updater makes a
database/config/binary backup, replaces only the selected component and
automatically restores the previous state on failure.

On the monitoring instance:

```bash
sudo ./scripts/update.sh server
```

On the production instance:

```bash
sudo ./scripts/update.sh agent
```

The script prints the timestamped release directory. Explicit rollback uses
that instance's directory and requires confirmation:

```bash
# Monitoring instance:
sudo ./scripts/rollback.sh \
  /var/lib/monitorozo-server/releases/TIMESTAMP --confirm

# Production instance:
sudo ./scripts/rollback.sh \
  /var/lib/monitorozo-agent/releases/TIMESTAMP --confirm
```

Database migrations are forward-only; rollback restores the matching online
backup when the release directory contains one.
If the server uses a non-default local listen port, set
`MONITOROZO_HEALTH_URL=http://127.0.0.1:PORT/readyz` for update, rollback and
restore commands.

## Backup and restore

Run backups separately on both instances. SQLite WAL databases must not be
copied while live with plain `cp`. On the monitoring instance the script uses
SQLite's online backup and integrity-checks it. On the production instance it
captures the agent sequence and spool. Both include protected configuration
and write SHA-256 checksums:

```bash
sudo ./scripts/backup.sh
# Or choose an explicit absolute destination:
sudo ./scripts/backup.sh /var/backups/monitorozo/20260724T120000Z
```

Encrypt and transfer each generated directory to a separate access-controlled
store. Test restores periodically on a replacement instance. A restore
verifies every checksum, detects the installed component, restores its
configuration/state/database and verifies service health:

```bash
sudo ./scripts/restore.sh \
  /var/backups/monitorozo/20260724T120000Z --confirm
```

## Uninstall

Back up first. The safe uninstall retains data and configuration:

```bash
# Monitoring instance:
sudo ./scripts/uninstall.sh server

# Production instance:
sudo ./scripts/uninstall.sh agent
```

After verifying the backup and only if permanent deletion is intended, remove
the retained `/etc/monitorozo`, `/var/lib/monitorozo-agent` and
`/var/lib/monitorozo-server` directories manually.

## Filesystem permissions

- `/etc/monitorozo/*.yaml`: `root:monitorozo-*`, mode `0640` when it contains no
  secret.
- `/etc/monitorozo/*.env`: `root:monitorozo-*`, mode `0640`.
- state directories: owned by the matching service user, mode `0750`.
- SQLite backups: root-owned, encrypted and access-controlled.

## Privilege note

Base, systemd, HTTP and TCP collection does not require root. Do not add the
agent to the `docker` group merely for convenience: access to `docker.sock`
normally permits root-equivalent host control.
