# Operations runbook (MVP)

Production traffic must use Nginx TLS; development HTTP must never cross an
untrusted network. Replace `monitor.example.com` and AWS region values below.

## Ubuntu installation

On an Ubuntu 24.04 server, build on CI or a trusted build host, copy the two
matching release binaries and this repository, then run:

```bash
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx sqlite3 ca-certificates
sudo install -d -m 0755 /opt/monitorozo
sudo cp -a . /opt/monitorozo/source
cd /opt/monitorozo/source
sudo install -d -m 0755 bin
sudo install -m 0755 dist/monitorozo-agent-linux-amd64 bin/monitorozo-agent
sudo install -m 0755 dist/monitorozo-server-linux-amd64 bin/monitorozo-server
sudo ./scripts/install.sh
sudo install -o root -g monitorozo-server -m 0640 config/server.example.yaml /etc/monitorozo/server.yaml
sudo install -o root -g monitorozo-agent -m 0640 config/agent.example.yaml /etc/monitorozo/agent.yaml
```

For Graviton instances, use the `linux-arm64` binaries. Generate credentials:

```bash
openssl rand -hex 32
/usr/local/bin/monitorozo-server hash-token 'PASTE_AGENT_TOKEN'
/usr/local/bin/monitorozo-server hash-password 'PASTE_LONG_ADMIN_PASSWORD'
/usr/local/bin/monitorozo-server generate-secret
```

Place hashes in `server.yaml`. Put plaintext secrets in protected files:

```bash
sudo sh -c 'printf "%s\n" "MONITOROZO_AGENT_TOKEN=PASTE_AGENT_TOKEN" > /etc/monitorozo/agent.env'
sudo sh -c 'printf "%s\n" "MONITOROZO_SMTP_PASSWORD=PASTE_SMTP_PASSWORD" > /etc/monitorozo/server.env'
sudo chown root:monitorozo-agent /etc/monitorozo/agent.env
sudo chown root:monitorozo-server /etc/monitorozo/server.env
sudo chmod 0640 /etc/monitorozo/agent.env /etc/monitorozo/server.env
```

EnvironmentFile values do not support arbitrary shell escaping. Generate
URL-safe secrets and avoid spaces or quotes.

## AWS security group

Inbound rules for the monitoring server:

| Protocol/port | Source | Purpose |
|---|---|---|
| TCP 443 | agent egress IPs and administrator CIDRs; `0.0.0.0/0` only if necessary | dashboard and ingestion |
| TCP 80 | `0.0.0.0/0`, temporarily/permanently | ACME HTTP-01 and HTTPS redirect |
| TCP 22 | administrator VPN/bastion CIDR only | administration |

Do **not** expose TCP 8080. The agent needs only outbound TCP 443. The server
needs outbound TCP 587 for SES/SMTP and TCP 53/UDP 53 DNS as appropriate.

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
Size the volume with headroom and monitor it externally until disk alerts are
implemented. Changing retention takes effect at the next maintenance run.

## Start and inspect services

```bash
sudo systemctl enable --now monitorozo-server monitorozo-agent
sudo systemctl status monitorozo-server monitorozo-agent
curl --fail http://127.0.0.1:8080/healthz
sudo journalctl -u monitorozo-server -f
sudo journalctl -u monitorozo-agent -f
sudo journalctl -u monitorozo-server --since "1 hour ago" --no-pager
```

## Update and rollback

Build and test the release first. Put new binaries in `bin/`, then:

```bash
sudo ./scripts/update.sh
```

The script prints the backup directory. Roll back both binaries atomically from
that directory:

```bash
sudo systemctl stop monitorozo-agent monitorozo-server
sudo install -m 0755 /var/lib/monitorozo-server/releases/TIMESTAMP/monitorozo-agent /usr/local/bin/monitorozo-agent
sudo install -m 0755 /var/lib/monitorozo-server/releases/TIMESTAMP/monitorozo-server /usr/local/bin/monitorozo-server
sudo systemctl start monitorozo-server monitorozo-agent
sudo systemctl --no-pager status monitorozo-server monitorozo-agent
```

Database migrations are forward-only. Back up before updates and restore the
matching database when rolling back across a schema change.

## Backup and restore

SQLite WAL databases must not be copied while live with plain `cp`. Create a
consistent online backup and include protected configuration:

```bash
sudo install -d -o root -g root -m 0700 /var/backups/monitorozo
sudo sqlite3 /var/lib/monitorozo-server/monitorozo.db ".timeout 5000" ".backup '/var/backups/monitorozo/monitorozo.db'"
sudo tar -C / -czf /var/backups/monitorozo/config-$(date -u +%Y%m%dT%H%M%SZ).tar.gz etc/monitorozo
sudo sha256sum /var/backups/monitorozo/monitorozo.db
```

Encrypt and transfer backups to a separate access-controlled store. Restore:

```bash
sudo systemctl stop monitorozo-server
sudo install -o monitorozo-server -g monitorozo-server -m 0640 /var/backups/monitorozo/monitorozo.db /var/lib/monitorozo-server/monitorozo.db
sudo rm -f /var/lib/monitorozo-server/monitorozo.db-wal /var/lib/monitorozo-server/monitorozo.db-shm
sudo -u monitorozo-server sqlite3 /var/lib/monitorozo-server/monitorozo.db "PRAGMA integrity_check;"
sudo systemctl start monitorozo-server
```

Restore `/etc/monitorozo` from the matching encrypted archive only when
credentials/configuration also need recovery.

## Uninstall

Back up first. The safe uninstall retains data and configuration:

```bash
sudo ./scripts/uninstall.sh
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

Base collection does not require root. Do not add the agent to the `docker`
group merely for monitoring: access to `docker.sock` normally permits
root-equivalent host control.
