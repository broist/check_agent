# Monitorozo telepítési kézikönyv

Ez az útmutató a két szerveres production telepítést írja le:

- a monitoring szerveren fut a `monitorozo-server`, Nginx, TLS és SQLite;
- a production szerveren fut a `monitorozo-agent`, amely HTTPS-en küldi az adatokat.

Példákban használt domain: `monitor.acuwall.hu`.

## 1. DNS és tűzfal

Hozz létre egy `A` rekordot:

```text
monitor.acuwall.hu -> monitoring Lightsail static IP
```

Lightsail inbound szabályok a monitoring szerveren:

```text
TCP 80   0.0.0.0/0
TCP 443  0.0.0.0/0, később szűkíthető
TCP 22   csak saját admin IP
```

Ne nyisd ki publikusan a `8080` portot. A Monitorozo server csak
`127.0.0.1:8080` címen fusson, kívülről kizárólag Nginxen keresztül érhető el.

## 2. Monitoring szerver

```bash
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx sqlite3 ca-certificates git curl
sudo install -d -m 0755 /opt/monitorozo
cd /opt/monitorozo
sudo git clone https://github.com/broist/check_agent.git source
cd /opt/monitorozo/source
```

Töltsd le a release binárist:

```bash
sudo rm -rf /tmp/dist
sudo rm -f /tmp/SHA256SUMS
mkdir -p /tmp/dist

curl -fL -o /tmp/dist/monitorozo-server-linux-amd64 \
  https://github.com/broist/check_agent/releases/download/v1.0.2/monitorozo-server-linux-amd64

curl -fL -o /tmp/SHA256SUMS \
  https://github.com/broist/check_agent/releases/download/v1.0.2/SHA256SUMS

cd /tmp
grep 'dist/monitorozo-server-linux-amd64$' SHA256SUMS | sha256sum -c -
```

Ha `OK`, telepítsd:

```bash
cd /opt/monitorozo/source
sudo install -d -m 0755 bin
sudo install -m 0755 /tmp/dist/monitorozo-server-linux-amd64 bin/monitorozo-server
sudo ./scripts/install.sh server
```

## 3. Server konfiguráció

```bash
sudo install -o root -g monitorozo-server -m 0640 config/server.example.yaml /etc/monitorozo/server.yaml
```

Generálj agent tokent, hash-t, admin jelszó hash-t és session secretet:

```bash
AGENT_TOKEN="$(openssl rand -hex 32)"
echo "$AGENT_TOKEN"

/usr/local/bin/monitorozo-server hash-token "$AGENT_TOKEN"
/usr/local/bin/monitorozo-server hash-password 'IDE_IRD_AZ_ADMIN_JELSZOT'
/usr/local/bin/monitorozo-server generate-secret
```

A `/etc/monitorozo/server.yaml` fontos részei:

```yaml
listen: 127.0.0.1:8080
public_url: https://monitor.acuwall.hu/
secure_cookies: true
trusted_proxy: 127.0.0.0/8

agent_tokens:
  - agent_id: prod-01
    hash: "$argon2id$..."

admin_password_hash: "$2a$..."
session_secret: "legalabb-32-karakteres-secret"
```

Jogosultság:

```bash
sudo chown root:monitorozo-server /etc/monitorozo/server.yaml
sudo chmod 0640 /etc/monitorozo/server.yaml
sudo systemctl enable --now monitorozo-server
curl --fail http://127.0.0.1:8080/readyz
```

## 4. Nginx és HTTPS

Első tanúsítványhoz használható webroot ellenőrzés:

```bash
sudo mkdir -p /var/www/html/.well-known/acme-challenge
echo 'acme-ok' | sudo tee /var/www/html/.well-known/acme-challenge/test >/dev/null
curl http://monitor.acuwall.hu/.well-known/acme-challenge/test
```

Ha `acme-ok`, kérj tanúsítványt:

```bash
sudo certbot certonly --webroot \
  -w /var/www/html \
  -d monitor.acuwall.hu \
  --agree-tos \
  --no-eff-email \
  -m istvan.biro@acuwall.hu
```

Végleges Nginx config:

```bash
cd /opt/monitorozo/source
sudo cp deploy/nginx/monitorozo.conf /etc/nginx/sites-available/monitorozo
sudo sed -i 's/monitor\.example\.com/monitor.acuwall.hu/g' /etc/nginx/sites-available/monitorozo
sudo ln -sf /etc/nginx/sites-available/monitorozo /etc/nginx/sites-enabled/monitorozo
sudo nginx -t
sudo systemctl reload nginx
```

Ellenőrzés:

```bash
curl -I https://monitor.acuwall.hu/
curl --fail http://127.0.0.1:8080/readyz
```

## 5. Production agent szerver

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates git curl
sudo install -d -m 0755 /opt/monitorozo
cd /opt/monitorozo
sudo git clone https://github.com/broist/check_agent.git check_agent
cd /opt/monitorozo/check_agent
```

Agent bináris:

```bash
sudo rm -rf /tmp/dist
sudo rm -f /tmp/SHA256SUMS
mkdir -p /tmp/dist

curl -fL -o /tmp/dist/monitorozo-agent-linux-amd64 \
  https://github.com/broist/check_agent/releases/download/v1.0.2/monitorozo-agent-linux-amd64

curl -fL -o /tmp/SHA256SUMS \
  https://github.com/broist/check_agent/releases/download/v1.0.2/SHA256SUMS

cd /tmp
grep 'dist/monitorozo-agent-linux-amd64$' SHA256SUMS | sha256sum -c -
```

Telepítés:

```bash
cd /opt/monitorozo/check_agent
sudo install -d -m 0755 bin
sudo install -m 0755 /tmp/dist/monitorozo-agent-linux-amd64 bin/monitorozo-agent
sudo ./scripts/install.sh agent
sudo install -o root -g monitorozo-agent -m 0640 config/agent.example.yaml /etc/monitorozo/agent.yaml
```

Állítsd be:

```yaml
agent_id: prod-01
server_url: https://monitor.acuwall.hu
systemd_services: []
docker:
  enabled: false
http_checks: []
tcp_checks: []
```

Token env fájl:

```bash
sudo sh -c 'printf "%s\n" "MONITOROZO_AGENT_TOKEN=IDE_JON_A_PLAINTEXT_AGENT_TOKEN" > /etc/monitorozo/agent.env'
sudo chown root:monitorozo-agent /etc/monitorozo/agent.env
sudo chmod 0640 /etc/monitorozo/agent.env
```

Indítás:

```bash
sudo systemctl enable --now monitorozo-agent
sudo systemctl status monitorozo-agent --no-pager
sudo journalctl -u monitorozo-agent --since "5 minutes ago" --no-pager
```

## 6. Frissítés

Mindig töltsd le az új release binárist, ellenőrizd a `SHA256SUMS` értéket,
majd futtasd a megfelelő komponenst:

```bash
sudo ./scripts/update.sh server
sudo ./scripts/update.sh agent
```

Rollback:

```bash
sudo ./scripts/rollback.sh /var/lib/monitorozo-server/releases/IDOPONT --confirm
```

## 7. Backup

Monitoring szerveren:

```bash
cd /opt/monitorozo/source
sudo ./scripts/backup.sh
```

Production agent szerveren:

```bash
cd /opt/monitorozo/check_agent
sudo ./scripts/backup.sh
```
