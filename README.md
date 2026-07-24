# Monitorozo

Monitorozo is a small, self-hosted Linux monitoring system written in Go. This
repository currently contains the first end-to-end MVP: a lightweight agent,
authenticated ingestion server, SQLite persistence, secure dashboard and a CPU
threshold SMTP alert. It also includes authenticated live updates, CPU/RAM
history charts, seven-day raw retention, 90-day hourly aggregates, disk I/O
rates and per-interface network throughput.

The exact scope and intentional deferrals are in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Do not expose development HTTP
to an untrusted network.

## Repository layout

```text
cmd/agent              agent executable
cmd/server             server executable and credential utilities
internal/agent         delivery queue, sequence state and retry
internal/collector     /proc and statfs Linux collectors
internal/server        HTTP API, dashboard and security middleware
internal/storage       SQLite migrations and queries
internal/alerts        reserved for the full rule engine milestone
internal/email         STARTTLS SMTP delivery
internal/auth          token hashing, sessions and rate limiting
internal/config        strict YAML plus environment overrides
web                    embedded HTML/CSS/vanilla JavaScript
deploy/systemd         hardened native units
deploy/docker          Dockerfiles and Compose
migrations             ordered embedded SQL migrations
docs                   threat model and operations runbook
scripts                install, update and uninstall helpers
```

## Build and test

Go 1.24 or newer is required.

```bash
go mod download
make lint
make test
make release VERSION=0.1.0
```

Release binaries are statically linked for Linux amd64 and arm64. Version,
commit and build time are injected with linker flags.

## Development quick start

Generate strong credentials without placing the plaintext token in Git:

```bash
openssl rand -hex 32
go run ./cmd/server hash-token 'PASTE_RANDOM_TOKEN'
go run ./cmd/server hash-password 'A-unique-long-admin-password'
go run ./cmd/server generate-secret
```

Copy the example configuration to local files, set
`insecure_dev_http: true`, `secure_cookies: false`, use a temporary database
path, and insert the generated hashes. Start the server and then the agent:

```bash
go run ./cmd/server -config server.local.yaml
go run ./cmd/agent -config agent.local.yaml
```

Open `http://127.0.0.1:8080/`. The dashboard remains empty until a real agent
report arrives.

## Configuration precedence

YAML is read first; supported `MONITOROZO_*` environment variables override
it. Secret overrides include:

- `MONITOROZO_AGENT_TOKEN`
- `MONITOROZO_ADMIN_PASSWORD_HASH`
- `MONITOROZO_SESSION_SECRET`
- `MONITOROZO_SMTP_PASSWORD`

Never commit populated environment files. Protect them with mode `0640` and a
service-specific group.

## Production deployment

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for exact Ubuntu, AWS, Nginx,
Let's Encrypt, SMTP/SES, systemd, logging, backup, restore, update, rollback and
uninstall procedures.

## Security

The server stores only Argon2id agent-token hashes. Admin passwords use bcrypt.
Ingestion has body limits, strict validation, IP rate limiting and transactional
timestamp/sequence replay protection. The dashboard uses opaque server-side
sessions, Secure/HttpOnly/SameSite cookies, CSRF checks and a restrictive CSP.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before exposing the service.
