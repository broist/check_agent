# Implementation plan

## MVP boundary

### Included in the first vertical slice

- Linux CPU, memory, swap, mounted-filesystem and uptime collection.
- Configurable 5-second-or-longer collection interval.
- Authenticated HTTP(S) JSON ingestion with timestamp/sequence replay checks.
- Token rotation through multiple simultaneously valid hashed tokens.
- Bounded agent queue and exponential retry.
- SQLite WAL storage and embedded migrations.
- Latest-report authenticated responsive dashboard.
- Secure admin login, session and CSRF handling.
- Configurable CPU threshold, transition audit and SMTP/recovery mail.
- Health endpoint, systemd units, Docker images/Compose and operator docs.
- Unit tests and an end-to-end ingestion test.

### Delivered immediately after the MVP gate

- Authenticated SSE report notifications.
- CPU/RAM history API and dependency-free canvas charts.
- Seven-day raw retention and 90-day hourly aggregates.
- Per-device disk I/O and per-interface network throughput.
- Pending/firing/resolved CPU, RAM, disk and offline alert rules.
- Notification retry, cooldown, recovery mail, acknowledgement and history.

### Deferred to later milestones

- Service, Docker, HTTP, TCP and TLS collectors.
- Multi-host dashboard, alert pending durations/cooldowns and acknowledgement.
- Amazon SES API integration (SES SMTP works in the MVP).
- Installer/updater/uninstaller automation beyond safe starter scripts.

## Delivery stages and gates

1. **Architecture gate** — architecture, threat model and MVP boundary reviewed.
2. **Agent gate** — collectors and payload validation unit-tested; static build.
3. **Server gate** — migration, ingestion, auth and alert transitions tested.
4. **End-to-end gate** — a real collected report reaches SQLite and dashboard.
5. **Deployment gate** — systemd sandboxing, Compose and operator procedures
   validated.
6. **Release gate** — `gofmt`, `go vet`, tests and amd64/arm64 builds pass.

## Next milestones

1. systemd, Docker, HTTP/TLS and TCP collectors with least-privilege guidance.
2. Multi-agent administration, token rotation UI and audit browser.

No deferred critical security behavior is represented as a TODO in executable
code. Deferred features remain documented product scope.
