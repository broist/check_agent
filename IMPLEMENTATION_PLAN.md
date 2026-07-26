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
- Optional systemd, Docker, HTTP/TLS and TCP checks.
- Service/container, three-consecutive HTTP failure and TLS-expiry rules.
- Responsive dashboard status lists for all optional integrations.
- Crash-safe bounded agent spool with ordered retry and restart recovery.
- Bounded-age backfill that preserves replay protection without firing stale alerts.
- Pinned GitHub Actions CI and tag release workflows with race tests, checksums
  and amd64/arm64 artifacts.
- Transactional update with readiness check and automatic rollback, plus
  verified backup/restore and explicit rollback scripts.
- Hardened native units, distroless non-root images and an opt-in host-agent
  Compose profile.

### Explicit non-goals for this production cut

- A multi-tenant fleet administration UI. The requested deployment target is a
  small two-instance Lightsail setup: one central monitor and one or more
  configured production agents.
- Amazon SES API delivery. The production path uses SES-compatible STARTTLS
  SMTP, which satisfies the alert-mail requirement through AWS's SMTP
  submission route.

## Delivery stages and gates

1. **Architecture gate** — architecture, threat model and MVP boundary reviewed.
2. **Agent gate** — collectors and payload validation unit-tested; static build.
3. **Server gate** — migration, ingestion, auth and alert transitions tested.
4. **End-to-end gate** — a real collected report reaches SQLite and dashboard.
5. **Deployment gate** — systemd sandboxing, Compose and operator procedures
   validated.
6. **Release gate** — `gofmt`, `go vet`, tests and amd64/arm64 builds pass.

## Remaining release evidence

Before declaring the cut complete, the current worktree must pass the full
local verification suite, GitHub Actions must run green after push, and the
operator runbook must match the pushed release revision.

No deferred critical security behavior is represented as a TODO in executable
code. The listed non-goals are outside the requested two-instance production
scope.
