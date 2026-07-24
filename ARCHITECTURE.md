# Monitorozo architecture

## Scope

This milestone implements the first production-oriented vertical slice:

1. a Linux agent reads CPU, memory, filesystem and uptime metrics from `/proc`
   and `statfs(2)`;
2. the agent sends signed-in requests to the server over HTTP(S);
3. the server validates, rate-limits and persists reports in SQLite;
4. an authenticated dashboard shows the latest real report;
5. a configurable CPU threshold can create an alert and send SMTP mail;
6. both binaries can run as hardened systemd services.

Docker, systemd-service, HTTP/TCP/TLS probes, aggregation, SSE, alert
acknowledgement and token self-service are explicitly deferred until this slice
is proven. The schema and package boundaries leave room for them.

## Components

```text
/proc, statfs
     |
     v
monitorozo-agent -- bounded memory queue -- HTTPS POST /api/v1/reports
                                         |
                                  bearer token (hashed at rest)
                                         |
                                         v
                              monitorozo-server
                              | validation/rate limit
                              | replay protection
                              | alert evaluator -> SMTP
                              v
                         SQLite (WAL mode)
                              |
                     authenticated dashboard
```

### Agent

`cmd/agent` wires configuration, structured JSON logging, signal handling,
collection and delivery. `internal/collector` reads Linux kernel interfaces
without invoking shell commands. CPU utilization is computed from two
successive `/proc/stat` samples. Disk I/O and interface traffic rates are
calculated from successive `/proc/diskstats` and `/proc/net/dev` counters,
including safe handling of counter resets. Filesystems are discovered through
`/proc/self/mountinfo`, filtered to real filesystems, and measured with
`unix.Statfs`.

Reports are placed in a fixed-capacity in-memory FIFO. The sender retries with
capped exponential backoff and jitter. When the queue is full, the oldest
report is discarded and an error is logged without secrets. Sequence numbers
are persisted atomically so a restart does not make valid traffic look like a
replay.

### Server

`cmd/server` wires configuration, SQLite storage, authentication, alerting and
HTTP routing. The ingestion endpoint accepts a bounded JSON body, authenticates
an agent token against an Argon2id-derived hash, checks timestamp skew and a
strictly increasing sequence number in the same transaction as insertion, then
evaluates the report.

SQLite uses WAL, foreign keys, a busy timeout, prepared statements through
`database/sql`, one writer connection and indexed time-series tables.
Migrations are embedded in the binary and applied transactionally.

Raw reports are retained for seven days by default. A bounded maintenance job
upserts completed hours into an hourly CPU/RAM aggregate table and retains
those points for 90 days. Both periods and the maintenance interval are
configurable. History responses are capped and downsampled in-process.

The dashboard uses embedded Go templates, CSS and vanilla JavaScript. It does
not display synthetic data. Canvas charts query authenticated raw/hourly
history, and an authenticated Server-Sent Events stream signals new reports.
Authentication uses bcrypt, opaque server-side
sessions, Secure/HttpOnly/SameSite cookies, CSRF tokens, idle/absolute expiry
and per-IP login throttling. Security headers are applied globally.

### Alert flow

The rule engine evaluates CPU and memory duration thresholds, per-mount disk
warning/critical thresholds and agent-offline state. Rules move through
`pending`, `firing` and `resolved`; every transition is audited. Notifications
are stored before delivery, retried by one bounded background worker and
deduplicated with a configurable cooldown. Firing and recovery e-mails contain
the resource, measured value, threshold, start time and outage duration.
Operators can acknowledge active alerts through a CSRF-protected dashboard
action. SMTP can be disabled for local development.

## Configuration and secrets

Each binary reads YAML followed by `MONITOROZO_*` environment overrides.
Secrets may be provided only by environment in production. Example values are
deliberately invalid. Configuration files containing secrets must be owned by
root and mode `0600`; service users only receive values through systemd
credentials or a protected EnvironmentFile.

Agent tokens are never stored plaintext by the server. An operator generates
an Argon2id encoded token hash with `monitorozo-server hash-token`. Admin
passwords use `monitorozo-server hash-password`.

## Security boundaries

- Internet clients terminate TLS at Nginx.
- The server listens on loopback by default.
- Only `/healthz`, `/login` and the ingestion endpoint are unauthenticated.
- The agent service has no write access outside its state directory.
- The server service can write only its state directory.
- Access to `/var/run/docker.sock` is not granted in the MVP. Future Docker
  monitoring must document that this is effectively root-equivalent access.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for abuse cases and controls.

## Availability and recovery

The agent keeps a bounded queue during short network outages. The server
returns explicit status codes so permanent errors are not retried forever.
SQLite backup uses its online backup command while WAL is enabled. Service
deployment keeps the previous binary to permit rollback.

## Resource targets

- Agent steady-state RSS target: below 30 MiB.
- No polling subprocesses.
- Default collection period: 10 seconds (hard minimum: 5 seconds).
- Bounded report body: 256 KiB.
- Bounded queue, request deadlines and capped database connections.
