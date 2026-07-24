# Threat model

## Assets

- agent API tokens and admin credentials;
- host telemetry and operational metadata;
- alert destinations and SMTP credentials;
- integrity and availability of the monitoring service;
- SQLite history and audit events.

## Principal risks and controls

| Risk | Impact | MVP controls | Residual risk / follow-up |
|---|---|---|---|
| Token theft in transit | forged telemetry | HTTPS required in production; Nginx TLS | endpoint host compromise |
| Database disclosure | token reuse | Argon2id encoded hashes only | offline guessing of weak tokens; require 32 random bytes |
| Replay/duplicate report | false history/alerts | timestamp skew and monotonic sequence in one transaction | sequence state recovery must preserve agent state |
| Oversized/malformed input | memory/CPU exhaustion | 256 KiB body cap, strict JSON, field/count/range validation | distributed volumetric DoS belongs at proxy/firewall |
| Brute-force admin login | dashboard compromise | bcrypt, per-IP limiter, generic errors | use external SSO in a later release |
| Session theft/fixation | admin compromise | random server-side sessions, rotation at login, Secure/HttpOnly/SameSite cookie, expiry | TLS endpoint and browser remain trusted |
| CSRF | state-changing requests | per-session CSRF token and Origin check | dashboard is still XSS-sensitive |
| XSS from host/mount data | session theft | `html/template`, JSON encoder, CSP, no inline untrusted HTML | future UI code must retain these properties |
| SQL injection | data loss/disclosure | parameterized SQL and fixed queries | migration review remains required |
| Alert-mail storm | cost/noise | transition-only delivery and stored state | cooldown/pending duration is next milestone |
| SMTP credential leakage | account compromise | environment-only secret; redacted logging | process environment readable to privileged users |
| Malicious proxy headers | auth/rate-limit bypass | proxy headers ignored unless trusted proxy is configured | configure exact loopback proxy CIDRs only |
| Agent privilege escalation | host compromise | dedicated unprivileged user, systemd sandbox, read-only collection | kernel pseudo-files expose host metadata |
| Docker socket access | root-equivalent host control | not used in MVP; explicit warning | use a constrained proxy if later enabled |
| SQLite corruption/loss | history loss | WAL, busy timeout, online backup procedure | single-node design has no HA |
| Dependency compromise | binary compromise | few pinned Go modules, CI verification | review and update dependencies regularly |

## Trust assumptions

- Nginx, the Linux kernel, systemd and the server host administrator are trusted.
- DNS and public PKI are trusted for agent-to-server TLS.
- SMTP submission is protected with TLS.
- A local root user can read process memory and all service secrets; the design
  does not claim protection from a compromised root account.

## Least privilege

The base metrics require no root privileges on standard Ubuntu. The agent needs
read access to `/proc`, mount metadata and the network, plus write access only
to `/var/lib/monitorozo-agent`. The server needs network bind permission on an
unprivileged loopback port and write access only to
`/var/lib/monitorozo-server`. Neither service can modify monitored workloads.

