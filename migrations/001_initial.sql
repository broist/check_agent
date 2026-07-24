CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS agent_tokens (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    PRIMARY KEY(agent_id, token_hash)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    measured_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    cpu_percent REAL NOT NULL,
    memory_percent REAL NOT NULL,
    swap_percent REAL NOT NULL,
    uptime_seconds INTEGER NOT NULL,
    payload_json BLOB NOT NULL,
    UNIQUE(agent_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_reports_agent_time
    ON reports(agent_id, measured_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    rule_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('firing', 'resolved')),
    value REAL NOT NULL,
    threshold REAL NOT NULL,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    notification_state TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_state ON alerts(agent_id, state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_one_firing
    ON alerts(agent_id, rule_key) WHERE state = 'firing';

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(occurred_at DESC);
