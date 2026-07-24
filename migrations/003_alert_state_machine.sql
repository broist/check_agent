DROP INDEX IF EXISTS idx_alerts_one_firing;
DROP INDEX IF EXISTS idx_alerts_agent_state;

ALTER TABLE alerts RENAME TO alerts_legacy;

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    rule_key TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL CHECK(severity IN ('warning', 'critical')),
    state TEXT NOT NULL CHECK(state IN ('pending', 'firing', 'resolved')),
    value REAL NOT NULL,
    threshold REAL NOT NULL,
    started_at TEXT NOT NULL,
    firing_at TEXT,
    resolved_at TEXT,
    acknowledged_at TEXT,
    acknowledged_by TEXT,
    notification_state TEXT NOT NULL DEFAULT 'none'
        CHECK(notification_state IN ('none', 'pending', 'sent', 'suppressed')),
    last_notified_at TEXT
);

INSERT INTO alerts (
    id, agent_id, rule_key, resource, severity, state, value, threshold,
    started_at, firing_at, resolved_at, notification_state
)
SELECT
    id, agent_id, rule_key, '', severity, state, value, threshold,
    started_at,
    CASE WHEN state = 'firing' THEN started_at ELSE NULL END,
    resolved_at, notification_state
FROM alerts_legacy;

DROP TABLE alerts_legacy;

CREATE INDEX idx_alerts_agent_state ON alerts(agent_id, state);
CREATE INDEX idx_alerts_history ON alerts(started_at DESC);
CREATE UNIQUE INDEX idx_alerts_one_active
    ON alerts(agent_id, rule_key, resource)
    WHERE state IN ('pending', 'firing');

