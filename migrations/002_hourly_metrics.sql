CREATE TABLE IF NOT EXISTS hourly_metrics (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    hour_start TEXT NOT NULL,
    cpu_avg REAL NOT NULL,
    cpu_min REAL NOT NULL,
    cpu_max REAL NOT NULL,
    memory_avg REAL NOT NULL,
    memory_min REAL NOT NULL,
    memory_max REAL NOT NULL,
    samples INTEGER NOT NULL,
    PRIMARY KEY(agent_id, hour_start)
);

CREATE INDEX IF NOT EXISTS idx_hourly_metrics_agent_time
    ON hourly_metrics(agent_id, hour_start DESC);

