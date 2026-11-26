CREATE TABLE agent_labels (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
