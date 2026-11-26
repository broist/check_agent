CREATE TABLE http_check_buckets (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    bucket_start TEXT NOT NULL,
    ok_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(agent_id, check_name, bucket_start)
) WITHOUT ROWID;

CREATE INDEX idx_http_check_buckets_time ON http_check_buckets(bucket_start);
