CREATE TABLE IF NOT EXISTS nazo_state (
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    version TEXT NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, kind, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS nazo_state_expiry ON nazo_state (tenant_id, expires_at);
