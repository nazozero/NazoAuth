-- WebAuthn credentials are tenant-scoped. The signed update uses an opaque CAS version.
CREATE TABLE IF NOT EXISTS nazo_passkeys (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    credential TEXT NOT NULL CHECK(json_valid(credential)),
    label TEXT NOT NULL,
    last_used_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    version TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, credential_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES nazo_users(tenant_id, id)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_passkeys_user ON nazo_passkeys(tenant_id, user_id, created_at, id);
