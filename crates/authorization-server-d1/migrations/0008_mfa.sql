-- The preceding schema only permitted 0, so replacing this one column preserves
-- every previously possible value without rebuilding users or its FK children.
-- This is a versioned, one-time migration, not an initialization statement.
ALTER TABLE nazo_users DROP COLUMN mfa_enabled;
ALTER TABLE nazo_users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0
    CHECK(mfa_enabled IN (0, 1));

CREATE TABLE IF NOT EXISTS nazo_mfa_totp (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, id TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL, secret_key_id TEXT NOT NULL,
    confirmed_at INTEGER, last_used_step INTEGER CHECK(last_used_step >= 0),
    version TEXT NOT NULL,
    PRIMARY KEY(tenant_id,user_id), UNIQUE(tenant_id,user_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS nazo_mfa_backup_codes (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, id TEXT NOT NULL,
    credential_id TEXT NOT NULL, code_hash TEXT NOT NULL CHECK(length(code_hash)>0),
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id,credential_id)
        REFERENCES nazo_mfa_totp(tenant_id,user_id,id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_mfa_backup_user ON nazo_mfa_backup_codes(tenant_id,user_id);

CREATE TABLE IF NOT EXISTS nazo_mfa_devices (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, credential_id TEXT NOT NULL,
    token_hash TEXT NOT NULL, user_agent_hash TEXT,
    expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY(tenant_id,token_hash),
    FOREIGN KEY(tenant_id,user_id,credential_id)
        REFERENCES nazo_mfa_totp(tenant_id,user_id,id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_mfa_devices_user ON nazo_mfa_devices(tenant_id,user_id);
CREATE INDEX IF NOT EXISTS nazo_mfa_devices_expiry ON nazo_mfa_devices(tenant_id,expires_at);
