-- Each deployment binds one primary D1 database. Tenant IDs remain part of every key.
CREATE TABLE IF NOT EXISTS nazo_clients (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, client_id TEXT NOT NULL,
    realm_id TEXT NOT NULL, organization_id TEXT NOT NULL,
    registration TEXT NOT NULL CHECK(json_valid(registration)),
    secret_digest TEXT, epoch INTEGER NOT NULL CHECK(epoch BETWEEN 0 AND 9007199254740991),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, client_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_users (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, email TEXT NOT NULL,
    principal TEXT NOT NULL CHECK(json_valid(principal)),
    claims TEXT NOT NULL CHECK(json_valid(claims)), password_hash TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK(epoch BETWEEN 0 AND 9007199254740991), active INTEGER NOT NULL CHECK(active IN (0, 1)),
    mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mfa_enabled = 0),
    avatar_revision INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL CHECK(created_at BETWEEN -9007199254740991 AND 9007199254740991), updated_at INTEGER NOT NULL CHECK(updated_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, email)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_subjects (
    tenant_id TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, subject),
    FOREIGN KEY (tenant_id, user_id) REFERENCES nazo_users(tenant_id, id)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_grants (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
    scopes TEXT NOT NULL, resources TEXT NOT NULL, details TEXT NOT NULL,
    revision TEXT NOT NULL, PRIMARY KEY (tenant_id, user_id, client_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_decisions (
    tenant_id TEXT NOT NULL, request_hash TEXT NOT NULL, par_hash TEXT,
    event_id TEXT NOT NULL, retain_until INTEGER NOT NULL CHECK(retain_until BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, request_hash), UNIQUE (tenant_id, par_hash)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_decisions_expiry ON nazo_decisions(tenant_id,retain_until);
CREATE TABLE IF NOT EXISTS nazo_redemptions (
    tenant_id TEXT NOT NULL, client_id TEXT NOT NULL, grant_hash TEXT NOT NULL,
    issuance_id TEXT NOT NULL, holder TEXT, jti TEXT NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991),
    family_id TEXT, retain_until INTEGER NOT NULL CHECK(retain_until BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, client_id, grant_hash)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_redemptions_expiry ON nazo_redemptions(tenant_id,retain_until);
CREATE TABLE IF NOT EXISTS nazo_refresh_families (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, client_id TEXT NOT NULL, user_id TEXT,
    contract TEXT NOT NULL, contract_hash TEXT NOT NULL,
    member TEXT NOT NULL, member_id TEXT NOT NULL, token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at BETWEEN -9007199254740991 AND 9007199254740991), expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991), revoked_at INTEGER CHECK(revoked_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, token_hash)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_refresh_scope ON nazo_refresh_families(tenant_id, client_id, user_id, created_at, id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS nazo_refresh_expiry ON nazo_refresh_families(tenant_id,expires_at);
CREATE TABLE IF NOT EXISTS nazo_refresh_spent (
    tenant_id TEXT NOT NULL, token_hash TEXT NOT NULL, family_id TEXT NOT NULL,
    member_id TEXT NOT NULL, successor_id TEXT NOT NULL,
    spent_at INTEGER NOT NULL CHECK(spent_at BETWEEN -9007199254740991 AND 9007199254740991), expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, family_id) REFERENCES nazo_refresh_families(tenant_id, id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_spent_family ON nazo_refresh_spent(tenant_id, family_id, spent_at DESC, member_id DESC);
CREATE INDEX IF NOT EXISTS nazo_spent_expiry ON nazo_refresh_spent(tenant_id,expires_at);
CREATE TABLE IF NOT EXISTS nazo_revocations (
    tenant_id TEXT NOT NULL, jti_hash TEXT NOT NULL, client_id TEXT NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY (tenant_id, jti_hash)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_revocations_expiry ON nazo_revocations(tenant_id,expires_at);
CREATE TABLE IF NOT EXISTS nazo_signing_keys (
    tenant_id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),
    metadata TEXT NOT NULL, material TEXT NOT NULL, wrapping_key_id TEXT NOT NULL
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_modules (
    tenant_id TEXT NOT NULL, module_id TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    PRIMARY KEY (tenant_id, module_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE, event_type TEXT NOT NULL,
    category TEXT NOT NULL, occurred_at INTEGER NOT NULL CHECK(occurred_at BETWEEN -9007199254740991 AND 9007199254740991),
    payload TEXT NOT NULL CHECK(json_valid(payload))
) STRICT;
CREATE INDEX IF NOT EXISTS nazo_audit_tenant_time ON nazo_audit(tenant_id, occurred_at);
CREATE TRIGGER IF NOT EXISTS nazo_audit_no_update BEFORE UPDATE ON nazo_audit
BEGIN SELECT RAISE(ABORT, 'security audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS nazo_audit_no_delete BEFORE DELETE ON nazo_audit
BEGIN SELECT RAISE(ABORT, 'security audit is append-only'); END;
