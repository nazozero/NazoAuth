-- CIBA uses the existing tenant-scoped CAS store. The pending notification
-- projection is an atomic, bounded queue over those same authoritative rows.
CREATE INDEX IF NOT EXISTS nazo_ciba_ping_due ON nazo_state (
    tenant_id, json_extract(value,'$.ping_notification.next_attempt_at'), key
) WHERE kind='ciba' AND json_extract(value,'$.ping_notification.status')='pending';

-- Preserve native SCIM uniqueness, soft deletion and stable cursor ordering.
CREATE UNIQUE INDEX IF NOT EXISTS nazo_users_username ON nazo_users (
    tenant_id, json_extract(claims,'$.preferred_username')
);
CREATE UNIQUE INDEX IF NOT EXISTS nazo_users_email_lower ON nazo_users(tenant_id,lower(email));
CREATE INDEX IF NOT EXISTS nazo_users_created ON nazo_users(tenant_id,created_at,id);
CREATE TABLE IF NOT EXISTS nazo_deleted_users (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, deleted_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id)
) STRICT, WITHOUT ROWID;

-- SCIM credentials remain separately provisioned operator authority. Only
-- their digest is persisted. Identity/event timestamps are in microseconds.
CREATE TABLE IF NOT EXISTS nazo_scim_tokens (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, token_hash TEXT NOT NULL,
    scopes TEXT NOT NULL CHECK(json_valid(scopes)), event_audience TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,token_hash)
) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nazo_scim_events (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, transaction_id TEXT NOT NULL,
    subject_uri TEXT NOT NULL, events TEXT NOT NULL CHECK(json_valid(events)),
    occurred_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,id)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_scim_events_order ON nazo_scim_events(tenant_id,occurred_at,id);
CREATE INDEX IF NOT EXISTS nazo_scim_events_expiry ON nazo_scim_events(tenant_id,expires_at);
CREATE TABLE IF NOT EXISTS nazo_scim_event_receipts (
    tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, token_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('acknowledged','error')),
    error_code TEXT, error_description TEXT, updated_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,event_id,token_id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES nazo_scim_events(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id,token_id) REFERENCES nazo_scim_tokens(tenant_id,id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
