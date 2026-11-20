ALTER TABLE nazo_clients ADD COLUMN require_mtls_bound_tokens INTEGER NOT NULL DEFAULT 0
    CHECK(require_mtls_bound_tokens IN (0,1));

CREATE TABLE IF NOT EXISTS nazo_mtls_trust_requests (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    certificate_pem TEXT NOT NULL CHECK(length(CAST(certificate_pem AS BLOB)) BETWEEN 1 AND 16384
        AND certificate_pem LIKE '-----BEGIN CERTIFICATE-----%'
        AND certificate_pem LIKE '%-----END CERTIFICATE-----%'),
    certificate_sha256 TEXT NOT NULL CHECK(length(certificate_sha256)=64
        AND certificate_sha256 NOT GLOB '*[^0-9a-f]*'),
    subject_dn TEXT NOT NULL CHECK(length(CAST(subject_dn AS BLOB)) BETWEEN 1 AND 2048),
    not_before INTEGER NOT NULL, not_after INTEGER NOT NULL CHECK(not_after>not_before),
    status INTEGER NOT NULL DEFAULT 0 CHECK(status IN (0,1,2,3)),
    admin_note TEXT CHECK(admin_note IS NULL OR length(CAST(admin_note AS BLOB)) BETWEEN 1 AND 1000),
    resolved_by_user_id TEXT CHECK(resolved_by_user_id IS NULL OR resolved_by_user_id<>user_id),
    resolved_at INTEGER, revoked_by_user_id TEXT, revoked_at INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, version TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'admin-session' CHECK(source='admin-session'),
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,client_id,certificate_sha256),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id),
    FOREIGN KEY(tenant_id,client_id) REFERENCES nazo_clients(tenant_id,id),
    FOREIGN KEY(tenant_id,resolved_by_user_id) REFERENCES nazo_users(tenant_id,id),
    FOREIGN KEY(tenant_id,revoked_by_user_id) REFERENCES nazo_users(tenant_id,id),
    CHECK((status=0 AND resolved_by_user_id IS NULL AND resolved_at IS NULL AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
       OR (status IN (1,2) AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
       OR (status=3 AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_mtls_trust_user ON nazo_mtls_trust_requests(tenant_id,user_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS nazo_mtls_trust_status ON nazo_mtls_trust_requests(tenant_id,status,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS nazo_mtls_trust_active ON nazo_mtls_trust_requests(tenant_id,certificate_sha256) WHERE status=1;

CREATE TABLE IF NOT EXISTS nazo_mtls_trust_events (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, request_id TEXT NOT NULL,
    actor_user_id TEXT NOT NULL, action INTEGER NOT NULL CHECK(action IN (0,1,2,3)),
    note TEXT CHECK(note IS NULL OR length(CAST(note AS BLOB)) BETWEEN 1 AND 1000),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,request_id) REFERENCES nazo_mtls_trust_requests(tenant_id,id),
    FOREIGN KEY(tenant_id,actor_user_id) REFERENCES nazo_users(tenant_id,id)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_mtls_trust_event_request ON nazo_mtls_trust_events(tenant_id,request_id,created_at,id);
CREATE TRIGGER IF NOT EXISTS nazo_mtls_trust_events_no_update BEFORE UPDATE ON nazo_mtls_trust_events
BEGIN SELECT RAISE(ABORT,'mTLS trust events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS nazo_mtls_trust_events_no_delete BEFORE DELETE ON nazo_mtls_trust_events
BEGIN SELECT RAISE(ABORT,'mTLS trust events are append-only'); END;
