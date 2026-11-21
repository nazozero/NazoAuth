CREATE TABLE IF NOT EXISTS nazo_federation_links (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK(provider_type IN ('oidc','social','saml')),
    provider_id TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL,
    claims TEXT NOT NULL CHECK(json_valid(claims)),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,provider_type,provider_id,subject),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_federation_user ON nazo_federation_links(tenant_id,user_id);

CREATE TABLE IF NOT EXISTS nazo_access_requests (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
    site_name TEXT NOT NULL, site_url TEXT NOT NULL, request_description TEXT NOT NULL,
    status INTEGER NOT NULL CHECK(status IN (0,1,2)), admin_note TEXT,
    approved_client_id TEXT, resolved_by_user_id TEXT,
    required_approval_event_id TEXT, decision_event_id TEXT,
    created_at INTEGER NOT NULL, resolved_at INTEGER,
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id),
    FOREIGN KEY(tenant_id,approved_client_id) REFERENCES nazo_clients(tenant_id,id),
    FOREIGN KEY(tenant_id,resolved_by_user_id) REFERENCES nazo_users(tenant_id,id),
    CHECK(status<>0 OR (approved_client_id IS NULL AND resolved_at IS NULL AND required_approval_event_id IS NULL)),
    CHECK(required_approval_event_id IS NULL OR (status=1 AND approved_client_id IS NOT NULL AND resolved_at IS NOT NULL))
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_access_requests_user ON nazo_access_requests(tenant_id,user_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS nazo_access_requests_status ON nazo_access_requests(tenant_id,status,created_at DESC,id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS nazo_access_requests_decision ON nazo_access_requests(tenant_id,decision_event_id) WHERE decision_event_id IS NOT NULL;

-- Credential delivery is an immutable attempt, disclosed once only after its
-- approval's Required outcome. The payload (including any client secret) is
-- encrypted; tokens are hashed and versions fence every state transition.
CREATE TABLE IF NOT EXISTS nazo_client_deliveries (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
    attempt_id TEXT NOT NULL, version TEXT NOT NULL, ciphertext TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,user_id,token_hash),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_client_deliveries_expiry ON nazo_client_deliveries(tenant_id,expires_at);
