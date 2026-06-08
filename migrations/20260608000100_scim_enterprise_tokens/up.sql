CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_hash VARCHAR(64) NOT NULL,
    label VARCHAR(120) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '["scim:read", "scim:write"]'::jsonb,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_scim_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_scim_tokens_token_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_scim_tokens_label_non_empty CHECK (length(btrim(label)) > 0),
    CONSTRAINT ck_scim_tokens_scopes_array CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX IF NOT EXISTS ix_scim_tokens_tenant_active
    ON scim_tokens (tenant_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_scim_tokens_expires_at
    ON scim_tokens (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS scim_audit_events (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    scim_token_id UUID REFERENCES scim_tokens(id),
    event_type VARCHAR(64) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_hash VARCHAR(64),
    user_agent_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_scim_audit_events_event_type CHECK (event_type IN ('scim_token_used', 'scim_token_denied')),
    CONSTRAINT ck_scim_audit_events_scopes_array CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX IF NOT EXISTS ix_scim_audit_events_token_time
    ON scim_audit_events (scim_token_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_scim_audit_events_tenant_time
    ON scim_audit_events (tenant_id, created_at DESC);
