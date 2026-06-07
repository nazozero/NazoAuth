CREATE TABLE IF NOT EXISTS external_identity_links (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    provider_type VARCHAR(16) NOT NULL,
    provider_id VARCHAR(120) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    email VARCHAR(254) NOT NULL,
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ,
    CONSTRAINT ck_external_identity_links_provider_type CHECK (provider_type IN ('oidc', 'saml')),
    CONSTRAINT ck_external_identity_links_provider_id_non_empty CHECK (length(trim(provider_id)) > 0),
    CONSTRAINT ck_external_identity_links_subject_non_empty CHECK (length(trim(subject)) > 0),
    CONSTRAINT fk_external_identity_links_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_external_identity_links_tenant_provider_subject
    ON external_identity_links (tenant_id, provider_type, provider_id, subject);
CREATE INDEX IF NOT EXISTS ix_external_identity_links_tenant_user
    ON external_identity_links (tenant_id, user_id);
