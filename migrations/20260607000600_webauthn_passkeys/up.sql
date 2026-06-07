CREATE TABLE IF NOT EXISTS user_passkey_credentials (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    credential_id VARCHAR(2048) NOT NULL,
    credential JSONB NOT NULL,
    label VARCHAR(120) NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_user_passkey_credentials_label_non_empty CHECK (length(trim(label)) > 0),
    CONSTRAINT ck_user_passkey_credentials_credential_id_non_empty CHECK (length(trim(credential_id)) > 0),
    CONSTRAINT ck_user_passkey_credentials_sign_count_non_negative CHECK (sign_count >= 0),
    CONSTRAINT fk_user_passkey_credentials_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_user_passkey_credentials_tenant_credential
    ON user_passkey_credentials (tenant_id, credential_id);
CREATE INDEX IF NOT EXISTS ix_user_passkey_credentials_tenant_user
    ON user_passkey_credentials (tenant_id, user_id);
