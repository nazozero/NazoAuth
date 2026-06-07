CREATE TABLE IF NOT EXISTS user_totp_credentials (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    secret_base32 VARCHAR(128) NOT NULL,
    label VARCHAR(200) NOT NULL,
    confirmed_at TIMESTAMPTZ,
    last_used_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_user_totp_credentials_secret_non_empty CHECK (length(trim(secret_base32)) >= 16),
    CONSTRAINT ck_user_totp_credentials_label_non_empty CHECK (length(trim(label)) > 0),
    CONSTRAINT fk_user_totp_credentials_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_user_totp_credentials_tenant_user
    ON user_totp_credentials (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS ix_user_totp_credentials_user
    ON user_totp_credentials (user_id);

CREATE TABLE IF NOT EXISTS user_mfa_backup_codes (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_user_mfa_backup_codes_hash_non_empty CHECK (length(trim(code_hash)) > 0),
    CONSTRAINT fk_user_mfa_backup_codes_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_user_mfa_backup_codes_tenant_user_active
    ON user_mfa_backup_codes (tenant_id, user_id)
    WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS user_mfa_remembered_devices (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_agent_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_user_mfa_remembered_devices_token_hash CHECK (length(trim(token_hash)) = 64),
    CONSTRAINT fk_user_mfa_remembered_devices_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_user_mfa_remembered_devices_tenant_token
    ON user_mfa_remembered_devices (tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS ix_user_mfa_remembered_devices_tenant_user_active
    ON user_mfa_remembered_devices (tenant_id, user_id, expires_at);
