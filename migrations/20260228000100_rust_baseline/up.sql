CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    username VARCHAR(150) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name VARCHAR(80),
    avatar_url VARCHAR(512),
    role VARCHAR(16) NOT NULL DEFAULT 'user',
    admin_level INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT ck_users_role_value CHECK (role IN ('user', 'admin')),
    CONSTRAINT ck_users_admin_level_non_negative CHECK (admin_level >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));
CREATE INDEX IF NOT EXISTS ix_users_created_at_desc ON users (created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    client_id VARCHAR(128) NOT NULL,
    client_name VARCHAR(200) NOT NULL,
    client_type VARCHAR(32) NOT NULL,
    client_secret_hash VARCHAR(512),
    redirect_uris JSONB NOT NULL,
    scopes JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    token_endpoint_auth_method VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    allowed_audiences JSONB NOT NULL DEFAULT '["resource://default"]'::jsonb,
    CONSTRAINT ck_oauth_clients_redirect_uris_array CHECK (jsonb_typeof(redirect_uris) = 'array'),
    CONSTRAINT ck_oauth_clients_scopes_array CHECK (jsonb_typeof(scopes) = 'array'),
    CONSTRAINT ck_oauth_clients_grant_types_array CHECK (jsonb_typeof(grant_types) = 'array'),
    CONSTRAINT ck_oauth_clients_allowed_audiences_array CHECK (jsonb_typeof(allowed_audiences) = 'array'),
    CONSTRAINT ck_oauth_clients_client_type_value CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_clients_client_id ON oauth_clients (client_id);
CREATE INDEX IF NOT EXISTS ix_oauth_clients_created_at_desc ON oauth_clients (created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    refresh_token_blake3 VARCHAR(64) NOT NULL,
    token_family_id UUID NOT NULL,
    rotated_from_id UUID REFERENCES oauth_tokens(id),
    client_id UUID NOT NULL REFERENCES oauth_clients(id),
    user_id UUID REFERENCES users(id),
    scopes JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    reuse_detected_at TIMESTAMPTZ,
    subject VARCHAR(128) NOT NULL,
    dpop_jkt VARCHAR(128),
    CONSTRAINT ck_oauth_tokens_scopes_array CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_tokens_refresh_token_blake3 ON oauth_tokens (refresh_token_blake3);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_family ON oauth_tokens (token_family_id);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_family_active ON oauth_tokens (token_family_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_user_id ON oauth_tokens (user_id);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_user_client_active ON oauth_tokens (user_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_expires_at ON oauth_tokens (expires_at);

CREATE TABLE IF NOT EXISTS user_client_grants (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id),
    client_id UUID NOT NULL REFERENCES oauth_clients(id),
    first_authorized_at TIMESTAMPTZ NOT NULL,
    last_authorized_at TIMESTAMPTZ NOT NULL,
    last_scopes JSONB NOT NULL,
    authorization_count INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT ck_user_client_grants_last_scopes_array CHECK (jsonb_typeof(last_scopes) = 'array'),
    CONSTRAINT uq_user_client_grants_user_client UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS ix_user_client_grants_user_id ON user_client_grants (user_id);
CREATE INDEX IF NOT EXISTS ix_user_client_grants_last_authorized_at ON user_client_grants (last_authorized_at);
CREATE INDEX IF NOT EXISTS ix_user_client_grants_user_last_authorized ON user_client_grants (user_id, last_authorized_at DESC);

CREATE TABLE IF NOT EXISTS access_token_revocations (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    access_token_jti_blake3 VARCHAR(64) NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_access_token_revocations_jti_blake3 UNIQUE (access_token_jti_blake3)
);

CREATE INDEX IF NOT EXISTS ix_access_token_revocations_expires_at ON access_token_revocations (expires_at);

CREATE TABLE IF NOT EXISTS client_access_requests (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id),
    site_name VARCHAR(120) NOT NULL,
    site_url VARCHAR(512) NOT NULL,
    request_description VARCHAR(2000) NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    admin_note VARCHAR(1000),
    resolved_by_user_id UUID REFERENCES users(id),
    approved_client_id UUID REFERENCES oauth_clients(id),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_client_access_requests_status_code CHECK (status IN (0, 1, 2))
);

CREATE INDEX IF NOT EXISTS ix_client_access_requests_user_id ON client_access_requests (user_id);
CREATE INDEX IF NOT EXISTS ix_client_access_requests_status ON client_access_requests (status);
CREATE INDEX IF NOT EXISTS ix_client_access_requests_user_created_at ON client_access_requests (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_client_access_requests_status_created_at ON client_access_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_client_access_requests_created_at ON client_access_requests (created_at DESC);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_type'
          AND data_type = 'USER-DEFINED'
    ) THEN
        ALTER TABLE oauth_clients
            ALTER COLUMN client_type TYPE VARCHAR(32)
            USING client_type::text;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'users'
          AND column_name = 'role'
          AND data_type = 'USER-DEFINED'
    ) THEN
        ALTER TABLE users
            ALTER COLUMN role DROP DEFAULT,
            ALTER COLUMN role TYPE VARCHAR(16)
            USING role::text,
            ALTER COLUMN role SET DEFAULT 'user';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'client_access_requests'
          AND column_name = 'status'
          AND data_type <> 'smallint'
    ) THEN
        DROP INDEX IF EXISTS ux_client_access_requests_user_pending;
        ALTER TABLE client_access_requests
            ALTER COLUMN status DROP DEFAULT,
            ALTER COLUMN status TYPE SMALLINT
            USING CASE status::text
                WHEN 'pending' THEN 0
                WHEN 'approved' THEN 1
                WHEN 'rejected' THEN 2
            END,
            ALTER COLUMN status SET DEFAULT 0,
            ALTER COLUMN status SET NOT NULL;
    END IF;
END $$;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS display_name VARCHAR(80),
    ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(512),
    ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS admin_level INTEGER NOT NULL DEFAULT 0;

UPDATE users
SET email = CONCAT('generated-', id::text, '@invalid.local')
WHERE email IS NULL;

ALTER TABLE users
    ALTER COLUMN email SET NOT NULL;

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allowed_audiences JSONB;

UPDATE oauth_clients
SET allowed_audiences = '["resource://default"]'::jsonb
WHERE allowed_audiences IS NULL;

ALTER TABLE oauth_clients
    ALTER COLUMN allowed_audiences SET NOT NULL,
    ALTER COLUMN allowed_audiences SET DEFAULT '["resource://default"]'::jsonb;

ALTER TABLE oauth_tokens
    ADD COLUMN IF NOT EXISTS dpop_jkt VARCHAR(128);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_users_role_value'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT ck_users_role_value CHECK (role IN ('user', 'admin'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_users_admin_level_non_negative'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT ck_users_admin_level_non_negative CHECK (admin_level >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_oauth_clients_client_type_value'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT ck_oauth_clients_client_type_value CHECK (client_type IN ('public', 'confidential'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_oauth_clients_token_endpoint_auth_method_value'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_client_access_requests_status_code'
    ) THEN
        ALTER TABLE client_access_requests
            ADD CONSTRAINT ck_client_access_requests_status_code CHECK (status IN (0, 1, 2));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_client_access_requests_user_pending
    ON client_access_requests (user_id)
    WHERE status = 0;

COMMENT ON COLUMN client_access_requests.status IS '0=pending, 1=approved, 2=rejected';
COMMENT ON COLUMN oauth_clients.token_endpoint_auth_method IS
    'none=public client, client_secret_basic=HTTP Basic client authentication, client_secret_post=form body client authentication';
COMMENT ON COLUMN users.role IS 'user=normal account, admin=administrator';

DROP TYPE IF EXISTS client_access_request_status_enum;
DROP TYPE IF EXISTS client_type_enum;
DROP TYPE IF EXISTS user_role_enum;
