DROP INDEX IF EXISTS ix_client_access_requests_tenant_id;
DROP INDEX IF EXISTS ix_access_token_revocations_tenant_id;
DROP INDEX IF EXISTS ix_user_client_grants_tenant_id;
DROP INDEX IF EXISTS ix_oauth_tokens_tenant_id;
DROP INDEX IF EXISTS ix_oauth_clients_tenant_id;
DROP INDEX IF EXISTS ix_users_tenant_id;
DROP INDEX IF EXISTS ux_client_access_requests_tenant_user_pending;
DROP INDEX IF EXISTS ux_access_token_revocations_tenant_jti_blake3;
DROP INDEX IF EXISTS ix_oauth_tokens_tenant_user_client_active;
DROP INDEX IF EXISTS ix_oauth_tokens_tenant_family_active;
DROP INDEX IF EXISTS ix_oauth_tokens_tenant_family;
DROP INDEX IF EXISTS ux_oauth_tokens_tenant_refresh_token_blake3;
DROP INDEX IF EXISTS ux_oauth_clients_tenant_client_id;
DROP INDEX IF EXISTS ux_users_tenant_email_lower;
DROP INDEX IF EXISTS ux_users_tenant_email;
DROP INDEX IF EXISTS ux_users_tenant_username;

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS uq_user_client_grants_tenant_user_client;

ALTER TABLE client_access_requests
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_client_tenant,
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_resolver_tenant,
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_user_tenant;

ALTER TABLE access_token_revocations
    DROP CONSTRAINT IF EXISTS fk_access_token_revocations_client_tenant;

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_client_tenant,
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_user_tenant;

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_user_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_client_tenant;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS uq_oauth_clients_id_tenant;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS uq_users_id_tenant;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_clients_client_id ON oauth_clients (client_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_oauth_tokens_refresh_token_blake3 ON oauth_tokens (refresh_token_blake3);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_family ON oauth_tokens (token_family_id);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_family_active ON oauth_tokens (token_family_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_user_client_active ON oauth_tokens (user_id, client_id) WHERE revoked_at IS NULL;
ALTER TABLE access_token_revocations
    ADD CONSTRAINT uq_access_token_revocations_jti_blake3 UNIQUE (access_token_jti_blake3);
ALTER TABLE user_client_grants
    ADD CONSTRAINT uq_user_client_grants_user_client UNIQUE (user_id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_client_access_requests_user_pending
    ON client_access_requests (user_id)
    WHERE status = 0;

ALTER TABLE client_access_requests
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_tenant,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE access_token_revocations
    DROP CONSTRAINT IF EXISTS fk_access_token_revocations_tenant,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_tenant,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_tenant,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_organization,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_organization_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_realm,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_realm_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_tenant,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS realm_id,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS fk_users_organization,
    DROP CONSTRAINT IF EXISTS fk_users_organization_tenant,
    DROP CONSTRAINT IF EXISTS fk_users_realm,
    DROP CONSTRAINT IF EXISTS fk_users_realm_tenant,
    DROP CONSTRAINT IF EXISTS fk_users_tenant,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS realm_id,
    DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS ix_organizations_tenant_id;
DROP INDEX IF EXISTS ix_realms_tenant_id;
DROP INDEX IF EXISTS ux_organizations_tenant_slug_lower;
DROP INDEX IF EXISTS ux_realms_tenant_slug_lower;
DROP INDEX IF EXISTS ux_tenants_slug_lower;
ALTER TABLE organizations
    DROP CONSTRAINT IF EXISTS uq_organizations_id_tenant;
ALTER TABLE realms
    DROP CONSTRAINT IF EXISTS uq_realms_id_tenant;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS realms;
DROP TABLE IF EXISTS tenants;
