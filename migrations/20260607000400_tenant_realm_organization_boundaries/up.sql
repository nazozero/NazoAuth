CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    slug VARCHAR(120) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_tenants_slug_non_empty CHECK (length(trim(slug)) > 0),
    CONSTRAINT ck_tenants_status_value CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS realms (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    slug VARCHAR(120) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_realms_slug_non_empty CHECK (length(trim(slug)) > 0),
    CONSTRAINT ck_realms_status_value CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    slug VARCHAR(120) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_organizations_slug_non_empty CHECK (length(trim(slug)) > 0),
    CONSTRAINT ck_organizations_status_value CHECK (status IN ('active', 'suspended', 'deleted'))
);

INSERT INTO tenants (id, slug, display_name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default tenant', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO realms (id, tenant_id, slug, display_name, status)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default realm',
    'active'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO organizations (id, tenant_id, slug, display_name, status)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default organization',
    'active'
)
ON CONFLICT (id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_slug_lower ON tenants (lower(slug));
CREATE UNIQUE INDEX IF NOT EXISTS ux_realms_tenant_slug_lower ON realms (tenant_id, lower(slug));
CREATE UNIQUE INDEX IF NOT EXISTS ux_organizations_tenant_slug_lower ON organizations (tenant_id, lower(slug));
CREATE INDEX IF NOT EXISTS ix_realms_tenant_id ON realms (tenant_id);
CREATE INDEX IF NOT EXISTS ix_organizations_tenant_id ON organizations (tenant_id);

ALTER TABLE realms
    DROP CONSTRAINT IF EXISTS uq_realms_id_tenant,
    ADD CONSTRAINT uq_realms_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE organizations
    DROP CONSTRAINT IF EXISTS uq_organizations_id_tenant,
    ADD CONSTRAINT uq_organizations_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id UUID,
    ADD COLUMN IF NOT EXISTS realm_id UUID,
    ADD COLUMN IF NOT EXISTS organization_id UUID;

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS tenant_id UUID,
    ADD COLUMN IF NOT EXISTS realm_id UUID,
    ADD COLUMN IF NOT EXISTS organization_id UUID;

ALTER TABLE oauth_tokens
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

ALTER TABLE user_client_grants
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

ALTER TABLE access_token_revocations
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

ALTER TABLE client_access_requests
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE users
SET tenant_id = '00000000-0000-0000-0000-000000000001',
    realm_id = '00000000-0000-0000-0000-000000000002',
    organization_id = '00000000-0000-0000-0000-000000000003'
WHERE tenant_id IS NULL OR realm_id IS NULL OR organization_id IS NULL;

UPDATE oauth_clients
SET tenant_id = '00000000-0000-0000-0000-000000000001',
    realm_id = '00000000-0000-0000-0000-000000000002',
    organization_id = '00000000-0000-0000-0000-000000000003'
WHERE tenant_id IS NULL OR realm_id IS NULL OR organization_id IS NULL;

UPDATE oauth_tokens
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE user_client_grants
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE access_token_revocations
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE client_access_requests
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE users
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001',
    ALTER COLUMN realm_id SET NOT NULL,
    ALTER COLUMN realm_id SET DEFAULT '00000000-0000-0000-0000-000000000002',
    ALTER COLUMN organization_id SET NOT NULL,
    ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000003';

ALTER TABLE oauth_clients
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001',
    ALTER COLUMN realm_id SET NOT NULL,
    ALTER COLUMN realm_id SET DEFAULT '00000000-0000-0000-0000-000000000002',
    ALTER COLUMN organization_id SET NOT NULL,
    ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000003';

ALTER TABLE oauth_tokens
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE user_client_grants
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE access_token_revocations
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE client_access_requests
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS fk_users_tenant,
    DROP CONSTRAINT IF EXISTS fk_users_realm,
    DROP CONSTRAINT IF EXISTS fk_users_realm_tenant,
    DROP CONSTRAINT IF EXISTS fk_users_organization,
    DROP CONSTRAINT IF EXISTS fk_users_organization_tenant,
    ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    ADD CONSTRAINT fk_users_realm FOREIGN KEY (realm_id) REFERENCES realms(id),
    ADD CONSTRAINT fk_users_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id),
    ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    ADD CONSTRAINT fk_users_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id);

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_realm,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_realm_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_organization,
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_organization_tenant,
    ADD CONSTRAINT fk_oauth_clients_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    ADD CONSTRAINT fk_oauth_clients_realm FOREIGN KEY (realm_id) REFERENCES realms(id),
    ADD CONSTRAINT fk_oauth_clients_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id),
    ADD CONSTRAINT fk_oauth_clients_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    ADD CONSTRAINT fk_oauth_clients_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id);

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_tenant,
    ADD CONSTRAINT fk_oauth_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_tenant,
    ADD CONSTRAINT fk_user_client_grants_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE access_token_revocations
    DROP CONSTRAINT IF EXISTS fk_access_token_revocations_tenant,
    ADD CONSTRAINT fk_access_token_revocations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE client_access_requests
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_tenant,
    ADD CONSTRAINT fk_client_access_requests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

DROP INDEX IF EXISTS ix_users_username;
DROP INDEX IF EXISTS ix_users_email;
DROP INDEX IF EXISTS ux_users_email_lower;
DROP INDEX IF EXISTS ix_oauth_clients_client_id;
DROP INDEX IF EXISTS ix_oauth_tokens_refresh_token_blake3;
DROP INDEX IF EXISTS ix_oauth_tokens_family;
DROP INDEX IF EXISTS ix_oauth_tokens_family_active;
DROP INDEX IF EXISTS ix_oauth_tokens_user_client_active;
DROP INDEX IF EXISTS ux_client_access_requests_user_pending;

ALTER TABLE access_token_revocations
    DROP CONSTRAINT IF EXISTS uq_access_token_revocations_jti_blake3;

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS uq_user_client_grants_user_client;

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_username ON users (tenant_id, username);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_email ON users (tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_tenant_email_lower ON users (tenant_id, lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_clients_tenant_client_id ON oauth_clients (tenant_id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_oauth_tokens_tenant_refresh_token_blake3 ON oauth_tokens (tenant_id, refresh_token_blake3);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_tenant_family ON oauth_tokens (tenant_id, token_family_id);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_tenant_family_active ON oauth_tokens (tenant_id, token_family_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_tenant_user_client_active ON oauth_tokens (tenant_id, user_id, client_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_access_token_revocations_tenant_jti_blake3
    ON access_token_revocations (tenant_id, access_token_jti_blake3);
ALTER TABLE user_client_grants
    ADD CONSTRAINT uq_user_client_grants_tenant_user_client UNIQUE (tenant_id, user_id, client_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_client_access_requests_tenant_user_pending
    ON client_access_requests (tenant_id, user_id)
    WHERE status = 0;

CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users (tenant_id);
CREATE INDEX IF NOT EXISTS ix_oauth_clients_tenant_id ON oauth_clients (tenant_id);
CREATE INDEX IF NOT EXISTS ix_oauth_tokens_tenant_id ON oauth_tokens (tenant_id);
CREATE INDEX IF NOT EXISTS ix_user_client_grants_tenant_id ON user_client_grants (tenant_id);
CREATE INDEX IF NOT EXISTS ix_access_token_revocations_tenant_id ON access_token_revocations (tenant_id);
CREATE INDEX IF NOT EXISTS ix_client_access_requests_tenant_id ON client_access_requests (tenant_id);

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS uq_users_id_tenant,
    ADD CONSTRAINT uq_users_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS uq_oauth_clients_id_tenant,
    ADD CONSTRAINT uq_oauth_clients_id_tenant UNIQUE (id, tenant_id);

ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_client_tenant,
    DROP CONSTRAINT IF EXISTS fk_oauth_tokens_user_tenant,
    ADD CONSTRAINT fk_oauth_tokens_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id),
    ADD CONSTRAINT fk_oauth_tokens_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id);

ALTER TABLE user_client_grants
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_user_tenant,
    DROP CONSTRAINT IF EXISTS fk_user_client_grants_client_tenant,
    ADD CONSTRAINT fk_user_client_grants_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    ADD CONSTRAINT fk_user_client_grants_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id);

ALTER TABLE access_token_revocations
    DROP CONSTRAINT IF EXISTS fk_access_token_revocations_client_tenant,
    ADD CONSTRAINT fk_access_token_revocations_client_tenant FOREIGN KEY (client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id);

ALTER TABLE client_access_requests
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_user_tenant,
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_resolver_tenant,
    DROP CONSTRAINT IF EXISTS fk_client_access_requests_client_tenant,
    ADD CONSTRAINT fk_client_access_requests_user_tenant FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    ADD CONSTRAINT fk_client_access_requests_resolver_tenant FOREIGN KEY (resolved_by_user_id, tenant_id) REFERENCES users(id, tenant_id),
    ADD CONSTRAINT fk_client_access_requests_client_tenant FOREIGN KEY (approved_client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id);

COMMENT ON TABLE tenants IS 'Top-level isolation boundary for users, clients, grants, tokens, and enterprise identity integrations.';
COMMENT ON TABLE realms IS 'Authentication realm within a tenant; future external IdP federation binds here.';
COMMENT ON TABLE organizations IS 'Organization boundary within a tenant; future SCIM provisioning binds here.';
COMMENT ON COLUMN users.tenant_id IS 'Tenant isolation key; default preserves existing single-tenant deployments.';
COMMENT ON COLUMN oauth_clients.tenant_id IS 'Tenant isolation key; client_id uniqueness is tenant-scoped.';
