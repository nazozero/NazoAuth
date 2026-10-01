-- Logical reverse of this migration only. Not a production artifact
-- rollback authorization. The successful up proved false / NULL / empty state.
LOCK TABLE controller_registry_slots, oauth_clients, organizations, realms,
    user_mfa_remembered_devices, users IN ACCESS EXCLUSIVE MODE;

ALTER TABLE oauth_clients
    ADD COLUMN backchannel_user_code_parameter BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT ck_oauth_clients_ciba_user_code_disabled
        CHECK (backchannel_user_code_parameter = FALSE),
    ADD CONSTRAINT fk_oauth_clients_realm
        FOREIGN KEY (realm_id) REFERENCES realms(id),
    ADD CONSTRAINT fk_oauth_clients_organization
        FOREIGN KEY (organization_id) REFERENCES organizations(id);
ALTER TABLE users
    ADD CONSTRAINT fk_users_realm
        FOREIGN KEY (realm_id) REFERENCES realms(id),
    ADD CONSTRAINT fk_users_organization
        FOREIGN KEY (organization_id) REFERENCES organizations(id);

CREATE TABLE openid4vci_credential_configurations (
    id VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    configuration JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_configuration_id
        CHECK (char_length(btrim(id)) BETWEEN 1 AND 255),
    CONSTRAINT ck_openid4vci_configuration_object
        CHECK (jsonb_typeof(configuration) = 'object' AND configuration <> '{}'::jsonb),
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE controller_registry_slots ADD COLUMN last_used_at TIMESTAMPTZ;
ALTER TABLE user_mfa_remembered_devices ADD COLUMN last_used_at TIMESTAMPTZ;
