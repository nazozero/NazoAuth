CREATE TABLE device_authorization_decisions (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_code_hash varchar(64) NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_code_hash)
);
CREATE INDEX device_authorization_decisions_expiry ON device_authorization_decisions (expires_at);
