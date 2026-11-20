-- A registration token is a client-management authority, never a bearer access token.
-- Static provisioned clients have no row and cannot be claimed through RFC 7592.
CREATE TABLE IF NOT EXISTS nazo_client_registrations (
    tenant_id TEXT NOT NULL, client_id TEXT NOT NULL,
    token_hash TEXT NOT NULL CHECK(length(token_hash) = 64),
    PRIMARY KEY (tenant_id, client_id), UNIQUE (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, client_id) REFERENCES nazo_clients(tenant_id, id)
) WITHOUT ROWID, STRICT;
