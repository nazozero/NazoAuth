ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allow_client_assertion_endpoint_audience BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.allow_client_assertion_endpoint_audience IS
    'Allows private_key_jwt client assertion aud to match endpoint URLs at PAR; disabled by default for FAPI final negative tests';

UPDATE oauth_clients
SET allow_client_assertion_endpoint_audience = TRUE,
    updated_at = CURRENT_TIMESTAMP
WHERE client_id IN (
    'nazo-oidf-id2-client-1',
    'nazo-oidf-id2-client-2',
    'nazo-oidf-message-id1-client-1',
    'nazo-oidf-message-id1-client-2'
);
