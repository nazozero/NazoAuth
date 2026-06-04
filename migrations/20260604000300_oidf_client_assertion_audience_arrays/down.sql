UPDATE oauth_clients
SET allow_client_assertion_audience_array = FALSE,
    updated_at = CURRENT_TIMESTAMP
WHERE client_id IN (
    'nazo-oidf-id2-client-1',
    'nazo-oidf-id2-client-2',
    'nazo-oidf-message-id1-client-1',
    'nazo-oidf-message-id1-client-2'
);
