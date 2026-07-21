ALTER TABLE oauth_tokens
    DROP CONSTRAINT IF EXISTS oauth_tokens_client_attestation_jkt_length,
    DROP COLUMN client_attestation_jkt;
