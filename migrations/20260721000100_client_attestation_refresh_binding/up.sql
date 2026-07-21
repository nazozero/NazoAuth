ALTER TABLE oauth_tokens
    ADD COLUMN client_attestation_jkt VARCHAR(128) NULL,
    ADD CONSTRAINT oauth_tokens_client_attestation_jkt_length
        CHECK (
            client_attestation_jkt IS NULL
            OR char_length(btrim(client_attestation_jkt)) BETWEEN 20 AND 128
        );

COMMENT ON COLUMN oauth_tokens.client_attestation_jkt IS
    'RFC 7638 thumbprint of the client instance key that an attestation-authenticated refresh token is bound to';
