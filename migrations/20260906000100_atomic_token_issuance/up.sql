-- Stop the legacy saga writer before applying this migration.  The legacy
-- phase/response constraints must be removed before clearing historical
-- response envelopes: clearing a signed/delivered row while the old
-- phase_response check is still active would make the migration fail before
-- it reaches the new terminal-only constraints.
ALTER TABLE oauth_token_issuances
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_phase_response_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_signed_fields_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_phase_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_claim_owner_pair_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_response_pair_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_grant_key_check,
    DROP CONSTRAINT IF EXISTS oauth_token_issuances_request_digest_check;

-- Historical response envelopes are intentionally not treated as successful
-- issuance: clear the opaque body and its metadata while retaining the
-- operation key and any access-token revocation evidence.
UPDATE oauth_token_issuances
SET response_ciphertext = NULL,
    response_digest = NULL,
    response_envelope_version = NULL,
    response_key_id = NULL,
    updated_at = NOW();

ALTER TABLE oauth_token_issuances
    DROP COLUMN IF EXISTS phase,
    DROP COLUMN IF EXISTS claim_owner_id,
    DROP COLUMN IF EXISTS claim_started_at;

ALTER TABLE oauth_token_issuances
    ADD CONSTRAINT oauth_token_issuances_jti_expiry_pair_check
        CHECK ((access_token_jti IS NULL) = (access_token_expires_at IS NULL)),
    ADD CONSTRAINT oauth_token_issuances_response_pair_check
        CHECK ((response_ciphertext IS NULL) = (response_digest IS NULL)
            AND ((response_ciphertext IS NULL) = (response_envelope_version IS NULL))
            AND ((response_ciphertext IS NULL) = (response_key_id IS NULL))
            AND (response_ciphertext IS NULL OR access_token_jti IS NOT NULL)),
    ADD CONSTRAINT oauth_token_issuances_grant_key_check
        CHECK (length(grant_key_blake3) = 64),
    ADD CONSTRAINT oauth_token_issuances_request_digest_check
        CHECK (length(request_digest) = 64);

-- The startup preflight projects only this narrow metadata tuple.  Keep the
-- index partial so ordinary JTI/revocation rows do not pay for response-only
-- state that is not queried on the hot path.
CREATE INDEX IF NOT EXISTS oauth_token_issuances_response_key_metadata_idx
    ON oauth_token_issuances (response_key_id, response_envelope_version, expires_at)
    WHERE response_ciphertext IS NOT NULL;

COMMENT ON TABLE oauth_token_issuances IS
    'Terminal token issuance facts; only idempotent issuances retain an encrypted response body.';
