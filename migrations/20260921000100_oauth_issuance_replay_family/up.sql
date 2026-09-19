-- Authorization-code replay evidence moves onto the durable issuance row.
-- The committed single-use grant fence already records which access token the
-- redemption produced; the refresh family is required so an exact replay can
-- revoke the whole grant it originally issued. Nullable: fresh (non
-- single-use) issuances and rows committed before this migration have no
-- family to record.
ALTER TABLE oauth_token_issuances
    ADD COLUMN refresh_token_family_id UUID;

COMMENT ON COLUMN oauth_token_issuances.refresh_token_family_id IS
    'Refresh-token family issued by this redemption. Read back through the single-use fence on replay so revoke-on-replay can retire the family; NULL when the issuance produced no refresh token and for pre-migration rows.';
