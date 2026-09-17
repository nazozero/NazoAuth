-- access_token_revocations.expires_at is now stored as the revocation
-- retention deadline (verified token exp + MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS
-- = 60 seconds). Existing rows written by older writers may still hold the
-- bare token exp. Rows that can no longer fall inside the acceptance window
-- are already reclaimable, so only rows that can still matter are extended by
-- one full window. The migration ledger runs this exactly once; rows already
-- padded by a fixed writer receive at most one additional window.
UPDATE access_token_revocations
SET expires_at = expires_at + INTERVAL '60 seconds'
WHERE expires_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds';
