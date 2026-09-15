DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_token_issuances) THEN
        RAISE EXCEPTION
            'cannot roll back token issuance storage while durable issuance records exist';
    END IF;
END
$$;

DROP FUNCTION nazo_oauth_cleanup_expired_security_state();

DROP INDEX ix_oauth_tokens_rotated_from_id;

DROP TABLE oauth_token_issuances;
