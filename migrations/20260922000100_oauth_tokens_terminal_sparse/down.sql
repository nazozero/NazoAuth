DROP INDEX ix_oauth_tokens_terminal_sparse;

-- Restore the un-exempted contract before dropping the marker column.
ALTER TABLE oauth_tokens
    DROP CONSTRAINT ck_oauth_tokens_refresh_contract_current;

ALTER TABLE oauth_tokens
    ADD CONSTRAINT ck_oauth_tokens_refresh_contract_current CHECK (
        jsonb_path_match(
            audience,
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
        )
        AND CASE
            WHEN COALESCE(nazo_refresh_auth_context_is_current(oidc_auth_context), FALSE)
            THEN (oidc_auth_context ->> 'auth_time')::BIGINT
                <= floor(EXTRACT(EPOCH FROM issued_at))::BIGINT
            ELSE FALSE
        END
    );

ALTER TABLE oauth_tokens
    DROP COLUMN sparsified_at;
