-- Terminal refresh-token members shrink to a reuse-detection stub.
--
-- A rotated member that is expired AND past the lost-response window
-- (revoked_at + 60s) can no longer participate in any live path: the token
-- endpoint rejects expired presentations before the context or scope checks,
-- the lost-response successor edge only matters within 60 seconds of the
-- parent's revocation, and a rotation parent must be unrevoked. What remains
-- is the hash -> family mapping that still feeds reuse detection, family
-- compromise and eventual whole-family reclaim.
--
-- `sparsified_at` marks the terminal projection: payload columns are rewritten
-- to tombstones and `rotated_from_id` is unlinked so dead chains stop
-- contributing traversal edges to reclaim ordering and successor scans.
ALTER TABLE oauth_tokens
    ADD COLUMN sparsified_at TIMESTAMPTZ;

COMMENT ON COLUMN oauth_tokens.sparsified_at IS
    'Terminal projection time. When set, payload columns hold tombstones and rotated_from_id is cleared; the row only carries hash-to-family reuse evidence until whole-family reclaim.';

-- Candidate scan for the bounded sparsify pass: members awaiting the terminal
-- projection, ordered by expiry. Shrinks as members are rewritten.
CREATE INDEX ix_oauth_tokens_terminal_sparse
    ON oauth_tokens (expires_at, id)
    WHERE revoked_at IS NOT NULL AND sparsified_at IS NULL;

-- The refresh-contract CHECK requires a non-empty audience and a current
-- authentication context; terminal stubs deliberately tombstone both, so the
-- constraint exempts rows once the projection marked them. Non-sparse rows
-- keep the full contract unchanged.
ALTER TABLE oauth_tokens
    DROP CONSTRAINT ck_oauth_tokens_refresh_contract_current;

ALTER TABLE oauth_tokens
    ADD CONSTRAINT ck_oauth_tokens_refresh_contract_current CHECK (
        sparsified_at IS NOT NULL
        OR (
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
        )
    );
