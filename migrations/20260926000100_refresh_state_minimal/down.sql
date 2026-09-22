-- Rebuild the pre-20260926000100 wide-member model. Contract payloads are
-- restored onto each family's current member; spent proofs become terminal
-- tombstone members (sparsified_at set) because their authorization payload
-- no longer exists anywhere in the new model.
CREATE FUNCTION nazo_refresh_auth_context_is_current(context JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT context IS NOT NULL
       AND jsonb_path_match(
            context,
            '$.type() == "object"'
        )
       AND (context ->> 'version')::INT = 1
       AND jsonb_path_match(
            context -> 'issuer',
            '$.type() == "string" && !(@ like_regex "^\\s*$")'
        )
       AND jsonb_path_match(
            context -> 'audience',
            '$.type() == "string" && !(@ like_regex "^\\s*$")'
        )
       AND (context ->> 'auth_time')::BIGINT > 0
       AND jsonb_path_match(
            context -> 'amr',
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
        )
       AND CASE WHEN context ? 'oidc_sid'
            THEN jsonb_path_match(context -> 'oidc_sid', '$.type() == "string" && !(@ like_regex "^\\s*$")')
            ELSE TRUE END
       AND CASE WHEN context ? 'id_token_sid'
            THEN jsonb_path_match(context -> 'id_token_sid', '$.type() == "string" && !(@ like_regex "^\\s*$")')
            ELSE TRUE END
       AND CASE WHEN context ? 'acr'
            THEN jsonb_path_match(context -> 'acr', '$.type() == "string" && !(@ like_regex "^\\s*$")')
            ELSE TRUE END
       AND CASE WHEN context ? 'nonce'
            THEN jsonb_path_match(context -> 'nonce', '$.type() == "string"')
            ELSE TRUE END
       AND jsonb_path_match(
            context -> 'userinfo_claims',
            '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'
        )
       AND jsonb_path_match(
            context -> 'userinfo_claim_requests',
            '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string"))'
        )
       AND jsonb_path_match(
            context -> 'id_token_claims',
            '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'
        )
       AND jsonb_path_match(
            context -> 'id_token_claim_requests',
            '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string"))'
        );
$$;

CREATE TABLE oauth_tokens (
    id UUID PRIMARY KEY NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    refresh_token_blake3 VARCHAR(64) NOT NULL,
    token_family_id UUID NOT NULL,
    rotated_from_id UUID REFERENCES oauth_tokens(id),
    client_id UUID NOT NULL,
    user_id UUID,
    scopes JSONB NOT NULL,
    audience JSONB NOT NULL,
    authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    reuse_detected_at TIMESTAMPTZ,
    subject VARCHAR(128) NOT NULL,
    dpop_jkt VARCHAR(128),
    mtls_x5t_s256 VARCHAR(128),
    client_attestation_jkt VARCHAR(128),
    oidc_auth_context JSONB,
    sparsified_at TIMESTAMPTZ,
    CONSTRAINT fk_oauth_tokens_client_tenant
        FOREIGN KEY (client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id),
    CONSTRAINT fk_oauth_tokens_user_tenant
        FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT ck_oauth_tokens_scopes_array CHECK (jsonb_typeof(scopes) = 'array'),
    CONSTRAINT ck_oauth_tokens_authorization_details_array
        CHECK (jsonb_typeof(authorization_details) = 'array'),
    CONSTRAINT ck_oauth_tokens_refresh_contract_current CHECK (
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
    )
);

CREATE UNIQUE INDEX ux_oauth_tokens_tenant_refresh_token_blake3
    ON oauth_tokens (tenant_id, refresh_token_blake3);
CREATE INDEX ix_oauth_tokens_tenant_family
    ON oauth_tokens (tenant_id, token_family_id);
CREATE INDEX ix_oauth_tokens_tenant_family_active
    ON oauth_tokens (tenant_id, token_family_id)
    WHERE revoked_at IS NULL;
CREATE INDEX ix_oauth_tokens_tenant_expires
    ON oauth_tokens (tenant_id, expires_at);
CREATE INDEX ix_oauth_tokens_rotated_from_id
    ON oauth_tokens (rotated_from_id)
    WHERE rotated_from_id IS NOT NULL;
CREATE INDEX ix_oauth_tokens_terminal_sparse
    ON oauth_tokens (expires_at, id)
    WHERE revoked_at IS NOT NULL AND sparsified_at IS NULL;

-- Current members carry the family contract payload.
INSERT INTO oauth_tokens (
    id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
    client_id, user_id, scopes, audience, authorization_details,
    issued_at, expires_at, revoked_at, reuse_detected_at,
    subject, dpop_jkt, mtls_x5t_s256, client_attestation_jkt,
    oidc_auth_context, sparsified_at
)
SELECT
    f.current_member_id,
    f.tenant_id,
    encode(f.current_token_blake3, 'hex'),
    f.token_family_id,
    s.member_id,
    f.client_id,
    f.user_id,
    c.contract -> 'scopes',
    f.current_audience,
    COALESCE(c.contract -> 'authorization_details', '[]'::jsonb),
    f.current_issued_at,
    f.current_expires_at,
    f.revoked_at,
    f.reuse_detected_at,
    c.contract ->> 'subject',
    f.dpop_jkt,
    f.mtls_x5t_s256,
    f.client_attestation_jkt,
    (c.contract -> 'authentication_context')
        || jsonb_build_object('id_token_sid', f.current_id_token_sid),
    NULL
FROM oauth_refresh_families AS f
JOIN oauth_refresh_contracts AS c
    ON c.tenant_id = f.tenant_id AND c.contract_blake3 = f.contract_blake3
LEFT JOIN oauth_refresh_spent_tokens AS s
    ON s.tenant_id = f.tenant_id
   AND s.token_family_id = f.token_family_id
   AND s.successor_member_id = f.current_member_id;

-- Spent proofs become tombstoned members linked to their direct successor.
INSERT INTO oauth_tokens (
    id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
    client_id, user_id, scopes, audience, authorization_details,
    issued_at, expires_at, revoked_at, reuse_detected_at,
    subject, dpop_jkt, mtls_x5t_s256, client_attestation_jkt,
    oidc_auth_context, sparsified_at
)
SELECT
    s.member_id,
    s.tenant_id,
    encode(s.refresh_token_blake3, 'hex'),
    s.token_family_id,
    parent.member_id,
    f.client_id,
    f.user_id,
    '[]'::jsonb,
    '["tombstone"]'::jsonb,
    '[]'::jsonb,
    s.spent_at,
    s.expires_at,
    s.spent_at,
    f.reuse_detected_at,
    'tombstone',
    NULL, NULL, NULL,
    NULL,
    s.spent_at
FROM oauth_refresh_spent_tokens AS s
JOIN oauth_refresh_families AS f
    ON f.tenant_id = s.tenant_id AND f.token_family_id = s.token_family_id
LEFT JOIN oauth_refresh_spent_tokens AS parent
    ON parent.tenant_id = s.tenant_id
   AND parent.token_family_id = s.token_family_id
   AND parent.successor_member_id = s.member_id;

DROP TABLE oauth_refresh_spent_tokens;
DROP TABLE oauth_refresh_families;
DROP TABLE oauth_refresh_contracts;
