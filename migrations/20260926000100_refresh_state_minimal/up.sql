-- Refresh durable state is split into three lifecycles with explicit bounds.
--
-- The previous `oauth_tokens` model persisted the entire authorization
-- contract (scopes, audience, authorization_details, subject, sender
-- constraints, full OIDC authentication context) once per token generation,
-- kept rotated predecessors until their own 30-day expiry before
-- sparsification, and placed no bound on simultaneously active families per
-- grant scope. The 6h soak measured 15.63GB / 12.62M rows, ~98% of database
-- growth, with ~25,956 active families per fixture user.
--
-- Replacement model:
--
--   * oauth_refresh_contracts — the immutable authorization contract shared by
--     every generation of a family, content-addressed by a 32-byte digest so
--     identical contracts are stored once per tenant. The persisted context
--     strips `nonce` (no refresh-time reader; OIDC Core 12.2 suppresses it in
--     refreshed ID Tokens) and `id_token_sid` (per-generation family state).
--   * oauth_refresh_families — one narrow row per family carrying only
--     authority state: ownership, sender constraints, the current member
--     identity/digest, the current (possibly narrowed) audience, expiry and
--     the family-level revoked/compromised facts.
--   * oauth_refresh_spent_tokens — compact reuse/lost-response proofs for
--     rotated members, deleted at their own expiry; no authorization payload.
--
-- Active families are capped at 10 per (tenant_id, user_id, client_id) for
-- user-bound grants; the cap is enforced inside the issuance transaction and
-- the same deterministic oldest-first rule converges upgraded data here.
--
-- Digests are stored as BYTEA(32), never hex text.

-- Defense-in-depth shape check for persisted contracts. The runtime validates
-- the same contract before writing; this CHECK is the last line against a
-- malformed row ever becoming refresh authority. `nonce` and `id_token_sid`
-- must be absent or null: the persisted context strips both (the nonce has no
-- refresh-time reader and the ID-token session id is per-generation state).
CREATE FUNCTION nazo_refresh_contract_well_formed(contract JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    -- COALESCE guards the CHECK semantics: jsonb_path_match on a missing key
    -- yields NULL, and a CHECK constraint accepts NULL. NULL must fail.
    SELECT COALESCE(
       contract IS NOT NULL
       AND jsonb_path_match(contract, '$.type() == "object"')
       AND jsonb_path_match(contract -> 'subject', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'scopes', '$.type() == "array" && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'audiences', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'authorization_details', '$.type() == "array"')
       AND jsonb_path_match(contract -> 'authentication_context', '$.type() == "object"')
       AND (contract #>> '{authentication_context,version}')::INT = 1
       AND jsonb_path_match(contract -> 'authentication_context' -> 'issuer', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'audience', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND (contract #>> '{authentication_context,auth_time}')::BIGINT > 0
       AND jsonb_path_match(contract -> 'authentication_context' -> 'amr', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND COALESCE(contract #>> '{authentication_context,nonce}', '') = ''
       AND COALESCE(contract #>> '{authentication_context,id_token_sid}', '') = ''
       AND jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'),
       FALSE
    );
$$;

CREATE TABLE oauth_refresh_contracts (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    contract_blake3 BYTEA NOT NULL,
    contract JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_oauth_refresh_contracts
        PRIMARY KEY (tenant_id, contract_blake3),
    CONSTRAINT ck_oauth_refresh_contracts_digest
        CHECK (octet_length(contract_blake3) = 32),
    CONSTRAINT ck_oauth_refresh_contracts_shape
        CHECK (nazo_refresh_contract_well_formed(contract))
);

COMMENT ON TABLE oauth_refresh_contracts IS
    'Immutable per-family authorization contract, content-addressed by BLAKE3. Rows are reference-counted by families and reclaimed once unreferenced.';

CREATE TABLE oauth_refresh_families (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_family_id UUID NOT NULL,
    client_id UUID NOT NULL,
    user_id UUID,
    contract_blake3 BYTEA NOT NULL,
    current_member_id UUID NOT NULL,
    current_token_blake3 BYTEA NOT NULL,
    current_audience JSONB NOT NULL,
    current_issued_at TIMESTAMPTZ NOT NULL,
    current_expires_at TIMESTAMPTZ NOT NULL,
    current_id_token_sid VARCHAR(128),
    dpop_jkt VARCHAR(128),
    mtls_x5t_s256 VARCHAR(128),
    client_attestation_jkt VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    reuse_detected_at TIMESTAMPTZ,
    CONSTRAINT pk_oauth_refresh_families
        PRIMARY KEY (tenant_id, token_family_id),
    CONSTRAINT ux_oauth_refresh_families_current_digest
        UNIQUE (tenant_id, current_token_blake3),
    CONSTRAINT fk_orf_contract
        FOREIGN KEY (tenant_id, contract_blake3)
        REFERENCES oauth_refresh_contracts (tenant_id, contract_blake3),
    CONSTRAINT fk_orf_client_tenant
        FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth_clients (id, tenant_id),
    CONSTRAINT fk_orf_user_tenant
        FOREIGN KEY (user_id, tenant_id)
        REFERENCES users (id, tenant_id),
    CONSTRAINT ck_orf_digest
        CHECK (octet_length(current_token_blake3) = 32
               AND octet_length(contract_blake3) = 32),
    CONSTRAINT ck_orf_current_audience CHECK (
        jsonb_path_match(
            current_audience,
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
        )
    ),
    CONSTRAINT ck_orf_timeline
        CHECK (current_expires_at > current_issued_at)
);

COMMENT ON TABLE oauth_refresh_families IS
    'One row per refresh family: grant authority plus the current generation. Compromise and revocation are single-row facts; rotation updates the current-* columns in place.';

-- Presentation lookup is the hot path: digest -> family.
-- (tenant_id, token_family_id) PK serves family locks and native-SSO checks.

-- Grant-scope authority: family-cap enforcement, grant revocation and SCIM
-- revocation all address live families by (tenant, user, client). Ordering by
-- current_issued_at makes the deterministic oldest-first eviction O(limit).
CREATE INDEX ix_orf_scope_active
    ON oauth_refresh_families (tenant_id, user_id, client_id, current_issued_at, token_family_id)
    WHERE revoked_at IS NULL;

-- Client-mutation revocation addresses live families by (tenant, client);
-- user_id is the middle column of the scope index, so it cannot serve.
CREATE INDEX ix_orf_client_active
    ON oauth_refresh_families (tenant_id, client_id)
    WHERE revoked_at IS NULL;

-- Expiry sweep candidates.
CREATE INDEX ix_orf_expires
    ON oauth_refresh_families (current_expires_at);

CREATE TABLE oauth_refresh_spent_tokens (
    tenant_id UUID NOT NULL,
    refresh_token_blake3 BYTEA NOT NULL,
    token_family_id UUID NOT NULL,
    member_id UUID NOT NULL,
    -- Direct successor named at rotation time; required for the 60s
    -- lost-response edge check.
    successor_member_id UUID NOT NULL,
    spent_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_oauth_refresh_spent_tokens
        PRIMARY KEY (tenant_id, refresh_token_blake3),
    CONSTRAINT fk_orst_family
        FOREIGN KEY (tenant_id, token_family_id)
        REFERENCES oauth_refresh_families (tenant_id, token_family_id)
        ON DELETE CASCADE,
    CONSTRAINT ck_orst_digest
        CHECK (octet_length(refresh_token_blake3) = 32),
    CONSTRAINT ck_orst_timeline
        CHECK (expires_at > spent_at)
);

COMMENT ON TABLE oauth_refresh_spent_tokens IS
    'Minimal reuse/lost-response proof for a rotated generation. Carries no authorization payload; bounded to the newest 64 proofs per family at rotation and deleted at its own expiry or with the family.';

-- Per-family spent proofs are removed together on family retirement/expiry.
CREATE INDEX ix_orst_family
    ON oauth_refresh_spent_tokens (tenant_id, token_family_id);

-- Expiry sweep candidates: spent proofs die at their own expires_at.
CREATE INDEX ix_orst_expires
    ON oauth_refresh_spent_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- Upgrade path: convert oauth_tokens in place. On a fresh database every
-- statement below is a no-op against an empty table.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    has_tokens BOOLEAN;
BEGIN
    SELECT to_regclass('public.oauth_tokens') IS NOT NULL INTO has_tokens;
    IF NOT has_tokens THEN
        RETURN;
    END IF;

    -- Head of each family = latest member. Families whose head already
    -- expired carry no live authority (rotation, presentation and
    -- lost-response all reject expired current state), so they are not
    -- migrated at all — the same reason expired spent members are dropped.
    CREATE TEMPORARY TABLE nazo_refresh_migration_head ON COMMIT DROP AS
    SELECT DISTINCT ON (m.tenant_id, m.token_family_id)
        m.tenant_id,
        m.token_family_id,
        m.id AS member_id,
        m.refresh_token_blake3,
        m.client_id,
        m.user_id,
        m.scopes,
        m.audience,
        m.authorization_details,
        m.issued_at,
        m.expires_at,
        m.revoked_at,
        m.subject,
        m.dpop_jkt,
        m.mtls_x5t_s256,
        m.client_attestation_jkt,
        m.oidc_auth_context
    FROM oauth_tokens AS m
    ORDER BY m.tenant_id, m.token_family_id, m.issued_at DESC, m.id DESC;

    DELETE FROM nazo_refresh_migration_head
    WHERE expires_at <= CURRENT_TIMESTAMP;

    -- Contract material for digest + payload. The persisted contract strips
    -- nonce and id_token_sid; everything else is copied verbatim from the
    -- head member. Digest is a SQL-namespaced 32-byte identity (two md5
    -- halves over the canonical jsonb rendering); runtime writes use BLAKE3
    -- over the canonical Rust serialization. Both are content keys for the
    -- same dedup table; cross-format equality is not required because
    -- migrated families are bounded by their original expiry.
    CREATE TEMPORARY TABLE nazo_refresh_migration_contract ON COMMIT DROP AS
    SELECT
        h.tenant_id,
        h.token_family_id,
        decode(
            md5(nazo_contract.contract::text)
            || md5(nazo_contract.contract::text || '#nazo-refresh-contract'),
            'hex'
        ) AS contract_blake3,
        nazo_contract.contract
    FROM nazo_refresh_migration_head AS h
    CROSS JOIN LATERAL (
        SELECT jsonb_build_object(
            'subject', h.subject,
            'scopes', h.scopes,
            'audiences', h.audience,
            'authorization_details', h.authorization_details,
            'authentication_context',
                (h.oidc_auth_context - 'nonce' - 'id_token_sid')
                || '{"nonce":null,"id_token_sid":null}'::jsonb
        ) AS contract
    ) AS nazo_contract;

    INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract)
    SELECT DISTINCT tenant_id, contract_blake3, contract
    FROM nazo_refresh_migration_contract
    ON CONFLICT (tenant_id, contract_blake3) DO NOTHING;

    INSERT INTO oauth_refresh_families (
        tenant_id, token_family_id, client_id, user_id, contract_blake3,
        current_member_id, current_token_blake3, current_audience,
        current_issued_at, current_expires_at, current_id_token_sid,
        dpop_jkt, mtls_x5t_s256, client_attestation_jkt,
        created_at, revoked_at, reuse_detected_at
    )
    SELECT
        h.tenant_id,
        h.token_family_id,
        h.client_id,
        h.user_id,
        c.contract_blake3,
        h.member_id,
        decode(h.refresh_token_blake3, 'hex'),
        h.audience,
        h.issued_at,
        h.expires_at,
        LEFT(h.oidc_auth_context ->> 'id_token_sid', 128),
        h.dpop_jkt,
        h.mtls_x5t_s256,
        h.client_attestation_jkt,
        agg.created_at,
        CASE
            WHEN h.revoked_at IS NOT NULL THEN h.revoked_at
            ELSE agg.max_reuse_detected_at
        END,
        agg.max_reuse_detected_at
    FROM nazo_refresh_migration_head AS h
    JOIN nazo_refresh_migration_contract AS c
        ON c.tenant_id = h.tenant_id AND c.token_family_id = h.token_family_id
    JOIN (
        SELECT tenant_id, token_family_id,
               MIN(issued_at) AS created_at,
               MAX(reuse_detected_at) AS max_reuse_detected_at
        FROM oauth_tokens
        GROUP BY tenant_id, token_family_id
    ) AS agg
        ON agg.tenant_id = h.tenant_id AND agg.token_family_id = h.token_family_id;

    -- Non-head members of migrated families that are still inside their own
    -- acceptance window keep a compact proof. Revoked members contribute
    -- spent_at = revoked_at; an anomalous unrevoked non-head member is treated
    -- as spent from issuance (fail-closed: its lost-response window is already
    -- gone). Expired members and members of expired families are not moved —
    -- no reader remains.
    INSERT INTO oauth_refresh_spent_tokens (
        tenant_id, refresh_token_blake3, token_family_id, member_id,
        successor_member_id, spent_at, expires_at
    )
    SELECT
        m.tenant_id,
        decode(m.refresh_token_blake3, 'hex'),
        m.token_family_id,
        m.id,
        successor.id,
        COALESCE(m.revoked_at, m.issued_at),
        m.expires_at
    FROM oauth_tokens AS m
    JOIN oauth_refresh_families AS h
        ON h.tenant_id = m.tenant_id AND h.token_family_id = m.token_family_id
    JOIN LATERAL (
        SELECT s.id
        FROM oauth_tokens AS s
        WHERE s.tenant_id = m.tenant_id
          AND s.token_family_id = m.token_family_id
          AND s.rotated_from_id = m.id
        ORDER BY s.issued_at DESC, s.id DESC
        LIMIT 1
    ) AS successor ON TRUE
    WHERE m.id <> h.current_member_id
      AND m.expires_at > CURRENT_TIMESTAMP;

    -- Converge the active-family cap: keep the 10 most recently active
    -- families per (tenant, user, client); retire the rest with their spent
    -- proofs (CASCADE) and orphan contracts. user_id NULL rows belong to
    -- client_credentials-style grants and are uncapped.
    WITH ranked AS (
        SELECT tenant_id, token_family_id,
            row_number() OVER (
                PARTITION BY tenant_id, user_id, client_id
                ORDER BY current_issued_at DESC, token_family_id DESC
            ) AS rn
        FROM oauth_refresh_families
        WHERE user_id IS NOT NULL
          AND revoked_at IS NULL
          AND reuse_detected_at IS NULL
          AND current_expires_at > CURRENT_TIMESTAMP
    )
    DELETE FROM oauth_refresh_families AS f
    USING ranked
    WHERE f.tenant_id = ranked.tenant_id
      AND f.token_family_id = ranked.token_family_id
      AND ranked.rn > 10;

    DELETE FROM oauth_refresh_contracts AS c
    WHERE NOT EXISTS (
        SELECT 1 FROM oauth_refresh_families AS f
        WHERE f.tenant_id = c.tenant_id
          AND f.contract_blake3 = c.contract_blake3
    );

    DROP TABLE oauth_tokens;
    DROP FUNCTION IF EXISTS nazo_refresh_auth_context_is_current(JSONB);
END $$;
