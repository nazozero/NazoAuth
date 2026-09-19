-- Verify the bounded closed-set reclaim algorithm on the oversized fixture
-- shape: 300-node chain, identical issued_at/expires_at.
\set tenant '00000000-0000-0000-0000-000000000001'
\set fam 'f00df00d-0000-4000-8000-000000000002'

BEGIN;
WITH c AS (SELECT id FROM oauth_clients WHERE tenant_id = :'tenant' LIMIT 1),
     u AS (SELECT id FROM users WHERE tenant_id = :'tenant' LIMIT 1),
     ctx AS (SELECT oidc_auth_context FROM oauth_tokens WHERE oidc_auth_context IS NOT NULL LIMIT 1)
INSERT INTO oauth_tokens (
    id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
    client_id, user_id, scopes, audience, authorization_details,
    issued_at, expires_at, subject, oidc_auth_context)
SELECT gen_random_uuid(), :'tenant', md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text),
    :'fam', NULL, c.id, u.id,
    '["openid"]'::jsonb, '["resource://default"]'::jsonb, '[]'::jsonb,
    now() - interval '2 hours',
    now() - interval '1 hour', u.id::text, ctx.oidc_auth_context
FROM generate_series(1, 300) AS seq, c, u, ctx;
WITH ids AS (SELECT id, row_number() OVER (ORDER BY refresh_token_blake3) rn FROM oauth_tokens WHERE token_family_id = :'fam' AND tenant_id = :'tenant')
UPDATE oauth_tokens t SET rotated_from_id = p.id
FROM ids cur JOIN ids p ON p.rn = cur.rn - 1
WHERE t.id = cur.id;

\echo --- stmt1: bounded unlink
WITH doomed AS (
    SELECT id FROM oauth_tokens
    WHERE tenant_id = :'tenant' AND token_family_id = :'fam'
      AND expires_at <= now()
    ORDER BY issued_at DESC,
        EXISTS (
            SELECT 1 FROM oauth_tokens AS c2
            WHERE c2.tenant_id = :'tenant'
              AND c2.token_family_id = :'fam'
              AND c2.rotated_from_id = oauth_tokens.id),
        id DESC
    LIMIT 256 FOR UPDATE SKIP LOCKED
), outside_refs AS (
    SELECT orphan.id FROM oauth_tokens AS orphan
    WHERE orphan.tenant_id = :'tenant'
      AND orphan.token_family_id = :'fam'
      AND orphan.rotated_from_id IN (SELECT id FROM doomed)
      AND orphan.id NOT IN (SELECT id FROM doomed)
    LIMIT 256 FOR UPDATE SKIP LOCKED
)
UPDATE oauth_tokens AS orphan
SET rotated_from_id = NULL
FROM outside_refs
WHERE orphan.id = outside_refs.id;

\echo --- stmt2: closed-set delete
WITH RECURSIVE doomed AS (
    SELECT id FROM oauth_tokens
    WHERE tenant_id = :'tenant' AND token_family_id = :'fam'
      AND expires_at <= now()
    ORDER BY issued_at DESC,
        EXISTS (
            SELECT 1 FROM oauth_tokens AS c2
            WHERE c2.tenant_id = :'tenant'
              AND c2.token_family_id = :'fam'
              AND c2.rotated_from_id = oauth_tokens.id),
        id DESC
    LIMIT 256 FOR UPDATE SKIP LOCKED
), blocked(id) AS (
    SELECT d.id FROM doomed d
    WHERE EXISTS (
        SELECT 1 FROM oauth_tokens AS r
        WHERE r.rotated_from_id = d.id
          AND r.id NOT IN (SELECT id FROM doomed))
    UNION
    SELECT t.id FROM oauth_tokens AS t
    JOIN oauth_tokens AS child ON child.rotated_from_id = t.id
    JOIN blocked b ON b.id = child.id
    WHERE t.id IN (SELECT id FROM doomed)
)
DELETE FROM oauth_tokens AS target
USING doomed
WHERE target.id = doomed.id
  AND target.id NOT IN (SELECT id FROM blocked);

SELECT count(*) AS remaining FROM oauth_tokens WHERE token_family_id = :'fam';

\echo --- repeat to drain
WITH doomed AS (
    SELECT id FROM oauth_tokens
    WHERE tenant_id = :'tenant' AND token_family_id = :'fam'
      AND expires_at <= now()
    ORDER BY issued_at DESC,
        EXISTS (
            SELECT 1 FROM oauth_tokens AS c2
            WHERE c2.tenant_id = :'tenant'
              AND c2.token_family_id = :'fam'
              AND c2.rotated_from_id = oauth_tokens.id),
        id DESC
    LIMIT 256 FOR UPDATE SKIP LOCKED
), outside_refs AS (
    SELECT orphan.id FROM oauth_tokens AS orphan
    WHERE orphan.tenant_id = :'tenant'
      AND orphan.token_family_id = :'fam'
      AND orphan.rotated_from_id IN (SELECT id FROM doomed)
      AND orphan.id NOT IN (SELECT id FROM doomed)
    LIMIT 256 FOR UPDATE SKIP LOCKED
)
UPDATE oauth_tokens AS orphan
SET rotated_from_id = NULL
FROM outside_refs
WHERE orphan.id = outside_refs.id;

WITH RECURSIVE doomed AS (
    SELECT id FROM oauth_tokens
    WHERE tenant_id = :'tenant' AND token_family_id = :'fam'
      AND expires_at <= now()
    ORDER BY issued_at DESC,
        EXISTS (
            SELECT 1 FROM oauth_tokens AS c2
            WHERE c2.tenant_id = :'tenant'
              AND c2.token_family_id = :'fam'
              AND c2.rotated_from_id = oauth_tokens.id),
        id DESC
    LIMIT 256 FOR UPDATE SKIP LOCKED
), blocked(id) AS (
    SELECT d.id FROM doomed d
    WHERE EXISTS (
        SELECT 1 FROM oauth_tokens AS r
        WHERE r.rotated_from_id = d.id
          AND r.id NOT IN (SELECT id FROM doomed))
    UNION
    SELECT t.id FROM oauth_tokens AS t
    JOIN oauth_tokens AS child ON child.rotated_from_id = t.id
    JOIN blocked b ON b.id = child.id
    WHERE t.id IN (SELECT id FROM doomed)
)
DELETE FROM oauth_tokens AS target
USING doomed
WHERE target.id = doomed.id
  AND target.id NOT IN (SELECT id FROM blocked);

SELECT count(*) AS remaining FROM oauth_tokens WHERE token_family_id = :'fam';
ROLLBACK;
