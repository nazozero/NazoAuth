-- Remove only proven constant/empty state and logically redundant FKs.
-- Diesel's transaction must cover both preconditions and DDL.
LOCK TABLE controller_registry_slots, oauth_clients,
    openid4vci_credential_configurations, organizations, realms,
    user_mfa_remembered_devices, users IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    expected RECORD;
    actual RECORD;
BEGIN
    IF current_setting('session_replication_role') <> 'origin' THEN
        RAISE EXCEPTION 'inert schema cleanup requires ordinary FK enforcement';
    END IF;

    IF EXISTS (SELECT 1 FROM oauth_clients
               WHERE backchannel_user_code_parameter IS DISTINCT FROM FALSE) THEN
        RAISE EXCEPTION 'cannot remove CIBA user-code state: non-false legacy value';
    END IF;
    IF EXISTS (SELECT 1 FROM openid4vci_credential_configurations) THEN
        RAISE EXCEPTION 'cannot remove legacy OpenID4VCI configuration table: table is not empty';
    END IF;
    IF EXISTS (SELECT 1 FROM controller_registry_slots WHERE last_used_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot remove controller last-used state: non-null legacy value';
    END IF;
    IF EXISTS (SELECT 1 FROM user_mfa_remembered_devices WHERE last_used_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot remove remembered-device last-used state: non-null legacy value';
    END IF;

    -- MATCH SIMPLE only implies the single-column constraints when the
    -- child tenant and directory keys cannot be NULL. Refuse catalog drift.
    -- Older PostgreSQL releases keep column NOT NULL only in pg_attribute;
    -- inspect newer catalog entries when present without requiring that shape.
    IF EXISTS (
        SELECT 1
        FROM (VALUES
            ('users'::regclass, 'tenant_id'),
            ('users'::regclass, 'realm_id'),
            ('users'::regclass, 'organization_id'),
            ('oauth_clients'::regclass, 'tenant_id'),
            ('oauth_clients'::regclass, 'realm_id'),
            ('oauth_clients'::regclass, 'organization_id'),
            ('realms'::regclass, 'id'),
            ('realms'::regclass, 'tenant_id'),
            ('organizations'::regclass, 'id'),
            ('organizations'::regclass, 'tenant_id')
        ) AS required(table_oid, column_name)
        LEFT JOIN pg_catalog.pg_attribute AS a
          ON a.attrelid = required.table_oid
         AND a.attname = required.column_name
         AND NOT a.attisdropped
        WHERE a.attnum IS NULL OR NOT a.attnotnull
           OR EXISTS (
               SELECT 1 FROM pg_catalog.pg_constraint AS nn
               WHERE nn.conrelid = a.attrelid AND nn.contype = 'n'
                 AND nn.conkey = ARRAY[a.attnum]
                 AND (NOT nn.convalidated
                      OR NOT COALESCE((to_jsonb(nn)->>'conenforced')::boolean, TRUE))
           )
    ) THEN
        RAISE EXCEPTION 'cannot simplify directory FKs: required non-null key shape drifted';
    END IF;

    -- Exactly the eight known constraints, not a generic compatibility layer.
    FOR expected IN
        SELECT * FROM (VALUES
            ('users'::regclass, 'fk_users_realm', 'realms'::regclass,
             ARRAY['realm_id'], ARRAY['id']),
            ('users'::regclass, 'fk_users_realm_tenant', 'realms'::regclass,
             ARRAY['realm_id','tenant_id'], ARRAY['id','tenant_id']),
            ('users'::regclass, 'fk_users_organization', 'organizations'::regclass,
             ARRAY['organization_id'], ARRAY['id']),
            ('users'::regclass, 'fk_users_organization_tenant', 'organizations'::regclass,
             ARRAY['organization_id','tenant_id'], ARRAY['id','tenant_id']),
            ('oauth_clients'::regclass, 'fk_oauth_clients_realm', 'realms'::regclass,
             ARRAY['realm_id'], ARRAY['id']),
            ('oauth_clients'::regclass, 'fk_oauth_clients_realm_tenant', 'realms'::regclass,
             ARRAY['realm_id','tenant_id'], ARRAY['id','tenant_id']),
            ('oauth_clients'::regclass, 'fk_oauth_clients_organization', 'organizations'::regclass,
             ARRAY['organization_id'], ARRAY['id']),
            ('oauth_clients'::regclass, 'fk_oauth_clients_organization_tenant', 'organizations'::regclass,
             ARRAY['organization_id','tenant_id'], ARRAY['id','tenant_id'])
        ) AS required(child_oid, constraint_name, parent_oid, child_columns, parent_columns)
    LOOP
        SELECT c.* INTO actual
        FROM pg_catalog.pg_constraint AS c
        WHERE c.conrelid = expected.child_oid
          AND c.conname = expected.constraint_name
          AND c.contype = 'f';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cannot simplify directory FKs: missing %', expected.constraint_name;
        END IF;
        IF actual.confrelid <> expected.parent_oid
           OR actual.conkey IS DISTINCT FROM ARRAY(
               SELECT a.attnum FROM unnest(expected.child_columns)
                   WITH ORDINALITY AS wanted(name, ordinal)
               JOIN pg_catalog.pg_attribute AS a
                 ON a.attrelid = expected.child_oid AND a.attname = wanted.name
                AND NOT a.attisdropped
               ORDER BY wanted.ordinal)
           OR actual.confkey IS DISTINCT FROM ARRAY(
               SELECT a.attnum FROM unnest(expected.parent_columns)
                   WITH ORDINALITY AS wanted(name, ordinal)
               JOIN pg_catalog.pg_attribute AS a
                 ON a.attrelid = expected.parent_oid AND a.attname = wanted.name
                AND NOT a.attisdropped
               ORDER BY wanted.ordinal)
           OR NOT COALESCE((to_jsonb(actual)->>'conenforced')::boolean, TRUE)
           OR NOT actual.convalidated
           OR actual.condeferrable OR actual.condeferred
           OR actual.confmatchtype <> 's'
           OR actual.confdeltype <> 'a' OR actual.confupdtype <> 'a'
           OR (SELECT count(*) FROM pg_catalog.pg_trigger AS t
               WHERE t.tgconstraint = actual.oid AND t.tgenabled IN ('O', 'A')) <> 4
        THEN
            RAISE EXCEPTION 'cannot simplify directory FKs: unexpected semantics for %',
                expected.constraint_name;
        END IF;
    END LOOP;

    -- Preserve the original identity and composite parent-key authorities.
    IF EXISTS (
        SELECT 1
        FROM (VALUES
            ('realms'::regclass, 'p'::"char", ARRAY['id']),
            ('realms'::regclass, 'u'::"char", ARRAY['id','tenant_id']),
            ('organizations'::regclass, 'p'::"char", ARRAY['id']),
            ('organizations'::regclass, 'u'::"char", ARRAY['id','tenant_id'])
        ) AS required(table_oid, kind, columns)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint AS c
            JOIN pg_catalog.pg_index AS i ON i.indexrelid = c.conindid
            WHERE c.conrelid = required.table_oid AND c.contype = required.kind
              AND NOT c.condeferrable AND c.convalidated
              AND i.indisunique AND i.indisvalid AND i.indisready
              AND c.conkey = ARRAY(
                  SELECT a.attnum FROM unnest(required.columns)
                      WITH ORDINALITY AS wanted(name, ordinal)
                  JOIN pg_catalog.pg_attribute AS a
                    ON a.attrelid = required.table_oid AND a.attname = wanted.name
                   AND NOT a.attisdropped
                  ORDER BY wanted.ordinal)
        )
    ) THEN
        RAISE EXCEPTION 'cannot simplify directory FKs: parent key authority drifted';
    END IF;
END;
$$;

ALTER TABLE oauth_clients
    DROP CONSTRAINT ck_oauth_clients_ciba_user_code_disabled,
    DROP COLUMN backchannel_user_code_parameter,
    DROP CONSTRAINT fk_oauth_clients_realm,
    DROP CONSTRAINT fk_oauth_clients_organization;
ALTER TABLE users
    DROP CONSTRAINT fk_users_realm,
    DROP CONSTRAINT fk_users_organization;
DROP TABLE openid4vci_credential_configurations;
ALTER TABLE controller_registry_slots DROP COLUMN last_used_at;
ALTER TABLE user_mfa_remembered_devices DROP COLUMN last_used_at;
