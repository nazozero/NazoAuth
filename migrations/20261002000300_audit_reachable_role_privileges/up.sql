-- Traverse every membership edge before filtering roles the login can assume.
-- Privilege probes on each eligible role also cover its inheritance and PUBLIC.
-- CREATE OR REPLACE preserves the function identity, owner and existing ACL.
CREATE OR REPLACE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN, p_require_append BOOLEAN, p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE login_role(oid) AS (
        SELECT oid FROM pg_roles WHERE rolname = session_user
    ), membership(oid) AS (
        SELECT oid FROM login_role
        UNION
        SELECT edge.roleid
        FROM pg_auth_members AS edge
        JOIN membership AS member ON member.oid = edge.member
    ), eligible(oid) AS (
        SELECT member.oid
        FROM membership AS member
        WHERE member.oid = (SELECT oid FROM login_role)
            OR pg_has_role(session_user, member.oid,
                CASE WHEN current_setting('server_version_num')::INTEGER >= 160000
                    THEN 'SET' ELSE 'MEMBER' END)
    )
    SELECT (NOT COALESCE(p_require_append, FALSE) OR has_function_privilege(session_user,
        'public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)'::REGPROCEDURE, 'EXECUTE'))
    AND (NOT COALESCE(p_require_exporter, FALSE) OR (
        has_function_privilege(session_user, 'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_batch_members()'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_claim_security_audit_pending(bigint)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_reclaim_security_audit_batch(bytea,integer)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
        AND has_function_privilege(session_user, 'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
    ))
    AND (NOT COALESCE(p_require_least_privilege, TRUE) OR (
        NOT EXISTS (
            SELECT 1 FROM membership AS member
            JOIN pg_roles AS role ON role.oid = member.oid
            WHERE role.rolsuper AND pg_has_role(session_user, role.oid, 'MEMBER')
        )
        AND NOT EXISTS (
            SELECT 1 FROM pg_class AS relation JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public' AND relation.relname IN (
                'security_audit_chain_state', 'security_audit_events', 'security_audit_chain_entries'
            ) AND (
                pg_has_role(session_user, relation.relowner, 'MEMBER')
                OR EXISTS (
                    SELECT 1 FROM eligible AS role
                    WHERE has_table_privilege(role.oid, relation.oid,
                        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                        OR has_any_column_privilege(role.oid, relation.oid,
                            'SELECT,INSERT,UPDATE,REFERENCES')
                )
            )
        )
    )) AS policy_satisfied
$$;
