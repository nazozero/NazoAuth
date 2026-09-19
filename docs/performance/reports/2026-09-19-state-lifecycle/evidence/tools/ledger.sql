-- state storage ledger snapshot (run identically before/after)
SELECT 'TABLE_SIZE' AS section, relname,
       pg_total_relation_size(c.oid) AS total_bytes,
       pg_relation_size(c.oid) AS table_bytes,
       pg_indexes_size(c.oid) AS index_bytes,
       COALESCE(s.n_live_tup,0) AS live_tup_est,
       COALESCE(s.n_dead_tup,0) AS dead_tup_est
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid=c.oid
WHERE n.nspname='public' AND c.relkind='r' AND (
  relname LIKE 'oauth%' OR relname LIKE 'security_audit%' OR relname LIKE 'scim%'
  OR relname LIKE 'backchannel%' OR relname LIKE 'access_token%' OR relname LIKE 'tenant%'
  OR relname LIKE 'user%' OR relname LIKE 'openid%')
ORDER BY pg_total_relation_size(c.oid) DESC;
SELECT 'ROW_COUNTS' AS section, 'oauth_tokens' t, count(*)::text v FROM oauth_tokens
UNION ALL SELECT 'ROW_COUNTS','oauth_token_issuances',count(*)::text FROM oauth_token_issuances
UNION ALL SELECT 'ROW_COUNTS','security_audit_events',count(*)::text FROM security_audit_events
UNION ALL SELECT 'ROW_COUNTS','security_audit_event_outbox',count(*)::text FROM security_audit_event_outbox
UNION ALL SELECT 'ROW_COUNTS','security_audit_chain_entries',count(*)::text FROM security_audit_chain_entries;
SELECT 'EXPIRED_BACKLOG' AS section, 'oauth_tokens_expired' t, count(*)::text v,
       COALESCE(min(expires_at)::text,'-') oldest FROM oauth_tokens WHERE expires_at <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','issuances_due',count(*)::text,COALESCE(min(retain_until)::text,'-') FROM oauth_token_issuances WHERE retain_until <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','outbox_pending',count(*)::text,COALESCE(min(available_at)::text,'-') FROM security_audit_event_outbox WHERE exported_at IS NULL
UNION ALL SELECT 'EXPIRED_BACKLOG','outbox_exported_grace',count(*)::text,COALESCE(min(exported_at)::text,'-') FROM security_audit_event_outbox WHERE exported_at IS NOT NULL AND exported_at <= now()-interval '1 day'
UNION ALL SELECT 'EXPIRED_BACKLOG','revocations_due',count(*)::text,COALESCE(min(expires_at)::text,'-') FROM access_token_revocations WHERE expires_at <= now();
SELECT 'AUDIT' AS section,
       (SELECT count(*) FROM security_audit_event_outbox WHERE exported_at IS NULL) AS pending_export,
       (SELECT count(*) FROM security_audit_event_outbox WHERE exported_at IS NOT NULL) AS exported_rows,
       (SELECT count(*) FROM security_audit_events) AS events,
       (SELECT count(*) FROM security_audit_chain_entries) AS chain_entries;
