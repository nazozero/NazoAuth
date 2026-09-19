-- state storage ledger snapshot (run identically before/after the run).
-- Run inside the perf postgres container:
--   psql -U nazo -d nazoauth -f ledger.sql
-- Sections are prefixed so the output can be parsed mechanically; every
-- derived amplification number in the report is computed from two snapshots
-- of this file plus the run's logical operation count.

SELECT 'TABLE_SIZE' AS section, c.relname,
       pg_total_relation_size(c.oid) AS total_bytes,
       pg_relation_size(c.oid) AS table_bytes,
       pg_indexes_size(c.oid) AS index_bytes,
       COALESCE(s.n_live_tup,0) AS live_tup_est,
       COALESCE(s.n_dead_tup,0) AS dead_tup_est,
       COALESCE(s.n_tup_ins,0) AS tup_ins,
       COALESCE(s.n_tup_upd,0) AS tup_upd,
       COALESCE(s.n_tup_del,0) AS tup_del,
       COALESCE(s.vacuum_count,0) AS vacuum_count,
       COALESCE(s.autovacuum_count,0) AS autovacuum_count
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid=c.oid
WHERE n.nspname='public' AND c.relkind='r' AND (
  c.relname LIKE 'oauth%' OR c.relname LIKE 'security_audit%' OR c.relname LIKE 'scim%'
  OR c.relname LIKE 'backchannel%' OR c.relname LIKE 'access_token%' OR c.relname LIKE 'tenant%'
  OR c.relname LIKE 'user%' OR c.relname LIKE 'openid%')
ORDER BY pg_total_relation_size(c.oid) DESC;

-- Per-index bytes for the hot relations: index write amplification is a
-- first-class cost, so report index bytes separately from heap bytes.
SELECT 'INDEX_SIZE' AS section, t.relname AS table_name, i.relname AS index_name,
       pg_relation_size(i.oid) AS index_bytes,
       COALESCE(s.idx_scan,0) AS idx_scan
FROM pg_class t
JOIN pg_namespace n ON n.oid=t.relnamespace
JOIN pg_index x ON x.indrelid=t.oid
JOIN pg_class i ON i.oid=x.indexrelid
LEFT JOIN pg_stat_user_indexes s ON s.indexrelid=i.oid
WHERE n.nspname='public' AND (
  t.relname IN ('oauth_tokens','oauth_token_issuances','security_audit_events',
                'security_audit_event_outbox','security_audit_chain_entries',
                'access_token_revocations'))
ORDER BY t.relname, pg_relation_size(i.oid) DESC;

SELECT 'ROW_COUNTS' AS section, 'oauth_tokens' t, count(*)::text v FROM oauth_tokens
UNION ALL SELECT 'ROW_COUNTS','oauth_token_issuances',count(*)::text FROM oauth_token_issuances
UNION ALL SELECT 'ROW_COUNTS','security_audit_events',count(*)::text FROM security_audit_events
UNION ALL SELECT 'ROW_COUNTS','security_audit_event_outbox',count(*)::text FROM security_audit_event_outbox
UNION ALL SELECT 'ROW_COUNTS','security_audit_chain_entries',count(*)::text FROM security_audit_chain_entries
UNION ALL SELECT 'ROW_COUNTS','access_token_revocations',count(*)::text FROM access_token_revocations;

-- Every outbox row is undelivered work: an acknowledged row is deleted in the
-- same transaction that advances the anchor checkpoint, so the only rows that
-- can exist are pending or in-flight claims.
SELECT 'EXPIRED_BACKLOG' AS section, 'oauth_tokens_expired' t, count(*)::text v,
       COALESCE(min(expires_at)::text,'-') oldest FROM oauth_tokens WHERE expires_at <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','issuances_due',count(*)::text,COALESCE(min(retain_until)::text,'-') FROM oauth_token_issuances WHERE retain_until <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','outbox_pending',count(*)::text,COALESCE(min(available_at)::text,'-') FROM security_audit_event_outbox
UNION ALL SELECT 'EXPIRED_BACKLOG','outbox_due_unclaimed',count(*)::text,COALESCE(min(available_at)::text,'-') FROM security_audit_event_outbox WHERE available_at <= now() AND locked_at IS NULL
UNION ALL SELECT 'EXPIRED_BACKLOG','revocations_due',count(*)::text,COALESCE(min(expires_at)::text,'-') FROM access_token_revocations WHERE expires_at <= now();

SELECT 'AUDIT' AS section,
       (SELECT count(*) FROM security_audit_event_outbox) AS pending_export,
       (SELECT count(*) FROM security_audit_event_outbox WHERE locked_at IS NOT NULL) AS in_flight_claims,
       (SELECT count(*) FROM security_audit_events) AS events,
       (SELECT count(*) FROM security_audit_chain_entries) AS chain_entries,
       (SELECT anchor_sequence FROM security_audit_chain_state) AS anchor_sequence;

-- WAL position: diff two snapshots with pg_wal_lsn_diff to get WAL bytes for
-- the window, then divide by logical operations for WAL bytes/op.
SELECT 'WAL' AS section, pg_current_wal_lsn()::text AS lsn,
       pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::text AS lsn_bytes,
       now()::text AS sampled_at;

-- Global DB activity counters (insert/update/delete deltas attribute write
-- volume to relations via TABLE_SIZE tup_* columns).
SELECT 'BGWRITER' AS section, checkpoints_timed::text, checkpoints_req::text,
       buffers_checkpoint::text, buffers_clean::text, buffers_backend::text
FROM pg_stat_bgwriter;

SELECT 'DB_TOTAL' AS section, pg_database_size(current_database())::text AS db_bytes;
