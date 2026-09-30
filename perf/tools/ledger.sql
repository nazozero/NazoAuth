-- Canonical PostgreSQL state ledger — the only byte/DML ledger used by the
-- formal benchmark. Run identically before and after a measurement window:
--
--   psql -X -v ON_ERROR_STOP=1 -v run_id="$RUN_ID" -v phase=pre \
--        -U postgres -d oauth -f ledger.sql > ledger-pre.txt
--
-- Output is UNALIGNED tuples-only (\a \t): pipe-separated rows, no headers.
-- Two row shapes:
--   KV:    section | kind | key | value          (self-describing stats)
--   REL:   RELATION_BYTES | relid | relation | heap_main | heap_aux |
--          user_indexes_total | toast_total | total | live_est | dead_est |
--          ins | upd | hot_upd | del | vac | autovac | component_check
--
-- Every derived amplification number is computed from two outputs of this
-- file plus the run's logical-operation count. ledger_check.py validates:
-- META present, run_id match, required sections, DONE marker, no SQL error
-- lines, component_check == total per relation.
--
-- Reset semantics: every stats view emits stats_reset so the checker can
-- mark untrustworthy deltas INVALID. Gauge columns (sizes, queue length)
-- may legitimately decrease; counter columns may not.

\set QUIET on
\a \t

SELECT 'META', 'run_id', :'run_id'
UNION ALL SELECT 'META', 'phase', :'phase'
UNION ALL SELECT 'META', 'sampled_at', (now() AT TIME ZONE 'utc')::text
UNION ALL SELECT 'META', 'server_version_num', current_setting('server_version_num')
UNION ALL SELECT 'META', 'server_version', version()
UNION ALL SELECT 'META', 'database', current_database()
UNION ALL SELECT 'META', 'schema_version',
       (SELECT max(version) FROM __diesel_schema_migrations)
UNION ALL SELECT 'META', 'pg_stat_statements_track',
       current_setting('pg_stat_statements.track', true)
UNION ALL SELECT 'META', 'db_stats_reset',
       (SELECT (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_database
        WHERE datname = current_database());

-- ============================ RELATION_BYTES ============================
-- One row per PHYSICAL relation (relkind 'r' = heap incl. partition leaves).
-- Partitioned parents have no storage; leaves counted once here and rolled
-- up logically in PARTITION_ROLLUP.
-- total = pg_total_relation_size = heap_main + heap_aux + user_indexes_total
--          + toast_total; component_check re-sums and MUST equal total.
WITH rels AS (
  SELECT c.oid, n.nspname, c.relname, c.reltoastrelid
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
), sized AS (
  SELECT r.oid, r.nspname, r.relname,
         pg_relation_size(r.oid, 'main') AS heap_main,
         pg_relation_size(r.oid, 'fsm')
           + pg_relation_size(r.oid, 'vm')
           + pg_relation_size(r.oid, 'init') AS heap_aux,
         pg_indexes_size(r.oid) AS user_indexes_total,
         CASE WHEN r.reltoastrelid <> 0
              THEN pg_total_relation_size(r.reltoastrelid) ELSE 0 END AS toast_total,
         pg_total_relation_size(r.oid) AS total
  FROM rels r
)
SELECT 'RELATION_BYTES', s.oid::text, s.nspname || '.' || s.relname,
       s.heap_main::text, s.heap_aux::text, s.user_indexes_total::text,
       s.toast_total::text, s.total::text,
       COALESCE(st.n_live_tup,0)::text, COALESCE(st.n_dead_tup,0)::text,
       COALESCE(st.n_tup_ins,0)::text, COALESCE(st.n_tup_upd,0)::text,
       COALESCE(st.n_tup_hot_upd,0)::text, COALESCE(st.n_tup_del,0)::text,
       COALESCE(st.vacuum_count,0)::text, COALESCE(st.autovacuum_count,0)::text,
       (s.heap_main + s.heap_aux + s.user_indexes_total + s.toast_total)::text
FROM sized s LEFT JOIN pg_stat_user_tables st ON st.relid = s.oid
ORDER BY s.total DESC;

-- Logical rollup: leaf bytes attributed to partition root (one logical row).
WITH rels AS (
  SELECT c.oid, n.nspname, c.relname, pg_partition_root(c.oid) AS root_oid
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
)
SELECT 'PARTITION_ROLLUP', rn.nspname || '.' || rc.relname,
       count(*)::text, sum(pg_total_relation_size(r.oid))::text
FROM rels r
JOIN pg_class rc ON rc.oid = r.root_oid
JOIN pg_namespace rn ON rn.oid = rc.relnamespace
WHERE r.root_oid <> r.oid
GROUP BY rn.nspname, rc.relname
ORDER BY sum(pg_total_relation_size(r.oid)) DESC;

-- ============================ INDEX_DETAIL =============================
-- Positional: section | index_oid | relation | index_name | bytes |
--             idx_scan | index_def
SELECT 'INDEX_DETAIL', i.oid::text, tn.nspname || '.' || t.relname,
       i.relname, pg_relation_size(i.oid)::text,
       COALESCE(s.idx_scan,0)::text,
       regexp_replace(pg_get_indexdef(x.indexrelid), '[\n\r\t|]+', ' ', 'g')
FROM pg_class t
JOIN pg_namespace tn ON tn.oid = t.relnamespace
JOIN pg_index x ON x.indrelid = t.oid
JOIN pg_class i ON i.oid = x.indexrelid
LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = i.oid
WHERE tn.nspname = 'public'
ORDER BY t.relname, pg_relation_size(i.oid) DESC;

-- ============================ ROW_COUNTS ===============================
-- Exact counts are BOUNDARY-ONLY evidence (load stopped). Never on a hot
-- sampling cadence or per exporter batch.
SELECT 'ROW_COUNTS', 'oauth_refresh_families', count(*)::text FROM oauth_refresh_families
UNION ALL SELECT 'ROW_COUNTS','oauth_refresh_spent_tokens',count(*)::text FROM oauth_refresh_spent_tokens
UNION ALL SELECT 'ROW_COUNTS','oauth_refresh_contracts',count(*)::text FROM oauth_refresh_contracts
UNION ALL SELECT 'ROW_COUNTS','oauth_token_issuances',count(*)::text FROM oauth_token_issuances
UNION ALL SELECT 'ROW_COUNTS','security_audit_events',count(*)::text FROM security_audit_events
UNION ALL SELECT 'ROW_COUNTS','security_audit_chain_entries',count(*)::text FROM security_audit_chain_entries
UNION ALL SELECT 'ROW_COUNTS','access_token_revocations',count(*)::text FROM access_token_revocations;

-- ============================ REFRESH_MODEL ============================
-- Refresh-state cardinality ledger. `live` = unrevoked, uncompromised and
-- unexpired. The active-family cap is a hard invariant: max_per_scope must
-- never exceed 10 for a user-bound scope.
SELECT 'REFRESH_MODEL', 'families', 'rows_total',
       count(*)::text FROM oauth_refresh_families
UNION ALL SELECT 'REFRESH_MODEL','families','live',
       count(*)::text FROM oauth_refresh_families
       WHERE revoked_at IS NULL AND reuse_detected_at IS NULL
         AND current_expires_at > now()
UNION ALL SELECT 'REFRESH_MODEL','families','live_user_bound',
       count(*)::text FROM oauth_refresh_families
       WHERE user_id IS NOT NULL AND revoked_at IS NULL
         AND reuse_detected_at IS NULL AND current_expires_at > now()
UNION ALL SELECT 'REFRESH_MODEL','families','machine',
       count(*)::text FROM oauth_refresh_families WHERE user_id IS NULL
UNION ALL SELECT 'REFRESH_MODEL','families','revoked',
       count(*)::text FROM oauth_refresh_families WHERE revoked_at IS NOT NULL
UNION ALL SELECT 'REFRESH_MODEL','families','compromised',
       count(*)::text FROM oauth_refresh_families WHERE reuse_detected_at IS NOT NULL
UNION ALL SELECT 'REFRESH_MODEL','families','max_active_per_scope',
       COALESCE((SELECT max(cnt)::text FROM (
         SELECT count(*) AS cnt FROM oauth_refresh_families
         WHERE user_id IS NOT NULL AND revoked_at IS NULL
           AND reuse_detected_at IS NULL AND current_expires_at > now()
         GROUP BY tenant_id, user_id, client_id) s),'0')
UNION ALL SELECT 'REFRESH_MODEL','spent','rows_total',
       count(*)::text FROM oauth_refresh_spent_tokens
UNION ALL SELECT 'REFRESH_MODEL','contracts','rows_total',
       count(*)::text FROM oauth_refresh_contracts
UNION ALL SELECT 'REFRESH_MODEL','contracts','referenced',
       count(*)::text FROM oauth_refresh_contracts c
       WHERE EXISTS (SELECT 1 FROM oauth_refresh_families f
                     WHERE f.tenant_id=c.tenant_id
                       AND f.contract_blake3=c.contract_blake3)
UNION ALL SELECT 'REFRESH_MODEL','families','inserted_cumulative',
       n_tup_ins::text FROM pg_stat_user_tables
       WHERE relname='oauth_refresh_families'
UNION ALL SELECT 'REFRESH_MODEL','families','deleted_cumulative',
       n_tup_del::text FROM pg_stat_user_tables
       WHERE relname='oauth_refresh_families'
UNION ALL SELECT 'REFRESH_MODEL','spent','inserted_cumulative',
       n_tup_ins::text FROM pg_stat_user_tables
       WHERE relname='oauth_refresh_spent_tokens'
UNION ALL SELECT 'REFRESH_MODEL','spent','deleted_cumulative',
       n_tup_del::text FROM pg_stat_user_tables
       WHERE relname='oauth_refresh_spent_tokens'
UNION ALL SELECT 'REFRESH_MODEL','spent','max_per_family',
       COALESCE((SELECT max(cnt)::text FROM (
         SELECT count(*) AS cnt FROM oauth_refresh_spent_tokens
         GROUP BY tenant_id, token_family_id) s),'0')
UNION ALL SELECT 'REFRESH_MODEL','audit','capacity_retired_pending',
       count(*)::text FROM security_audit_events
       WHERE event_type = 'refresh_family_capacity_retired';

-- ============================ EXPIRED_BACKLOG ==========================
SELECT 'EXPIRED_BACKLOG', 'refresh_families_expired', count(*)::text,
       COALESCE(min(current_expires_at AT TIME ZONE 'utc')::text,'-')
FROM oauth_refresh_families WHERE current_expires_at <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','spent_proofs_due',count(*)::text,
       COALESCE(min(expires_at AT TIME ZONE 'utc')::text,'-')
FROM oauth_refresh_spent_tokens WHERE expires_at <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','contracts_unreferenced',count(*)::text,
       '-'
FROM oauth_refresh_contracts c
WHERE NOT EXISTS (SELECT 1 FROM oauth_refresh_families f
                  WHERE f.tenant_id=c.tenant_id
                    AND f.contract_blake3=c.contract_blake3)
UNION ALL SELECT 'EXPIRED_BACKLOG','issuances_due',count(*)::text,
       COALESCE(min(retain_until AT TIME ZONE 'utc')::text,'-')
FROM oauth_token_issuances WHERE retain_until <= now()
UNION ALL SELECT 'EXPIRED_BACKLOG','pending_events',count(*)::text,
       COALESCE(min(occurred_at AT TIME ZONE 'utc')::text,'-')
FROM security_audit_events
UNION ALL SELECT 'EXPIRED_BACKLOG','audit_batch_in_flight',(batch_first_sequence IS NOT NULL)::text,
       COALESCE((batch_locked_until AT TIME ZONE 'utc')::text,'-')
FROM security_audit_chain_state
UNION ALL SELECT 'EXPIRED_BACKLOG','audit_batch_blocked',(batch_blocked_reason IS NOT NULL)::text,
       COALESCE(batch_blocked_reason,'-')
FROM security_audit_chain_state
UNION ALL SELECT 'EXPIRED_BACKLOG','revocations_due',count(*)::text,
       COALESCE(min(expires_at AT TIME ZONE 'utc')::text,'-')
FROM access_token_revocations WHERE expires_at <= now();

-- ============================ AUDIT (KV) ===============================
SELECT 'AUDIT', 'ledger', 'pending_export',
       (SELECT count(*)::text FROM security_audit_events)
UNION ALL SELECT 'AUDIT','ledger','in_flight_batch_events',
       (SELECT COALESCE(batch_event_count,0)::text FROM security_audit_chain_state)
UNION ALL SELECT 'AUDIT','ledger','batch_generation',
       (SELECT batch_generation::text FROM security_audit_chain_state)
UNION ALL SELECT 'AUDIT','ledger','batch_attempts',
       (SELECT batch_attempts::text FROM security_audit_chain_state)
UNION ALL SELECT 'AUDIT','ledger','events',
       (SELECT count(*)::text FROM security_audit_events)
UNION ALL SELECT 'AUDIT','ledger','chain_entries',
       (SELECT count(*)::text FROM security_audit_chain_entries)
UNION ALL SELECT 'AUDIT','ledger','anchor_sequence',
       (SELECT anchor_sequence::text FROM security_audit_chain_state)
UNION ALL SELECT 'AUDIT','ledger','chain_head',
       (SELECT last_sequence::text FROM security_audit_chain_state)
UNION ALL SELECT 'AUDIT','ledger','oldest_pending_age_s',
       (SELECT COALESCE(extract(epoch FROM now()-min(occurred_at))::bigint::text,'-')
        FROM security_audit_events);

-- ============================ XACT_HORIZON ============================
-- MVCC horizon diagnostics: a long transaction pins backend_xmin and makes
-- vacuum unable to reclaim queue-head deletes, which is how dead index
-- prefixes accumulate under the audit pending-order index. Boundary snapshot.
SELECT 'XACT_HORIZON', 'activity', 'oldest_xact_age_s',
       COALESCE(max(extract(epoch FROM now() - xact_start))::bigint::text, '-')
FROM pg_stat_activity
WHERE xact_start IS NOT NULL AND pid <> pg_backend_pid()
UNION ALL
SELECT 'XACT_HORIZON', 'activity', 'xmin_lag_xids',
       COALESCE(max(age(backend_xmin))::text, '-')
FROM pg_stat_activity
WHERE backend_xmin IS NOT NULL AND pid <> pg_backend_pid()
UNION ALL
SELECT 'XACT_HORIZON', 'activity', 'xacts_over_60s',
       count(*)::text
FROM pg_stat_activity
WHERE xact_start IS NOT NULL AND xact_start < now() - interval '60 seconds'
  AND pid <> pg_backend_pid()
UNION ALL
SELECT 'XACT_HORIZON', 'activity', 'xacts_over_300s',
       count(*)::text
FROM pg_stat_activity
WHERE xact_start IS NOT NULL AND xact_start < now() - interval '300 seconds'
  AND pid <> pg_backend_pid()
UNION ALL
SELECT 'XACT_HORIZON', 'activity', 'idle_in_xact_over_60s',
       count(*)::text
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND xact_start IS NOT NULL
  AND xact_start < now() - interval '60 seconds'
  AND pid <> pg_backend_pid()
UNION ALL
SELECT 'XACT_HORIZON', 'prepared', 'prepared_xacts', count(*)::text
FROM pg_prepared_xacts;

-- ============================ WAL (KV) =================================
SELECT 'WAL', 'stats', 'wal_records', wal_records::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_fpi', wal_fpi::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_bytes', wal_bytes::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_buffers_full', wal_buffers_full::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','stats_reset', (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_wal;

-- PG<18 keeps wal_write/wal_sync/wal_*_time in pg_stat_wal; PG18 moved them
-- into pg_stat_io (writes/fsyncs per backend). Emit per actual version.
SELECT current_setting('server_version_num')::int < 180000 AS pg_lt18 \gset
\if :pg_lt18
SELECT 'WAL','stats','wal_write', wal_write::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_sync', wal_sync::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_write_time', wal_write_time::text FROM pg_stat_wal
UNION ALL SELECT 'WAL','stats','wal_sync_time', wal_sync_time::text FROM pg_stat_wal;
\endif

SELECT 'WAL','position','lsn', pg_current_wal_lsn()::text
UNION ALL SELECT 'WAL','position','sampled_at', (now() AT TIME ZONE 'utc')::text;

-- On-disk WAL retention vs generation are different things: report both.
SELECT 'WAL','waldir','files', count(*)::text FROM pg_ls_waldir()
UNION ALL SELECT 'WAL','waldir','bytes', COALESCE(sum(size),0)::text FROM pg_ls_waldir()
UNION ALL SELECT 'WAL','waldir','newest',
       COALESCE(max(modification AT TIME ZONE 'utc')::text,'-') FROM pg_ls_waldir();

SELECT 'WAL','archiver','archived_count', archived_count::text FROM pg_stat_archiver
UNION ALL SELECT 'WAL','archiver','failed_count', failed_count::text FROM pg_stat_archiver
UNION ALL SELECT 'WAL','archiver','last_archived_wal', COALESCE(last_archived_wal,'-') FROM pg_stat_archiver
UNION ALL SELECT 'WAL','archiver','stats_reset', (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_archiver;

SELECT 'WAL','replication_slots','count', count(*)::text FROM pg_replication_slots
UNION ALL SELECT 'WAL','replication_slots','retained_bytes',
       COALESCE(sum(COALESCE(safe_wal_size,0)),0)::text FROM pg_replication_slots
UNION ALL SELECT 'WAL','replication_slots','names',
       COALESCE(string_agg(slot_name||':'||COALESCE(wal_status,'?'),','),'-')
FROM pg_replication_slots;

-- ================== BGWRITER / CHECKPOINTER / IO (KV) ==================
-- Column layout differs by major version: >=17 splits the checkpointer out
-- of bgwriter; pg_stat_io exists >=16. Emit what the actual server has.
SELECT 'BGWRITER','bgwriter','buffers_clean', buffers_clean::text FROM pg_stat_bgwriter
UNION ALL SELECT 'BGWRITER','bgwriter','maxwritten_clean', maxwritten_clean::text FROM pg_stat_bgwriter
UNION ALL SELECT 'BGWRITER','bgwriter','buffers_alloc', buffers_alloc::text FROM pg_stat_bgwriter
UNION ALL SELECT 'BGWRITER','bgwriter','stats_reset', (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_bgwriter;

SELECT current_setting('server_version_num')::int >= 170000 AS pg17 \gset
\if :pg17
SELECT 'CHECKPOINTER','checkpointer','num_timed', num_timed::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','num_requested', num_requested::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','restartpoints_timed', restartpoints_timed::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','restartpoints_req', restartpoints_req::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','restartpoints_done', restartpoints_done::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','write_time', write_time::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','sync_time', sync_time::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','buffers_written', buffers_written::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','stats_reset', (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_checkpointer;
\endif
\if :pg17
SELECT current_setting('server_version_num')::int >= 180000 AS pg18 \gset
\if :pg18
-- PG18 adds num_done and slru_written to pg_stat_checkpointer.
SELECT 'CHECKPOINTER','checkpointer','num_done', num_done::text FROM pg_stat_checkpointer
UNION ALL SELECT 'CHECKPOINTER','checkpointer','slru_written', slru_written::text FROM pg_stat_checkpointer;
\endif
\endif
\if :pg17
\else
SELECT 'CHECKPOINTER','pre17-bgwriter','checkpoints_timed', checkpoints_timed::text FROM pg_stat_bgwriter
UNION ALL SELECT 'CHECKPOINTER','pre17-bgwriter','checkpoints_req', checkpoints_req::text FROM pg_stat_bgwriter
UNION ALL SELECT 'CHECKPOINTER','pre17-bgwriter','checkpoint_write_time', checkpoint_write_time::text FROM pg_stat_bgwriter
UNION ALL SELECT 'CHECKPOINTER','pre17-bgwriter','checkpoint_sync_time', checkpoint_sync_time::text FROM pg_stat_bgwriter
UNION ALL SELECT 'CHECKPOINTER','pre17-bgwriter','buffers_checkpoint', buffers_checkpoint::text FROM pg_stat_bgwriter;
\endif

SELECT current_setting('server_version_num')::int >= 160000 AS pg16 \gset
\if :pg16
SELECT 'IO', backend_type, 'reads', reads::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'read_time', read_time::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'writes', writes::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'write_time', write_time::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'writebacks', writebacks::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'writeback_time', writeback_time::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'extends', extends::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'extend_time', extend_time::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'hits', hits::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'evictions', evictions::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'reuses', reuses::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'fsyncs', fsyncs::text FROM pg_stat_io
UNION ALL SELECT 'IO', backend_type, 'fsync_time', fsync_time::text FROM pg_stat_io;
\else
SELECT 'IO','unavailable','reason','pg_stat_io requires PostgreSQL 16+';
\endif

-- ============================ DB_TOTAL / ACTIVITY (KV) =================
SELECT 'DB_TOTAL','db','db_bytes', pg_database_size(current_database())::text
UNION ALL SELECT 'DB_TOTAL','db','temp_bytes', temp_bytes::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','temp_files', temp_files::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','xact_commit', xact_commit::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','xact_rollback', xact_rollback::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','tup_returned', tup_returned::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','tup_fetched', tup_fetched::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','tup_inserted', tup_inserted::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','tup_updated', tup_updated::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','tup_deleted', tup_deleted::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','deadlocks', deadlocks::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','blk_read_time', blk_read_time::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','blk_write_time', blk_write_time::text FROM pg_stat_database WHERE datname=current_database()
UNION ALL SELECT 'DB_TOTAL','db','stats_reset', (stats_reset AT TIME ZONE 'utc')::text FROM pg_stat_database WHERE datname=current_database();

SELECT 'ACTIVITY','backends','total', count(*)::text FROM pg_stat_activity WHERE datname=current_database()
UNION ALL SELECT 'ACTIVITY','backends','active', count(*) FILTER (WHERE state='active')::text FROM pg_stat_activity WHERE datname=current_database()
UNION ALL SELECT 'ACTIVITY','backends','idle_in_tx', count(*) FILTER (WHERE state='idle in transaction')::text FROM pg_stat_activity WHERE datname=current_database()
UNION ALL SELECT 'ACTIVITY','backends','lock_waiting', count(*) FILTER (WHERE wait_event_type='Lock')::text FROM pg_stat_activity WHERE datname=current_database();

-- ============================ TOP_STATEMENTS (KV) ======================
-- SQL-level attribution boundary. `track` reported in META; when track=all
-- nested function calls appear as separate queryids — never summed into
-- toplevel counts. Section is absent (feature-flagged) when the extension
-- is not installed — the checker treats that as a hard failure for the
-- benchmark DB, which always enables pg_stat_statements.
SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pg_stat_statements') AS has_pss \gset
\if :has_pss
SELECT 'TOP_STATEMENTS', queryid::text, 'calls', calls::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'rows', rows::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'total_exec_time', total_exec_time::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'shared_blks_read', shared_blks_read::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'shared_blks_written', shared_blks_written::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'temp_blks_read', temp_blks_read::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'temp_blks_written', temp_blks_written::text FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s
UNION ALL SELECT 'TOP_STATEMENTS', queryid::text, 'query_head',
       regexp_replace(left(query,160), '[\n\r\t|]+', ' ', 'g') FROM (
  SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 40) s;
\else
SELECT 'TOP_STATEMENTS','unavailable','reason','pg_stat_statements extension not installed';
\endif

-- ============================ DONE =====================================
SELECT 'DONE','complete', (now() AT TIME ZONE 'utc')::text;
