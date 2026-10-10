SELECT base.value::jsonb || jsonb_build_object(
 'revocations',(SELECT jsonb_build_object('total',count(*),'eligible',count(*) FILTER(WHERE expires_at<=now()),'retained',count(*) FILTER(WHERE expires_at>now())) FROM access_token_revocations),
 'issuance_counts',(SELECT jsonb_build_object('total',count(*),'eligible',count(*) FILTER(WHERE retain_until<=now()),'retained',count(*) FILTER(WHERE retain_until>now()),'oldest_due_s',coalesce(extract(epoch FROM now()-min(retain_until) FILTER(WHERE retain_until<=now())),0),'oldest_created_retention_remaining_s',extract(epoch FROM min(retain_until)-now())) FROM oauth_token_issuances),
 'decision_oldest_due_s',(SELECT coalesce(extract(epoch FROM now()-min(business_retain_until)),0) FROM security_audit_events WHERE event_type='authorization_decision_committed' AND exported_at IS NOT NULL AND business_retain_until<=now()),
 'family_oldest_due_s',(SELECT coalesce(extract(epoch FROM now()-min(least(current_expires_at,coalesce(revoked_at,current_expires_at)))),0) FROM oauth_refresh_families WHERE current_expires_at<=now() OR revoked_at IS NOT NULL),
 'decision_retention',(SELECT jsonb_build_object('last_business_retain_until',max(business_retain_until),'last_remaining_s',extract(epoch FROM max(business_retain_until)-clock_timestamp()),'exported_compact',count(*) FILTER(WHERE exported_at IS NOT NULL AND payload='{}'::jsonb),'exported_full',count(*) FILTER(WHERE exported_at IS NOT NULL AND payload<>'{}'::jsonb),'unexported',count(*) FILTER(WHERE exported_at IS NULL)) FROM security_audit_events WHERE event_type='authorization_decision_committed'), 'decision_bytes',(SELECT jsonb_build_object('count',count(*),'payload_bytes',coalesce(sum(pg_column_size(payload)),0),'row_bytes',coalesce(sum(pg_column_size(e)),0)) FROM security_audit_events e WHERE event_type='authorization_decision_committed')
) FROM (SELECT json_build_object(
 'ts',extract(epoch from clock_timestamp()),
 'pending',(SELECT count(*) FROM security_audit_events WHERE exported_at IS NULL),
 'oldest_pending_s',(SELECT COALESCE(extract(epoch from now()-min(occurred_at)),0) FROM security_audit_events WHERE exported_at IS NULL),
 'pending_by_type',(SELECT COALESCE(json_object_agg(event_type,n),'{}') FROM (SELECT event_type,count(*) n FROM security_audit_events WHERE exported_at IS NULL GROUP BY event_type) q),
 'decision_eligible',(SELECT count(*) FROM security_audit_events WHERE event_type='authorization_decision_committed' AND exported_at IS NOT NULL AND business_retain_until<=now()),
 'decision_retained',(SELECT count(*) FROM security_audit_events WHERE event_type='authorization_decision_committed' AND business_retain_until>now()),
 'family_eligible',(SELECT count(*) FROM oauth_refresh_families WHERE current_expires_at<=now() OR revoked_at IS NOT NULL),
 'family_live',(SELECT count(*) FROM oauth_refresh_families WHERE current_expires_at>now() AND revoked_at IS NULL),
 'contract_orphan',(SELECT count(*) FROM oauth_refresh_contracts c WHERE NOT EXISTS(SELECT 1 FROM oauth_refresh_families f WHERE f.tenant_id=c.tenant_id AND f.contract_blake3=c.contract_blake3)),
 'spent_eligible',(SELECT count(*) FROM oauth_refresh_spent_tokens s WHERE s.expires_at<=now() OR EXISTS(SELECT 1 FROM oauth_refresh_families f WHERE f.tenant_id=s.tenant_id AND f.token_family_id=s.token_family_id AND (f.current_expires_at<=now() OR f.revoked_at IS NOT NULL))),
 'spent_retained',(SELECT count(*) FROM oauth_refresh_spent_tokens s WHERE s.expires_at>now() AND NOT EXISTS(SELECT 1 FROM oauth_refresh_families f WHERE f.tenant_id=s.tenant_id AND f.token_family_id=s.token_family_id AND (f.current_expires_at<=now() OR f.revoked_at IS NOT NULL))),
 'anchor',(SELECT anchor_sequence FROM security_audit_chain_state),
 'observed_at',(SELECT extract(epoch from anchor_observed_at) FROM security_audit_chain_state),
 'blocked',(SELECT batch_blocked_reason FROM security_audit_chain_state),
 'db_bytes',pg_database_size(current_database()),
 'tables',(SELECT json_agg(t) FROM (SELECT relname,pg_table_size(relid) table_bytes,pg_indexes_size(relid) index_bytes,n_tup_ins,n_tup_del,n_dead_tup,autovacuum_count FROM pg_stat_user_tables WHERE relname IN('security_audit_events','security_audit_chain_entries','oauth_refresh_contracts','oauth_refresh_families','oauth_refresh_spent_tokens','oauth_token_issuances','access_token_revocations')) t),
 'locks',(SELECT json_agg(t) FROM (SELECT wait_event_type,wait_event,count(*) n,max(extract(epoch from now()-xact_start)) xact_age_s FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() GROUP BY wait_event_type,wait_event) t)
)) AS base(value);
