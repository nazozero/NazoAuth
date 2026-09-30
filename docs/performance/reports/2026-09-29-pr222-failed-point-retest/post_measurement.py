#!/usr/bin/env python3
"""Post-measurement read-only population/full SQL evidence. Never prints secrets."""
import os,json,subprocess,sys,time,hashlib
from pathlib import Path
spec=json.loads(Path(sys.argv[1]).read_text()); project=os.environ['SIS_PROJECT']
out=Path(os.environ['SIS_RESULTS'])/spec['phase']/spec['name']
def command(args):
    return subprocess.run(args,text=True,capture_output=True,timeout=30,check=True).stdout.strip()
def sql(q):
    return json.loads(command(['docker','exec',project+'-postgres-1','psql','-U','postgres','-d','oauth','-At','-c',q]))
result={'ts':time.time(),'collected':False,'collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
try:
    result['pgss_full']=sql("SELECT json_build_object('stats_reset',(SELECT stats_reset FROM pg_stat_statements_info),'dealloc',(SELECT dealloc FROM pg_stat_statements_info),'statements',(SELECT json_agg(t) FROM (SELECT s.dbid,d.datname,s.userid,r.rolname,s.toplevel,s.queryid,s.calls,s.total_exec_time,s.rows,s.wal_records,s.wal_fpi,s.wal_bytes,s.stats_since,s.shared_blks_hit,s.shared_blks_read,s.shared_blks_dirtied,s.shared_blks_written,s.query AS q FROM pg_stat_statements s JOIN pg_roles r ON r.oid=s.userid JOIN pg_database d ON d.oid=s.dbid ORDER BY total_exec_time DESC) t))")
    result['relation_stats']=sql("SELECT json_agg(t) FROM (SELECT relname,n_live_tup,n_dead_tup,n_tup_ins,n_tup_upd,n_tup_del,seq_scan,seq_tup_read,idx_scan,last_autovacuum,last_analyze,last_autoanalyze FROM pg_stat_user_tables WHERE relname IN ('oauth_refresh_families','oauth_refresh_spent_tokens','oauth_token_issuances','security_audit_events','user_client_grants')) t")
    result['family_population']=sql("SELECT json_build_object('rows',(SELECT count(*) FROM oauth_refresh_families),'users',(SELECT count(DISTINCT user_id) FROM oauth_refresh_families),'live',(SELECT count(*) FROM oauth_refresh_families WHERE revoked_at IS NULL AND reuse_detected_at IS NULL AND current_expires_at>CURRENT_TIMESTAMP),'users_in_database',(SELECT count(*) FROM users))")
    code="import json,hashlib; from pathlib import Path; p=Path('/state/secrets.json'); b=p.read_bytes(); d=json.loads(b); print(json.dumps({'secrets_sha256':hashlib.sha256(b).hexdigest(),'seed_users':len(d.get('users',[])),'logged_in_sessions':len(d.get('logged_in_sessions',[])),'seeded_refresh_tokens':len(d.get('oidc_refresh_tokens',[])),'shared_seed':True}))"
    result['seed_population']=json.loads(command(['docker','run','--rm','--entrypoint','python','-v',project+'_perf_state:/state:ro',os.environ['SIS_PERF_IMAGE'],'-c',code]))
    result['indexes']=sql("SELECT json_agg(t) FROM (SELECT indexname,indexdef FROM pg_indexes WHERE tablename='oauth_refresh_families') t")
    try:
        query=next(r['q'] for r in result['pgss_full']['statements'] if r['queryid']==3059364362978693673 and r['rolname']=='nazoauth_perf_runtime' and r['toplevel'])
        result['fresh_generic_load_family_plan']=json.loads(command(['docker','exec',project+'-postgres-1','psql','-U','nazoauth_perf_runtime','-d','oauth','-qAt','-c','EXPLAIN (GENERIC_PLAN TRUE,FORMAT JSON) '+query]))
        result['plan_scope']='Fresh post-load generic plan; not the application connection cached plan.'
    except Exception as e: result['plan_error_kind']=type(e).__name__
    result['collected']=True
except Exception as e: result['error_kind']=type(e).__name__
(out/'post-measurement-diagnostics.json').write_text(json.dumps(result,indent=2)+'\n')
