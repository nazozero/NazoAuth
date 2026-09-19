import json,time,urllib.request,sys
import psycopg, redis
DB="postgresql://postgres:postgres@postgres:5432/oauth"
VK="redis://valkey:6379/0"
APP="http://nazoauth:8000/__perf/metrics"
out=open("/perf-state/soak-metrics-v2.jsonl","a",buffering=1)
r=redis.Redis.from_url(VK,decode_responses=True)
while True:
    row={"ts":int(time.time())}
    try:
        with psycopg.connect(DB) as c:
            row["pg"]=dict(zip(["backends","active","idle_in_tx"],
                c.execute("SELECT count(*),count(*) FILTER(WHERE state=%s),count(*) FILTER(WHERE state=%s) FROM pg_stat_activity",("active","idle in transaction")).fetchone()))
            row["pg_db"]=dict(zip(["xact_commit","xact_rollback","blks_read","blks_hit","tup_ret","tup_ins","tup_upd","tup_del","deadlocks","temp_bytes"],
                c.execute("SELECT xact_commit,xact_rollback,blks_read,blks_hit,tup_returned,tup_inserted,tup_updated,tup_deleted,deadlocks,temp_bytes FROM pg_stat_database WHERE datname=%s",("oauth",)).fetchone()))
            row["state"]=dict(zip(["tokens","tokens_exp","issuances","iss_due","outbox_pend","outbox_exp","audit_events","chain_entries"],
                c.execute("""SELECT (SELECT count(*) FROM oauth_tokens),
                  (SELECT count(*) FROM oauth_tokens WHERE expires_at<=now()),
                  (SELECT count(*) FROM oauth_token_issuances),
                  (SELECT count(*) FROM oauth_token_issuances WHERE retain_until<=now()),
                  (SELECT count(*) FROM security_audit_event_outbox WHERE exported_at IS NULL),
                  (SELECT count(*) FROM security_audit_event_outbox WHERE exported_at IS NOT NULL),
                  (SELECT count(*) FROM security_audit_events),
                  (SELECT count(*) FROM security_audit_chain_entries)""").fetchone()))
            row["oldest"]=dict(zip(["exp_tok_age_s","pend_outbox_age_s"],
                c.execute("""SELECT COALESCE(EXTRACT(EPOCH FROM now()-min(expires_at))::int,-1),
                  COALESCE(EXTRACT(EPOCH FROM now()-min(available_at))::int,-1)
                  FROM oauth_tokens, security_audit_event_outbox
                  WHERE oauth_tokens.expires_at<=now() AND security_audit_event_outbox.exported_at IS NULL""").fetchone() or (-1,-1)))
    except Exception as e: row["pg_err"]=str(e)[:160]
    try:
        i=r.info("stats"); m=r.info("memory"); cl=r.info("clients"); ks=r.info("keyspace")
        row["vk"]={"cmd":i.get("total_commands_processed"),"hits":i.get("keyspace_hits"),"miss":i.get("keyspace_misses"),
                   "exp":i.get("expired_keys"),"mem":m.get("used_memory"),"clients":cl.get("connected_clients"),
                   "evict":i.get("evicted_keys"),
                   "keys":(ks.get("db0") or {}).get("keys",0)}
    except Exception as e: row["vk_err"]=str(e)[:120]
    try:
        req=urllib.request.Request(APP,headers={"Host":"127.0.0.1:8000"})
        with urllib.request.urlopen(req,timeout=5) as resp:
            pm=json.load(resp)
        p=pm["db_pool"]
        row["pool"]={"acq":p["acquire_count"],"wait_ns":p["wait_nanos_total"],"wait_max_ns":p["wait_nanos_max"],
                     "conns":p.get("connections"),"idle":p.get("idle_connections"),"waiting":p.get("waiting_acquisitions")}
    except Exception as e: row["app_err"]=str(e)[:120]
    out.write(json.dumps(row)+"\n")
    time.sleep(10)
