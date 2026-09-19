import json
rows=[json.loads(l) for l in open("/s/soak-metrics-v2.jsonl")]
t0,t1=rows[0]["ts"],rows[-1]["ts"]
d=lambda a,b,k:(b.get(k) or 0)-(a.get(k) or 0)
pool=[r["pool"] for r in rows if "pool" in r]
p0,p1=pool[0],pool[-1]
g=[r["pg_db"] for r in rows if "pg_db" in r]
g0,g1=g[0],g[-1]
print("samples",len(rows),"span_min",round((t1-t0)/60,1),"pool_samples",len(pool))
print("pool_acq",d(p0,p1,"acq"),"wait_total_s",round(d(p0,p1,"wait_ns")/1e9,1),"wait_max_ms",round(max((p.get("wait_max_ns") or 0) for p in pool)/1e6,1))
print("waiters_peak",max((p.get("waiting") or 0) for p in pool),"idle_min",min((p.get("idle") or 0) for p in pool))
st=[r["state"] for r in rows if "state" in r]
print("due_peak",max(s.get("iss_due") or 0 for s in st))
print("tup_ins",d(g0,g1,"tup_ins"),"tup_del",d(g0,g1,"tup_del"),"deadlocks_delta",d(g0,g1,"deadlocks"))
vk=[r["vk"] for r in rows if "vk" in r]
print("vk_evict",max((v.get("evict") or 0) for v in vk))
print("outbox_end",st[-1].get("outbox_pend"),"tokens_end",st[-1].get("tokens"))
