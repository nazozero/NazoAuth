import redis, collections, json
r = redis.Redis.from_url("redis://valkey:6379/0", decode_responses=True)
cats = collections.Counter(); ttlc = collections.Counter(); mem = collections.Counter()
n = 0
for k in r.scan_iter(count=200):
    n += 1
    parts = k.split(":")
    # nazo:state:v1:<dep>:<epoch>:tenant:<uuid>:oauth:<category>:...
    if len(parts) > 8 and parts[5] == "tenant":
        cat = parts[7] + ":" + parts[8]
    elif len(parts) > 5:
        cat = ":".join(parts[5:7])
    else:
        cat = "?"
    t = r.ttl(k)
    ttb = "no_ttl" if t == -1 else ("gone" if t == -2 else str(int(t // 60)) + "m+")
    cats[cat] += 1; ttlc[(cat, ttb)] += 1
    try:
        mem[cat] += r.memory_usage(k) or 0
    except Exception:
        pass
    if n >= 30000:
        break
out = {"scanned": n, "by_cat": dict(cats.most_common(30)),
       "ttl_buckets": {c + "|" + t: v for (c, t), v in ttlc.most_common(60)},
       "mem_bytes": dict(mem.most_common(30))}
print(json.dumps(out, indent=1))
