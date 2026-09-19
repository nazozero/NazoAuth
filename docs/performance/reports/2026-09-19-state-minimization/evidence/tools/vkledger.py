"""Valkey state ledger — exact census + sampled detail.

Two passes over a non-blocking SCAN:

1. CENSUS (exact): every key is counted and bucketed into the
   `nazo:state:v1:<dep>:<epoch>:tenant:<uuid>:oauth:<category>` taxonomy.
   Counts are complete, never sampled or truncated — so per-prefix deltas
   between two snapshots are exact retained-keys-per-op evidence.

2. DETAIL (bounded sample): TTL distribution and MEMORY_USAGE are measured
   on a bounded per-category sample (default 400 keys/category). These are
   estimates and are labelled as such; they never feed exact key counts.

Run inside the perf compose network:
    docker run --rm --network nazoauth-perf_perf_net \
        -v $PWD/perf-results:/r nazoauth-perf-perf \
        python3 /r/vkledger.py

Never prints key names or values — only category counters and aggregates.
"""
import redis, collections, json, sys

SAMPLE_PER_CAT = int(sys.argv[2]) if len(sys.argv) > 2 else 400
URL = sys.argv[1] if len(sys.argv) > 1 else "redis://valkey:6379/0"
r = redis.Redis.from_url(URL, decode_responses=True)

def category(k: str) -> str:
    parts = k.split(":")
    # nazo:state:v1:<dep>:<epoch>:tenant:<uuid>:oauth:<category>:...
    if len(parts) > 8 and parts[5] == "tenant":
        return parts[7] + ":" + parts[8]
    if len(parts) > 5:
        return ":".join(parts[5:7])
    return "?"

census = collections.Counter()
detail_keys = collections.defaultdict(list)
for k in r.scan_iter(count=500):
    cat = category(k)
    census[cat] += 1
    if len(detail_keys[cat]) < SAMPLE_PER_CAT:
        detail_keys[cat].append(k)

ttlc = collections.Counter()
mem = collections.Counter()
for cat, keys in detail_keys.items():
    for k in keys:
        t = r.ttl(k)
        bucket = "no_ttl" if t == -1 else ("gone" if t == -2 else str(int(t // 60)) + "m+")
        ttlc[(cat, bucket)] += 1
        try:
            mem[cat] += r.memory_usage(k) or 0
        except Exception:
            pass

out = {
    "census_exact": dict(census.most_common(50)),
    "total_keys": sum(census.values()),
    "sampled_per_cat": {c: len(v) for c, v in detail_keys.items()},
    "ttl_buckets_sampled": {
        c + "|" + t: v for (c, t), v in ttlc.most_common(80)
    },
    "mem_bytes_sampled": dict(mem.most_common(50)),
    "used_memory": r.info("memory").get("used_memory"),
}
print(json.dumps(out, indent=1, sort_keys=True))
