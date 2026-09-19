#!/usr/bin/env python3
"""Valkey state ledger — exact census + bounded per-category detail.

Two passes over a non-blocking SCAN:

1. CENSUS (exact): every key seen during the scan is counted exactly once
   (dedup by name — SCAN may return a key twice across rehashes) and
   bucketed into the `nazo:state:v1:<dep>:<epoch>:tenant:<uuid>:oauth:
   <category>` taxonomy. Counts are complete over the scan window, not
   sampled — so per-prefix deltas between two ledgers are exact
   retained-keys-per-window evidence. Caveat (declared, not hidden): a
   SCAN is not a point-in-time snapshot — keys expiring or being created
   mid-scan are counted at whatever state they were seen. `scan_ms` and
   `keys_seen` quantify coverage.

2. DETAIL (bounded sample): TTL distribution and MEMORY_USAGE on a bounded
   per-category sample (default 400 keys/category, override argv[2]).
   Estimates only — labelled with sample_n per category, never feeding
   exact counts. sample-sum bytes are NEVER extrapolated to used_memory;
   dictionary/allocator overhead is reported separately via INFO memory.

Usage: vkledger.py [redis-url] [sample-per-cat]
Env:   RUN_ID — required for benchmark runs (stamped into output).

Never prints key names or values — only category counters and aggregates.
"""
import collections
import hashlib
import json
import os
import sys
import time

import redis

SAMPLE_PER_CAT = int(sys.argv[2]) if len(sys.argv) > 2 else 400
URL = sys.argv[1] if len(sys.argv) > 1 else "redis://valkey:6379/0"
RUN_ID = os.environ.get("RUN_ID", "unset")
r = redis.Redis.from_url(URL, decode_responses=True)


def category(k):
    parts = k.split(":")
    # nazo:state:v1:<dep>:<epoch>:tenant:<uuid>:oauth:<category>:...
    if len(parts) > 8 and parts[5] == "tenant":
        return parts[7] + ":" + parts[8]
    if len(parts) > 5:
        return ":".join(parts[5:7])
    return "?"


def main():
    t0 = time.time()
    census = collections.Counter()
    seen = set()
    detail_keys = collections.defaultdict(list)
    for k in r.scan_iter(count=1000):
        if k in seen:
            continue
        seen.add(k)
        cat = category(k)
        census[cat] += 1
        if len(detail_keys[cat]) < SAMPLE_PER_CAT:
            detail_keys[cat].append(k)
    scan_ms = int((time.time() - t0) * 1000)

    ttlc = collections.Counter()
    mem = collections.Counter()
    mem_n = collections.Counter()
    for cat, keys in detail_keys.items():
        for k in keys:
            t = r.ttl(k)
            bucket = ("no_ttl" if t == -1
                      else "gone" if t == -2
                      else str(int(t // 60)) + "m+")
            ttlc[(cat, bucket)] += 1
            try:
                mu = r.memory_usage(k)
                if mu:
                    mem[cat] += mu
                    mem_n[cat] += 1
            except Exception:
                pass

    out = {
        "meta": {
            "run_id": RUN_ID,
            "script_sha256": hashlib.sha256(
                open(__file__, "rb").read()).hexdigest(),
            "sampled_at": int(time.time()),
            "scan_ms": scan_ms,
            "sample_per_cat": SAMPLE_PER_CAT,
        },
        "census_exact": dict(census.most_common(64)),
        "total_keys": sum(census.values()),
        "keys_seen": len(seen),
        "sampled_per_cat": {c: len(v) for c, v in detail_keys.items()},
        "ttl_buckets_sampled": {
            c + "|" + t: v for (c, t), v in ttlc.most_common(96)
        },
        "mem_bytes_sampled": dict(mem.most_common(64)),
        "mem_sample_n": dict(mem_n),
        "info": {
            "dbsize": r.dbsize(),
            "used_memory": r.info("memory").get("used_memory"),
            "used_memory_rss": r.info("memory").get("used_memory_rss"),
            "mem_fragmentation_ratio":
                r.info("memory").get("mem_fragmentation_ratio"),
            "expired_keys": r.info("stats").get("expired_keys"),
            "evicted_keys": r.info("stats").get("evicted_keys"),
            "keyspace_hits": r.info("stats").get("keyspace_hits"),
            "keyspace_misses": r.info("stats").get("keyspace_misses"),
            "rdb_bgsave_in_progress":
                r.info("persistence").get("rdb_bgsave_in_progress"),
            "aof_enabled": r.info("persistence").get("aof_enabled"),
        },
        "done": True,
    }
    print(json.dumps(out, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
