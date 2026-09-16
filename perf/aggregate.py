#!/usr/bin/env python3
"""Aggregate all capacity-*.summary.json under /r into a compact JSON table."""
import glob
import json

rows = []
for f in sorted(glob.glob('/r/*/capacity-*.summary.json')):
    point = f.split('/')[-2]
    try:
        d = json.load(open(f))
    except Exception:
        continue
    r = d.get('result', d)
    m = r.get('k6', {}).get('measure', {})
    if not m:
        continue
    c = r.get('containers', {}).get('by_service', {})
    sql = r.get('sql', {}) or {}
    rows.append({
        'point': point,
        'ops_per_s': m.get('ops_per_s', 0),
        'ops': m.get('ops', 0),
        'errors': m.get('errors', 0),
        'p50': m.get('latency_ms', {}).get('p50'),
        'p95': m.get('latency_ms', {}).get('p95'),
        'p99': m.get('latency_ms', {}).get('p99'),
        'buckets': m.get('buckets'),
        'sql_per_req': sql.get('statements_per_http_request'),
        'pg': sql,
        'app_cpu': c.get('nazoauth', {}).get('cpu_percent_avg'),
        'app_rss': c.get('nazoauth', {}).get('memory_avg_bytes'),
        'pg_cpu': c.get('postgres', {}).get('cpu_percent_avg'),
        'db_conns': sql.get('connections_avg'),
        'pool_wait_ms': (r.get('db_pool', {}) or {}).get('wait_ms_avg'),
    })
print(json.dumps(rows, indent=1))
