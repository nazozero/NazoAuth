"""Sample NazoAuth table and audit-index counters on PostgreSQL 18 at Goose window boundaries."""
import json
from pathlib import Path
import re
import subprocess
import sys
import time

window, container, database, role = sys.argv[1:]
meta = Path(window) / "window"
deadline = time.monotonic() + 180
while time.monotonic() < deadline:
    fields = dict(re.findall(r"\b(epoch_ns|warm|seconds)=(\d+)\b", meta.read_text())) if meta.exists() else {}
    if fields.keys() >= {"epoch_ns", "warm", "seconds"}:
        break
    time.sleep(.05)
else:
    raise SystemExit("Goose did not announce a measurement window")

query = """
SELECT json_build_object('at_ns', (extract(epoch FROM statement_timestamp()) * 1000000000)::bigint,
    'tables', json_object_agg(s.relname, json_build_array(
        i.heap_blks_hit + coalesce(i.idx_blks_hit, 0) + coalesce(i.toast_blks_hit, 0) + coalesce(i.tidx_blks_hit, 0),
        i.heap_blks_read + coalesce(i.idx_blks_read, 0) + coalesce(i.toast_blks_read, 0) + coalesce(i.tidx_blks_read, 0),
        s.n_tup_ins, s.n_tup_upd, s.n_tup_del) ORDER BY s.relname),
    'audit_heap', (SELECT json_build_object('heap_reads',i.heap_blks_read,'toast_reads',i.toast_blks_read,
        'toast_index_reads',i.tidx_blks_read,'seq_scans',s.seq_scan,'seq_rows',s.seq_tup_read,
        'autovacuums',s.autovacuum_count,'autoanalyzes',s.autoanalyze_count)
        FROM pg_stat_user_tables s JOIN pg_statio_user_tables i USING (relid)
        WHERE s.relid='public.security_audit_events'::regclass),
    'audit_indexes', (SELECT json_object_agg(indexrelname,idx_blks_read)
        FROM pg_statio_user_indexes WHERE relid='public.security_audit_events'::regclass),
    'cluster_read_bytes', (SELECT json_object_agg(backend_type,bytes) FROM
        (SELECT backend_type,sum(read_bytes) AS bytes FROM pg_stat_io WHERE object='relation'
         GROUP BY backend_type) b))
FROM pg_stat_user_tables s JOIN pg_statio_user_tables i USING (relid)
WHERE s.schemaname = 'public'
"""
begin = int(fields["epoch_ns"]) + int(fields["warm"]) * 10**9
end = begin + int(fields["seconds"]) * 10**9
snapshots = []
for target in (begin, end):
    time.sleep(max(0, (target - time.time_ns()) / 10**9))
    value = json.loads(subprocess.check_output(
        ["docker", "exec", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", database, "-c", query]))
    if abs(value["at_ns"] - target) > 10**9:
        raise SystemExit("PostgreSQL observation missed the window boundary by more than one second")
    snapshots.append(value)
print(json.dumps(dict(start_ns=begin, end_ns=end, columns=["hits","reads","inserts","updates","deletes"],
                      before=snapshots[0], after=snapshots[1]), separators=(",",":")))
