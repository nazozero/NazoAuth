"""Add read-only WAL boundaries inside the existing request/counter window."""

from pathlib import Path
import shutil

dest = Path("bench")
if not dest.exists():
    shutil.copytree("../transaction-comparison/bench", dest)


def swap(file, old, new):
    p = dest / file
    s = p.read_text()
    if new in s:
        return
    assert s.count(old) == 1, (file, old)
    p.write_text(s.replace(old, new))


swap("topology.sh", "PG=oauthbench-pg", "PG=${BENCH_WINDOW_PG:-oauthbench-pg}")
swap(
    "comparison-point.sh",
    'snapshot >"$scratch/count-before"',
    '''snapshot >"$scratch/count-before"
lsn() { docker exec -u postgres "$PG" psql -XAt 'dbname=postgres replication=database' -c IDENTIFY_SYSTEM | cut -d'|' -f3; }
lsn >"$out.start-lsn"''',
)
swap(
    "comparison-point.sh",
    'snapshot >"$scratch/count-after"',
    '''lsn >"$out.end-lsn"
snapshot >"$scratch/count-after"''',
)
