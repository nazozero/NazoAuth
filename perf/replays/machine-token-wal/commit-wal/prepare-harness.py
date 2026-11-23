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
# Pin the observer too: it can still be visible to the database process sampler.
swap(
    "comparison-point.sh",
    'snapshot >"$scratch/count-before"',
    '''snapshot >"$scratch/count-before"
lsn() { docker exec -u postgres "$PG" /affinity "$PG_CPUS" psql -XAt 'dbname=postgres replication=database' -c IDENTIFY_SYSTEM | cut -d'|' -f3; }
lsn >"$out.start-lsn"''',
)
swap(
    "comparison-point.sh",
    'snapshot >"$scratch/count-after"',
    '''lsn >"$out.end-lsn"
snapshot >"$scratch/count-after"''',
)

swap("comparison-seal.py", "import json\n", "import json\nimport os\n")
swap(
    "comparison-seal.py",
    "        result.update(whole_success=whole_success",
    """        expect_audit = {"required": True, "off": False}[os.environ.get("BENCH_ISSUANCE_AUDIT", "required")]
        expected_rows = whole_success if expect_audit else 0
        result.update(expected_audit_rows=expected_rows, whole_success=whole_success""",
)
swap("comparison-seal.py", "audit_count_difference=signatures-whole_success", "audit_count_difference=signatures-expected_rows")
swap(
    "comparison-seal.py",
    "elif not whole_success or signatures != whole_success:",
    "elif not whole_success or signatures != expected_rows:",
)

swap("capacity/screen.py", "CONNECTIONS = 960", 'CONNECTIONS = int(os.environ.get("BENCH_WRK2_CONNECTIONS", "960"))')
