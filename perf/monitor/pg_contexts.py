"""Sample PostgreSQL allocator contexts of idle application backends after a benchmark."""
import json
import re
import subprocess
import sys
import time

container, database, user = sys.argv[1:]
if not re.fullmatch(r"[a-z_]+", database):
    raise ValueError("invalid database name")


def docker(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.STDOUT, text=True)


start = str(int(time.time()))
sql = (f"SELECT pid FROM pg_stat_activity WHERE datname='{database}' AND pid<>pg_backend_pid() "
       "AND backend_type='client backend' AND state='idle' AND pg_log_backend_memory_contexts(pid)")
pids = {int(pid) for pid in docker("exec", container, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1",
                                    "-U", user, "-d", database, "-c", sql).splitlines()}
if not pids:
    raise RuntimeError("no idle application backends")
# Identifiers after a context name may include SQL or user data. Export only byte counts.
context = re.compile(r"\[(\d+)\].*?(?:level: \d+; ([^:;]+):|Grand total:) (\d+) bytes? in .*?; (\d+) free .*?; (\d+) used")
pg18 = re.compile(r"\[(\d+)\].*?(?:level: \d+; ([^:;]+):|Grand total:) (\d+) total in .*?; (\d+) free .*?; (\d+) used")
for _ in range(10):
    rows = {}
    for line in docker("logs", "--since", start, container).splitlines():
        match = context.search(line) or pg18.search(line)
        if not match or int(match[1]) not in pids:
            continue
        pid = int(match[1])
        stats = rows.setdefault(pid, {"contexts": {}})
        values = list(map(int, match.group(3, 4, 5)))
        if match[2] is None:
            stats["total"] = values
        else:
            name = match[2].strip()
            if name not in {"CachedPlan","CachedPlanSource","CacheMemoryContext","TopMemoryContext",
                            "PLpgSQL function","ExecutorState","SPI Plan","Prepared Queries"}:
                name = "other"
            counts = stats["contexts"].setdefault(name, [0, 0, 0])
            for index, value in enumerate(values):
                counts[index] += value
    if set(rows) == pids and all("total" in r for r in rows.values()):
        print(json.dumps({"columns": ["allocated_bytes", "free_bytes", "used_bytes"], "backends": rows}))
        break
    time.sleep(0.5)
else:
    raise RuntimeError(f"missing allocator totals for {len(pids) - sum('total' in r for r in rows.values())} backends")
