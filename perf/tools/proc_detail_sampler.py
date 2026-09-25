#!/usr/bin/env python3
"""Per-thread / per-process CPU+RSS sampler for the bounded SIS probe.

Docker stats is unreliable on this nested cgroup-v1 host, so instead each
target container is sampled via `docker exec <c> sh -c '<procfs loop>'`:
the loop reads /proc/*/stat (per-process jiffies + rss) and
/proc/1/task/*/stat (per-thread jiffies of the container's init process,
which is the app process for nazoauth and the postmaster for postgres).

Output: one JSON row per tick to OUT_PATH (jsonl).
Env: RUN_ID, OUT_PATH, TICK_S, PROJECT (compose project name).
"""

import json
import os
import re
import subprocess
import sys
import time

RUN_ID = os.environ.get("RUN_ID", "unset")
OUT = os.environ.get("OUT_PATH", "/out/proc-detail.jsonl")
TICK = float(os.environ.get("TICK_S", "5"))
PROJECT = os.environ.get("PROJECT", "nazoauth-perf")
CLK = os.sysconf("SC_CLK_TCK")


def self_sha256() -> str:
    try:
        import hashlib
        with open(__file__, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "unknown"

# Per-process rows: pid, comm, utime+stime jiffies, rss pages.
# Per-thread rows for PID 1: tid, comm, jiffies.
SNIPPET = (
    "for f in /proc/[0-9]*/stat; do "
    "read -r l < $f 2>/dev/null || continue; "
    "rest=${l##*) }; set -- $rest; "
    "echo \"P ${l%% *} ${l#*(} $0 $1 $(( ${12:-0} + ${13:-0} )) ${22:-0}\"; "
    "done; "
    "for f in /proc/1/task/[0-9]*/stat; do "
    "read -r l < $f 2>/dev/null || continue; "
    "rest=${l##*) }; set -- $rest; "
    "tid=$(basename $(dirname $f)); "
    "echo \"T $tid ${l#*(} $(( ${12:-0} + ${13:-0} ))\"; "
    "done; "
    "cat /sys/fs/cgroup/cpu/cpu.stat 2>/dev/null | sed 's/^/C /'; "
    "cat /sys/fs/cgroup/cpu.stat 2>/dev/null | sed 's/^/C2 /'; "
    # cgroup memory usage (physical, incl. shared pages once): v1
    # memory.usage_in_bytes, v2 memory.current. Unlike summed backend
    # RSS this does not double-count shared buffers/libraries.
    "cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null "
    "| sed 's/^/M /'; "
    "cat /sys/fs/cgroup/memory.current 2>/dev/null | sed 's/^/M2 /'"
)

CONTAINERS = {
    "app": f"{PROJECT}-nazoauth-1",
    "postgres": f"{PROJECT}-postgres-1",
    "valkey": f"{PROJECT}-valkey-1",
}


def sample(name: str) -> dict | None:
    proc = subprocess.run(
        ["docker", "exec", name, "sh", "-c", SNIPPET],
        text=True, capture_output=True, timeout=30)
    if proc.returncode != 0:
        return None
    procs, threads, cgroup = [], [], {}
    mem_bytes = None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "P" and len(parts) >= 5:
            # pid comm(ut+st rss — comm may contain ')' so re-parse loosely
            try:
                procs.append({"pid": int(parts[1]),
                              "comm": parts[2].rstrip(")"),
                              "jif": int(parts[-2]), "rss_p": int(parts[-1])})
            except (ValueError, IndexError):
                continue
        elif parts[0] == "T" and len(parts) >= 3:
            try:
                threads.append({"tid": int(parts[1]),
                                "jif": int(parts[-1])})
            except (ValueError, IndexError):
                continue
        elif parts[0] in ("C", "C2") and len(parts) == 3:
            cgroup.setdefault(parts[0], {})[parts[1]] = int(parts[2])
        elif parts[0] in ("M", "M2") and len(parts) == 2:
            try:
                mem_bytes = int(parts[1])
            except ValueError:
                pass
    total_jif = sum(p["jif"] for p in procs)
    total_rss_kb = sum(p["rss_p"] for p in procs) * 4  # 4KiB pages
    top = sorted(procs, key=lambda p: -p["jif"])[:8]
    return {"total_jif": total_jif, "rss_kb": total_rss_kb,
            "n_proc": len(procs), "top_procs": top, "pid1_threads": threads,
            "cgroup": cgroup, "cgroup_mem_bytes": mem_bytes}


def container_name(base: str) -> str | None:
    proc = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True, capture_output=True, timeout=15)
    names = proc.stdout.split()
    if base in names:
        return base
    for n in names:
        if re.fullmatch(re.escape(base.rstrip("1")) + r"\d+", n):
            return n
    return None


def main() -> int:
    targets = {k: container_name(v) for k, v in CONTAINERS.items()}
    # load containers (k6 runners) join dynamically by prefix
    out = open(OUT, "a", buffering=1)
    out.write(json.dumps({"kind": "meta", "run_id": RUN_ID,
                          "script_sha256": self_sha256(),
                          "clk_tck": CLK, "targets": targets}) + "\n")
    while True:
        row = {"ts": time.time()}
        names = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            text=True, capture_output=True, timeout=15).stdout.split()
        dynamic = dict(targets)
        for n in names:
            if n.startswith(("sis-load-", "sis-side-", "sis-worker-",
                             "sis-rcv-")):
                dynamic[n] = n
        for key, cname in dynamic.items():
            if not cname:
                row[key] = None
                continue
            row[key] = sample(cname)
        try:
            mem = {}
            for line in open("/proc/meminfo"):
                k, _, rest = line.partition(":")
                p = rest.strip().split()
                if p and p[0].isdigit():
                    mem[k] = int(p[0])
            row["host_mem_kb"] = {
                "MemTotal": mem.get("MemTotal"),
                "MemAvailable": mem.get("MemAvailable")}
        except OSError:
            pass
        out.write(json.dumps(row) + "\n")
        time.sleep(TICK)


if __name__ == "__main__":
    sys.exit(main())
