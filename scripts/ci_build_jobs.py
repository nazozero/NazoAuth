"""Set Cargo concurrency from the Linux runner's CPU and memory budget."""

import os
from pathlib import Path

cpus = len(os.sched_getaffinity(0))
memory = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))) * 1024
limit = Path("/sys/fs/cgroup/memory.max")
if limit.exists() and limit.read_text().strip() != "max":
    memory = min(memory, int(limit.read_text()))
jobs = max(1, min(cpus, memory // (3 * 1024**3)))
print(f"CARGO_BUILD_JOBS={jobs}")
