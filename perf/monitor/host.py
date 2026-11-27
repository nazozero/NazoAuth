"""Sample Linux resource pressure and CPU accounting on the formal window clock."""
import json
import os
import time
from pathlib import Path

due = time.monotonic()
deadline = due + 3 * 3600
allowed = os.sched_getaffinity(0)
assert len(allowed) == 1, allowed
paths = {name:Path(path) for name,path in {
    'cpu_stat':'/proc/stat',
    'sched':'/proc/schedstat',
    'load':'/proc/loadavg',
    'pressure_cpu':'/proc/pressure/cpu',
    'pressure_io':'/proc/pressure/io',
    'pressure_memory':'/proc/pressure/memory',
    'cgroup_usage_percpu':'/sys/fs/cgroup/cpuacct/cpuacct.usage_percpu',
    'cgroup_stats':'/sys/fs/cgroup/cpu/cpu.stat',
}.items()}
while time.monotonic() < deadline:
    now = time.time_ns() // 10**6
    snapshot = {}
    for name, path in paths.items():
        try:
            snapshot[name] = path.read_text().splitlines()
        except OSError:
            snapshot[name] = []
    snapshot['cpu_stat'] = [line for line in snapshot['cpu_stat'] if line.startswith('cpu')]
    snapshot['sched'] = [line for line in snapshot['sched'] if line.startswith(('cpu','version'))]
    print(json.dumps(dict(t=now, **snapshot), separators=(',',':')),flush=True)
    due += 2
    time.sleep(max(0,due-time.monotonic()))
