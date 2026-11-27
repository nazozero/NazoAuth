"""Sample PostgreSQL smaps by PID on the monitoring CPU. Output is JSONL."""
import json
import os
import subprocess
import sys
import time

while True:
    start = time.time_ns()
    probe = subprocess.run(["docker", "exec", "--privileged", "-u", "0", sys.argv[1],
                            "/affinity", os.environ["BENCH_CONTROL_CPU"], "/tmp/pg-maps/read-pss"],
                           capture_output=True, text=True)
    end = time.time_ns()
    complete = False
    if probe.returncode == 0:
        lines = probe.stdout.splitlines()
        device, inode, size = lines[0].split()
        pids = [list(map(int, line.split())) for line in lines[1:]]
        complete = any(p[0] == 1 for p in pids)
        if complete:
            print(json.dumps(dict(begin_ns=start, end_ns=end, device=device, inode=int(inode),
                                  size_kib=int(size), pids=pids), separators=(",", ":")), flush=True)
    if "--once" in sys.argv[2:]:
        sys.exit(0 if complete else 1)
    time.sleep(2)
