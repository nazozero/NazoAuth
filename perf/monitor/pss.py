"""Sample NazoAuth and its two dependencies together in KiB. Stop with SIGTERM."""
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

# Sum only the service processes, excluding the sampler itself.
READ = """
set -eu
name=$1
set --
for proc in /proc/[0-9]*; do
    read -r comm < "$proc/comm" 2>/dev/null || continue
    case "$comm" in "$name") set -- "$@" "$proc/smaps_rollup";; esac
done
test "$#" -gt 0
awk '/^Pss:/ {sum += $2} END {print sum}' "$@"
"""


def sample(role):
    container, process = role
    output = subprocess.check_output([
        "docker", "exec", "--privileged", "-u", "0", container, "/affinity",
        os.environ["BENCH_CONTROL_CPU"], "sh", "-c", READ, "sh", process,
    ], stderr=subprocess.DEVNULL)
    value = int(output)
    if value <= 0:
        raise ValueError("missing PSS")
    return value


roles = [("oidc-bench-nazo", "nazoauth"), ("oidc-bench-postgres", "postgres"),
         ("oidc-bench-valkey", "valkey-server")]
with ThreadPoolExecutor(max_workers=3) as pool:
    while True:
        start = time.time_ns()
        try:
            values = list(pool.map(sample, roles))
        except (subprocess.CalledProcessError, ValueError):
            pass  # A restarting service has no complete sample.
        else:
            print(start, time.time_ns(), *values, sep="\t", flush=True)
        time.sleep(2)
