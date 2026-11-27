"""Sample service process trees together in KiB. Field order is app, then its dependencies."""
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

peer = sys.argv[1]
roles = ["oidc-bench-" + peer]
if peer != "kanidm":
    roles.append("oidc-bench-rauthy-db" if peer == "rauthy" else "oidc-bench-postgres")
if peer == "nazo":
    roles.append("oidc-bench-valkey")


def sample(container):
    output = subprocess.check_output([
        "docker", "exec", "--privileged", "-u", "0", container, "/affinity",
        os.environ["BENCH_CONTROL_CPU"], "/read-pss",
    ], stderr=subprocess.DEVNULL)
    pss, rss = map(int, output.split())
    return pss, rss


with ThreadPoolExecutor(max_workers=len(roles)) as pool:
    while True:
        begin = time.time_ns()
        try:
            values = list(pool.map(sample, roles))
        except (subprocess.CalledProcessError, ValueError):
            pass  # No partial batches (for example a process exited during collection).
        else:
            pss, rss = zip(*values)
            print(begin, time.time_ns(), *pss, *rss, sep="\t", flush=True)
        time.sleep(2)
