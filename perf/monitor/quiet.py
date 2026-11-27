"""Record idle host pressure and CPU use on the assigned physical cores."""
import json
import os
import time
from pathlib import Path


def read(cpus):
    busy = {}
    for line in Path("/proc/stat").read_text().splitlines():
        name, *ticks = line.split()
        if name.startswith("cpu") and name[3:].isdigit():
            busy[int(name[3:])] = sum(int(ticks[i]) for i in (0, 1, 2, 5, 6, 7))
    # Some CNB containers renumber /proc/stat CPUs but keep kernel affinity IDs.
    if not cpus.issubset(busy):
        lines = Path("/proc/schedstat").read_text().splitlines()
        if "version 15" not in lines:
            raise RuntimeError("No host CPU accounting for the assigned affinity")
        busy = {int(f[0][3:]): int(f[7]) / 1e9
                for line in lines if (f := line.split()) and f[0].startswith("cpu") and f[0][3:].isdigit()}
    else:
        hz = os.sysconf("SC_CLK_TCK")
        busy = {cpu: ticks / hz for cpu, ticks in busy.items()}
    pressure = Path("/proc/pressure/cpu").read_text().splitlines()[0]
    return time.monotonic(), busy, int(pressure.rsplit("total=", 1)[1])


def snapshot():
    cpus = set()
    for role in ("APP_CPUS","PG_CPUS","VK_CPUS","GEN_CPUS"):
        for cpu in os.environ["BENCH_"+role].split(","):
            siblings = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
            for span in siblings.read_text().strip().split(","):
                first, _, last = span.partition("-")
                cpus.update(range(int(first), int(last or first)+1))
    start, a, p = read(cpus)
    time.sleep(5)
    end, b, q = read(cpus)
    duration = end-start
    return {"psi_pct": (q-p)/duration/10000,
            "busy_cores": sum(b[i]-a[i] for i in cpus) / duration}


if __name__ == "__main__":
    first = snapshot()
    samples = [first]
    if first["psi_pct"] > 2:
        samples.append(snapshot())
    print(json.dumps({"samples":samples,"quiet": all(v["busy_cores"] <= .5 for v in samples)
                     and (first["psi_pct"] <= 2 or max(v["psi_pct"] for v in samples) < 20)}))
