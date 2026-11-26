"""Record idle host pressure and CPU use on the assigned physical cores."""
import json
import os
import time
from pathlib import Path


def read():
    busy = {}
    for line in Path("/proc/stat").read_text().splitlines():
        name, *ticks = line.split()
        if name.startswith("cpu") and name[3:].isdigit():
            busy[int(name[3:])] = sum(int(ticks[i]) for i in (0, 1, 2, 5, 6, 7))
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
    start, a, p = read()
    time.sleep(5)
    end, b, q = read()
    duration = end-start
    return {"psi_pct": (q-p)/duration/10000,
            "busy_cores": sum(b[i]-a[i] for i in cpus) / os.sysconf("SC_CLK_TCK") / duration}


if __name__ == "__main__":
    first = snapshot()
    samples = [first]
    if first["psi_pct"] > 2:
        samples.append(snapshot())
    print(json.dumps({"samples":samples,"quiet": all(v["busy_cores"] <= .5 for v in samples)
                     and (first["psi_pct"] <= 2 or max(v["psi_pct"] for v in samples) < 20)}))
