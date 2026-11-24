"""Repeat Keycloak issuance with idle-host controls around the stock k6 point."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

def cpu_ids(mask):
    cpus = set()
    for field in mask.split(","):
        ends = field.split("-")
        cpus.update(range(int(ends[0]), int(ends[-1]) + 1))
    return cpus


CPUS = cpu_ids(os.environ["BENCH_APP_CPUS"])
CONTROL = int(os.environ["BENCH_CONTROL_CPU"])
PSI_LIMIT = 0.43  # Upper end of the three original NazoAuth 12k windows.
PERIOD = 15
MAX_IDLE_WINDOWS = 10

def counters():
    psi = Path("/proc/pressure/cpu").read_text().splitlines()[0]
    sched = Path("/proc/schedstat").read_text().splitlines()
    assert sched[0] == "version 15"
    run = {}
    for line in sched:
        fields = line.split()
        if fields[0].startswith("cpu") and fields[0][3:].isdigit():
            cpu = int(fields[0][3:])
            if cpu in CPUS:
                run[cpu] = int(fields[7])
    assert run.keys() == CPUS
    return (time.time_ns(), int(psi.split("total=")[1]), sum(run.values()))

def interval(first, last):
    dt, psi, running = [end - begin for begin, end in zip(first, last)]
    assert dt > 0 and min(psi, running) >= 0
    return dict(seconds=dt / 1e9, psi_pct=100_000 * psi / dt,
                assigned_busy_cores=running / dt)

def idle():
    first = counters()
    time.sleep(PERIOD)
    return interval(first, counters())

def main():
    run_id = sys.argv[1]
    assert run_id.isdecimal() and len(CPUS) == 16
    dest = Path("results") / ("keycloak-pressure-" + run_id)
    assert (dest / "start.json").is_file()
    original = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {CONTROL})
    for n in range(1, 4):
        label = f"K-12000-{run_id}{n}"
        output = Path("results") / (label + ".json")
        assert not output.exists() and not (dest / f"round-{n}.json").exists()
        baselines = []
        for _ in range(MAX_IDLE_WINDOWS):
            pre = idle()
            baselines.append(pre)
            quiet = pre["psi_pct"] <= PSI_LIMIT and pre["assigned_busy_cores"] <= 1
            if quiet:
                break
        print(f"round {n} idle qualified={quiet} PSI={pre['psi_pct']:.2f}%", flush=True)
        samples = [counters()]
        # Keep the original driver's CPU mask. Only this extra observer is pinned.
        with subprocess.Popen(["bash", "policy-peers.sh", "machine", label],
                              preexec_fn=lambda: os.sched_setaffinity(0, original)) as proc:
            while proc.poll() is None:
                time.sleep(1)
                samples.append(counters())
            if proc.returncode:
                raise subprocess.CalledProcessError(proc.returncode, proc.args)
        point = json.loads(output.read_text())
        workload = point["workload"]
        assert workload == {"rate": 12000, "warm": 10, "seconds": 36}
        start_ns = (point["scenario_started_unix_ms"] + 10000) * 1000000
        inside = [s for s in samples if start_ns <= s[0] < start_ns + 36_000_000_000]
        assert len(inside) >= 30
        measured = interval(inside[0], inside[-1])
        after = idle()
        record = dict(round=n, idle_qualified=quiet, idle_attempts=baselines,
                      measured=measured, after=after, window=point)
        (dest / f"round-{n}.json").write_text(json.dumps(record, indent=2) + "\n")
        print(f"round {n} completed", flush=True)

if __name__ == "__main__":
    main()
