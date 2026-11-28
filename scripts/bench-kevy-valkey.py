#!/usr/bin/env python3
"""Measure one native state-backend window with the existing Goose arrival driver.

Start isolated NazoAuth and PostgreSQL processes (plus Valkey for that backend),
prepare private Goose fixtures through the application APIs, and supply their
root PIDs. Launch every service with taskset on the same CPU set; the driver and
this sampler use a separate set. Repeat both deployments in alternating order at each offered
rate, including the first failing rate, before comparing sustainable throughput.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "perf" / "monitor"))
from summarize import summarize  # noqa: E402

HZ = os.sysconf("SC_CLK_TCK")
NS = 1_000_000_000


def cpu_set(value):
    result = set()
    for part in value.split(","):
        ends = list(map(int, part.split("-")))
        if len(ends) == 1:
            result.add(ends[0])
        elif len(ends) == 2 and ends[0] <= ends[1]:
            result.update(range(ends[0], ends[1] + 1))
        else:
            raise argparse.ArgumentTypeError("expected CPU numbers or ranges")
    if not result or min(result) < 0:
        raise argparse.ArgumentTypeError("CPU set must be nonempty and nonnegative")
    return result


def process_snapshot():
    """Read PPIDs: some native sandboxes expose empty task/children files."""
    processes, children = {}, {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        pid = int(entry.name)
        children.setdefault(int(fields[1]), []).append(pid)
        # Include waited-for child time: reaped workers must not vanish from CPU totals.
        processes[pid] = (sum(map(int, fields[11:15])), int(fields[19]))
    return processes, children


def process_tree(root, snapshot):
    processes, children = snapshot
    pending, result = [root], {}
    while pending:
        pid = pending.pop()
        if pid in result or pid not in processes:
            continue
        try:
            tasks = list(Path(f"/proc/{pid}/task").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        result[pid] = (*processes[pid], tasks)
        pending.extend(children.get(pid, ()))
    return result


def memory(pid):
    fields = dict(line.split(":", 1) for line in
                  Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()[1:])
    return tuple(int(fields[key].split()[0]) for key in ("Pss", "Rss"))


def pressure():
    result = {f"{resource}_{kind}": None for resource in ("cpu", "memory", "io")
              for kind in ("some", "full")}
    for resource in ("cpu", "memory", "io"):
        try:
            lines = Path(f"/proc/pressure/{resource}").read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue  # Kernels without PSI must not report zero pressure.
        for line in lines:
            kind, *values = line.split()
            result[f"{resource}_{kind}"] = int(dict(v.split("=") for v in values)["total"])
    return result


def sample(components, masks, with_memory):
    result = {"time_ns": time.time_ns(), "components": {}, "pressure_us": pressure()}
    snapshot = process_snapshot()
    stat = Path("/proc/stat").read_text().splitlines()
    result["host_cpu_ticks"] = list(map(int, stat[0].split()[1:9]))
    result["loadavg"] = list(map(float, Path("/proc/loadavg").read_text().split()[:3]))
    result["host_tasks"] = {line.split()[0]: int(line.split()[1]) for line in stat
                            if line.startswith(("procs_running ", "procs_blocked "))}
    for role, root in components.items():
        tree = process_tree(root, snapshot)
        if root not in tree:
            continue
        row = {"root_start_ticks": tree[root][1],
               "cpu_ticks": sum(entry[0] for entry in tree.values()),
               "processes": len(tree), "affinity_mismatches": 0}
        for _, _, tasks in tree.values():
            for task in tasks:
                try:
                    row["affinity_mismatches"] += os.sched_getaffinity(int(task.name)) != masks[role]
                except ProcessLookupError:
                    pass
        if with_memory and role != "generator":
            try:
                points = [memory(pid) for pid in tree]
            except (FileNotFoundError, ProcessLookupError):
                pass  # Keep CPU; reject an incomplete memory batch.
            else:
                row["pss_kib"] = sum(point[0] for point in points)
                row["rss_kib"] = sum(point[1] for point in points)
        result["components"][role] = row
    result["sample_duration_ms"] = (time.time_ns() - result["time_ns"]) / 1_000_000
    return result


def resource_summary(samples, roles, start, end):
    seconds = (end - start) / NS
    resources = {}
    for role in roles:
        cpu, coverage = 0.0, 0.0
        for before, after in zip(samples, samples[1:]):
            span = min(after["time_ns"], end) - max(before["time_ns"], start)
            a, b = before["components"].get(role), after["components"].get(role)
            if span <= 0 or not a or not b or a["root_start_ticks"] != b["root_start_ticks"]:
                continue
            delta = b["cpu_ticks"] - a["cpu_ticks"]
            if delta < 0:
                continue
            cpu += delta / HZ * span / (after["time_ns"] - before["time_ns"])
            coverage += span / NS
        points = [row["components"][role] for row in samples
                  if start <= row["time_ns"] < end and role in row["components"]]
        memories = [row for row in points if "pss_kib" in row]
        resources[role] = {
            "cpu_seconds": cpu, "cpu_sample_seconds": coverage,
            "mean_cpu_cores": cpu / coverage if coverage else None,
            "peak_pss_mib": max((r["pss_kib"] for r in memories), default=0) / 1024 if memories else None,
            "peak_rss_sum_mib": max((r["rss_kib"] for r in memories), default=0) / 1024 if memories else None,
            "memory_samples": len(memories),
            "affinity_mismatches": sum(r["affinity_mismatches"] for r in points),
        }
    server_roles = set(roles) - {"generator"}
    total_memory = [sum(row["components"][role]["pss_kib"] for role in server_roles)
                    for row in samples if start <= row["time_ns"] < end
                    and all("pss_kib" in row["components"].get(role, {}) for role in server_roles)]
    total = {"cpu_seconds": sum(resources[r]["cpu_seconds"] for r in server_roles),
             "mean_cpu_cores": sum(resources[r]["cpu_seconds"] for r in server_roles) / seconds,
             "peak_pss_mib": max(total_memory) / 1024 if total_memory else None,
             "memory_samples": len(total_memory)}
    host_pressure = {}
    for key in samples[0]["pressure_us"]:
        used, coverage = 0.0, 0.0
        for before, after in zip(samples, samples[1:]):
            span = min(after["time_ns"], end) - max(before["time_ns"], start)
            if span > 0 and before["pressure_us"][key] is not None and after["pressure_us"][key] is not None:
                used += ((after["pressure_us"][key] - before["pressure_us"][key])
                         * span / (after["time_ns"] - before["time_ns"]))
                coverage += span / NS
        host_pressure[key] = used / coverage / 10_000 if coverage else None
    ticks = [0.0] * 8
    for before, after in zip(samples, samples[1:]):
        span = min(after["time_ns"], end) - max(before["time_ns"], start)
        if span > 0:
            for i, (a, b) in enumerate(zip(before["host_cpu_ticks"], after["host_cpu_ticks"])):
                ticks[i] += (b - a) * span / (after["time_ns"] - before["time_ns"])
    total_ticks = sum(ticks)
    points = [row for row in samples if start <= row["time_ns"] < end]
    host = {
        "cpu_execution_pct": 100 * sum(ticks[i] for i in (0, 1, 2, 5, 6)) / total_ticks if total_ticks else None,
        "cpu_steal_pct": 100 * ticks[7] / total_ticks if total_ticks else None,
        "cpu_iowait_pct": 100 * ticks[4] / total_ticks if total_ticks else None,
        "load_1m_range": [min(row["loadavg"][0] for row in points), max(row["loadavg"][0] for row in points)],
        "peak_runnable_tasks": max(row["host_tasks"]["procs_running"] for row in points),
        "peak_io_blocked_tasks": max(row["host_tasks"]["procs_blocked"] for row in points),
    }
    return resources, total, host_pressure, host


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(args):
    os.umask(0o077)
    available = os.sched_getaffinity(0)
    if not (args.server_cpus | args.driver_cpus) <= available:
        raise ValueError("requested CPUs are outside the current affinity mask")
    if args.server_cpus & args.driver_cpus:
        raise ValueError("service and generator CPUs must be disjoint")
    if (args.backend == "valkey") != (args.valkey_pid is not None):
        raise ValueError("the Valkey backend requires --valkey-pid; Kevy must omit it")
    if min(args.rate, args.seconds, args.warm_seconds, args.slots) <= 0:
        raise ValueError("rate, warm-up, duration and slots must be positive")
    if any(key in os.environ for key in ("BENCH_ARRIVAL_PHASES", "BENCH_GO_PROFILE")):
        raise ValueError("unset BENCH_ARRIVAL_PHASES and BENCH_GO_PROFILE for fixed-load comparison")
    components = {"app": args.app_pid, "postgres": args.postgres_pid}
    if args.valkey_pid:
        components["valkey"] = args.valkey_pid
    snapshot = process_snapshot()
    trees = {role: process_tree(pid, snapshot) for role, pid in components.items()}
    pids = [pid for tree in trees.values() for pid in tree]
    if len(pids) != len(set(pids)) or not all(pid in trees[role] for role, pid in components.items()):
        raise ValueError("component roots must identify distinct live process trees")
    for role, tree in trees.items():
        for _, _, tasks in tree.values():
            for task in tasks:
                if os.sched_getaffinity(int(task.name)) != args.server_cpus:
                    raise ValueError(f"launch the entire {role} process tree with taskset on --server-cpus")
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {
        "backend": args.backend, "platform": platform.platform(), "clock_ticks_per_second": HZ,
        "server_cpus": sorted(args.server_cpus), "generator_cpus": sorted(args.driver_cpus),
        "component_pids": components.copy(), "sampling_seconds": 0.25, "memory_sampling_seconds": 1,
        "driver_sha256": sha256(args.driver), "fixture_sha256": sha256(args.fixture),
        "application_sha256": sha256(f"/proc/{args.app_pid}/exe"),
    }
    proof = json.loads(args.fixture_proof.read_text()) if args.fixture_proof else None
    if proof:
        if (proof["fixture_sha256"] != metadata["fixture_sha256"]
                or proof["fixtures"] != args.rate * (args.warm_seconds + args.seconds)
                or any(proof[name] != getattr(args, name) for name in ("rate", "warm_seconds", "seconds"))):
            raise ValueError("fixture proof does not match this measured window")
        if time.time() > proof["latest_safe_start_epoch"]:
            raise ValueError("the assertion fixture cannot remain valid for this window")
        metadata["fixture_proof"] = proof
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    stop, samples, errors = threading.Event(), [], []
    process = None
    try:
        os.sched_setaffinity(0, args.driver_cpus)
        with (args.output / "driver.stdout").open("w") as stdout, (args.output / "driver.stderr").open("w") as stderr:
            process = subprocess.Popen([
                str(args.driver), str(args.rate), str(args.warm_seconds), str(args.seconds),
                str(args.slots), str(args.fixture), str(args.output / "arrivals.tsv"),
            ], stdout=stdout, stderr=stderr,
                env={**os.environ, "TOKIO_WORKER_THREADS": str(len(args.driver_cpus))})
            components["generator"] = process.pid
            masks = {role: args.server_cpus for role in components}
            masks["generator"] = args.driver_cpus

            def monitor():
                try:
                    with (args.output / "resources.jsonl").open("w") as out:
                        n = 0
                        due = time.monotonic()
                        while True:
                            row = sample(components, masks, n % 4 == 0)
                            samples.append(row)
                            out.write(json.dumps(row) + "\n")
                            out.flush()
                            n += 1
                            due += 0.25
                            if stop.wait(max(0, due - time.monotonic())):
                                samples.append(sample(components, masks, True))
                                out.write(json.dumps(samples[-1]) + "\n")
                                break
                except Exception as error:
                    errors.append(error)

            sampler = threading.Thread(target=monitor)
            sampler.start()
            try:
                returncode = process.wait(timeout=args.warm_seconds + args.seconds + 120)
            finally:
                stop.set()
                sampler.join()
        if errors:
            raise errors[0]
        if returncode:
            raise RuntimeError(f"Goose exited {returncode}; inspect driver.stderr")
        epoch = re.search(r"^epoch_ns=(\d+)", (args.output / "driver.stderr").read_text(), re.MULTILINE)
        if epoch is None:
            raise RuntimeError("Goose did not publish a measurement epoch")
        start = int(epoch[1]) + args.warm_seconds * NS
        end = start + args.seconds * NS
        result = summarize(args.output / "arrivals.tsv", args.rate, args.warm_seconds, args.seconds)
        resources, total, psi, host = resource_summary(samples, components, start, end)
        invalid = [role + "_sampling" for role, row in resources.items()
                   if row["cpu_sample_seconds"] < .95 * args.seconds
                   or (role != "generator" and not row["memory_samples"])
                   or row["affinity_mismatches"]]
        if proof and int(epoch[1]) / NS > proof["latest_safe_start_epoch"]:
            invalid.append("fixture_expiry_budget")
        if any(role not in sample["components"]
               or sample["components"][role]["root_start_ticks"] != trees[role][pid][1]
               for sample in samples if start <= sample["time_ns"] < end
               for role, pid in components.items() if role != "generator"):
            invalid.append("service_lifecycle")
        row = result["operations"]["all"]
        if row["outcomes"].get("scheduler_late", 0) > .001 * row["planned"]:
            invalid.append("generator_scheduling")
        if row["outcomes"].get("transport_addr_unavailable", 0):
            invalid.append("generator_source_ports")
        if (resources["generator"]["mean_cpu_cores"] or 0) >= .8 * len(args.driver_cpus):
            invalid.append("generator_cpu")
        result.update(backend=args.backend, resources=resources, total_server=total,
                      host_pressure_pct=psi, host=host, invalid_reasons=invalid,
                      measurement_valid=not invalid)
        (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 1 if invalid else 0
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        os.sched_setaffinity(0, available)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("kevy", "valkey"), required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-proof", type=Path, help="proof JSON emitted by client_assertions.py")
    parser.add_argument("--app-pid", type=int, required=True)
    parser.add_argument("--postgres-pid", type=int, required=True)
    parser.add_argument("--valkey-pid", type=int)
    parser.add_argument("--server-cpus", type=cpu_set, required=True)
    parser.add_argument("--driver-cpus", type=cpu_set, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--warm-seconds", type=int, default=10)
    parser.add_argument("--seconds", type=int, default=36)
    parser.add_argument("--slots", type=int, default=8192)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.driver, args.fixture, args.output = (p.resolve() for p in (args.driver, args.fixture, args.output))
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
