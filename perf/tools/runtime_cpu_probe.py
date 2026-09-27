#!/usr/bin/env python3
"""Probe this process's schedulable CPUs; metadata is advisory in nested CNB.

Only the probe process is pinned, and its original affinity is restored.
Does not read hidden ancestors, change cgroups, or infer guaranteed capacity.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
from pathlib import Path


def read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def cpu_list(text: str | None) -> set[int]:
    result: set[int] = set()
    for item in (text or "").split(","):
        if not item:
            continue
        ends = item.split("-")
        lo, hi = int(ends[0]), int(ends[-1])
        result.update(range(lo, hi + 1))
    return result


def probe() -> dict:
    original = os.sched_getaffinity(0)
    getcpu = getattr(ctypes.CDLL(None), "sched_getcpu", None)
    if getcpu is not None:
        getcpu.restype = ctypes.c_int
    accepted, rejected, topology = [], {}, {}
    try:
        for cpu in sorted(original):
            try:
                os.sched_setaffinity(0, {cpu})
                observed = getcpu() if getcpu is not None else None
                if os.sched_getaffinity(0) != {cpu} or (
                    observed is not None and observed != cpu
                ):
                    raise RuntimeError(f"binding mismatch: observed={observed}")
                accepted.append(cpu)
            except (OSError, RuntimeError) as error:
                rejected[str(cpu)] = str(error)
    finally:
        os.sched_setaffinity(0, original)
    for cpu in accepted:
        base = f"/sys/devices/system/cpu/cpu{cpu}/topology"
        try:
            pair = [int(read(f"{base}/{name}") or "-1")
                    for name in ("physical_package_id", "core_id")]
            topology[str(cpu)] = pair if min(pair) >= 0 else None
        except ValueError:
            topology[str(cpu)] = None
    quotas = []
    try:
        quota, period = (read("/sys/fs/cgroup/cpu.max") or "").split()
        if quota != "max" and int(period) > 0 and int(quota) > 0:
            quotas.append(int(quota) / int(period))
    except ValueError:
        pass
    for base in ("/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpu,cpuacct"):
        try:
            quota = int(read(f"{base}/cpu.cfs_quota_us") or "-1")
            period = int(read(f"{base}/cpu.cfs_period_us") or "0")
            if quota > 0 and period > 0:
                quotas.append(quota / period)
        except ValueError:
            pass
    return {"affinity": sorted(original), "runnable": accepted,
            "rejected": rejected, "binding_method": "setaffinity+getaffinity"
            + ("+getcpu" if getcpu is not None else ""),
            "online_reported": read("/sys/devices/system/cpu/online"),
            "topology": topology, "visible_quota_cores": min(quotas) if quotas else None,
            "effective_parent_capacity": "UNKNOWN"}


def make_plan(host: dict, runner: dict) -> dict:
    # The load container's tested CPUs own the plan. The SSH process can
    # have a narrower mask; application/PG containers are checked at startup.
    usable = sorted(set(runner["runnable"]))
    if not usable:
        raise ValueError("NO_TESTED_PINNABLE_CPU: use documented unpinned fallback")
    hints = [float(record["visible_quota_cores"]) for record in (host, runner)
             if record.get("visible_quota_cores") is not None
             and math.isfinite(float(record["visible_quota_cores"]))
             and float(record["visible_quota_cores"]) > 0]
    ceiling = min([len(usable), *hints])
    topology_ok = True
    for record in (host, runner):
        try:
            online = cpu_list(record.get("online_reported"))
        except ValueError:
            online = set()
        topology_ok &= set(usable).issubset(online)
    topology_ok &= all(
        runner.get("topology", {}).get(str(cpu)) is not None
        and runner["topology"][str(cpu)] == host.get("topology", {}).get(str(cpu))
        for cpu in usable)
    groups: dict[tuple, list[int]] = {}
    for cpu in usable:
        key = tuple(runner["topology"][str(cpu)]) if topology_ok else (cpu,)
        groups.setdefault(key, []).append(cpu)
    ordered = sorted(groups.values(), key=min)
    n = max(1, min(len(ordered) // 2, math.floor(ceiling / 2)))
    app = [min(group) for group in ordered[:n]]
    infra = [cpu for group in ordered[n:] for cpu in group]
    shared = not infra
    if shared:
        infra = usable[:]
    return {"allowed": usable, "multi": app, "single": app[:1], "infra": infra,
            "cpu_budget": ceiling, "cpu_budget_basis": "VISIBLE_PLANNING_CEILING_ONLY",
            "physical_cores": ordered if topology_ok else None,
            "topology_status": "CONSISTENT_VISIBLE_METADATA" if topology_ok else "UNVERIFIED",
            "isolation": "SHARED_INFRA" if shared else
                         ("VISIBLE_SMT_GROUPS_SEPARATED" if topology_ok else "LOGICAL_CPU_SETS_SEPARATED"),
            "effective_parent_capacity": "UNKNOWN"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("probe", "plan"))
    parser.add_argument("--host", type=Path)
    parser.add_argument("--runner", type=Path)
    args = parser.parse_args()
    if args.mode == "probe":
        result = probe()
    else:
        if args.host is None or args.runner is None:
            parser.error("plan requires --host and --runner")
        result = make_plan(json.loads(args.host.read_text()), json.loads(args.runner.read_text()))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
