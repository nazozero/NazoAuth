#!/usr/bin/env python3
"""Probe this runtime process's schedulable logical CPUs.

Only the probe process is pinned, and its original affinity is restored.
Does not inspect host topology, global memory, or cgroup ancestors.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
from pathlib import Path


def probe() -> dict:
    original = os.sched_getaffinity(0)
    getcpu = getattr(ctypes.CDLL(None), "sched_getcpu", None)
    if getcpu is not None:
        getcpu.restype = ctypes.c_int
    accepted, rejected = [], {}
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
    return {"scope": "runtime_process", "affinity": sorted(original), "runnable": accepted,
            "rejected": rejected, "binding_method": "setaffinity+getaffinity"
            + ("+getcpu" if getcpu is not None else "")}


def make_plan(runner: dict, cpu_budget: float | None = None) -> dict:
    # Runtime-local eligibility is a planning seed, not a physical capacity
    # guarantee. Check application/PG/runner affinity in their own processes.
    usable = sorted(set(runner["runnable"]))
    if not usable:
        raise ValueError("NO_TESTED_PINNABLE_CPU: use documented unpinned fallback")
    if cpu_budget is not None and (not math.isfinite(cpu_budget) or cpu_budget <= 0):
        raise ValueError("runtime CPU budget must be positive and finite")
    ceiling = min(len(usable), cpu_budget) if cpu_budget is not None else len(usable)
    n = max(1, min(len(usable) // 2, math.floor(ceiling / 2)))
    app, infra = usable[:n], usable[n:]
    shared = not infra
    if shared:
        infra = usable[:]
    return {"allowed": usable, "multi": app, "single": app[:1], "infra": infra,
            "scope": "runtime_process", "cpu_budget": ceiling,
            "cpu_budget_basis": "RUNTIME_PLANNING_HINT" if cpu_budget is not None else "PROCESS_AFFINITY_SEED",
            "physical_cores": None, "topology_status": "OUT_OF_SCOPE",
            "isolation": "SHARED_INFRA" if shared else "LOGICAL_CPU_SETS_SEPARATED"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("probe", "plan"))
    # Existing prepared task commands may still pass this flag. Accept it
    # without opening the file; running experiments need not be restarted.
    parser.add_argument("--host", help=argparse.SUPPRESS)
    parser.add_argument("--runner", type=Path)
    parser.add_argument("--cpu-budget", type=float,
                        help="optional already-known CPU quota for this runtime only")
    args = parser.parse_args()
    if args.mode == "probe":
        result = probe()
    else:
        if args.runner is None:
            parser.error("plan requires --runner")
        result = make_plan(json.loads(args.runner.read_text()), args.cpu_budget)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
