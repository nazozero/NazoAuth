"""Choose disjoint physical cores from the current Linux CPU affinity."""
import os
from collections import defaultdict
from pathlib import Path

nodes = defaultdict(lambda: defaultdict(list))
for cpu in sorted(os.sched_getaffinity(0)):
    root = Path(f"/sys/devices/system/cpu/cpu{cpu}")
    node = next(root.glob("node[0-9]*"), root)
    key = tuple((root / "topology" / f).read_text().strip() for f in ("physical_package_id", "core_id"))
    nodes[node.name][key].append(cpu)
for cores in nodes.values():
    paired = sorted((v for v in cores.values() if len(v) >= 2), key=min)
    if len(paired) < 16 or len(cores) < 25:
        continue
    # Keep both SMT threads for dependencies and generator, one for each application core.
    used = paired[:16]
    remaining = sorted((v for v in cores.values() if v not in used), key=min)
    roles = {"PG_CPUS": [c for pair in used[:7] for c in pair[:2]], "VK_CPUS": used[7][:2],
             "GEN_CPUS": [c for pair in used[8:16] for c in pair[:2]][:15], "APP_CPUS": [v[0] for v in remaining[:8]],
             "CONTROL_CPU": remaining[8][:1]}
    for name, values in roles.items():
        print(f"export BENCH_{name}=" + ",".join(map(str, values)))
    break
else:
    raise SystemExit("Requires 25 disjoint physical cores on one NUMA node, including 16 SMT pairs.")
