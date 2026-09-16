#!/usr/bin/env python3
"""Print measured-window stats for one capacity point.

Usage: cap_point.py <point_dir> <scenario>
Prints: "<ops_per_s> <errors> <p99_ms> <app_cpu_pct>" or nothing on failure.
"""
import json
import sys
from pathlib import Path

point_dir = Path(sys.argv[1])
scenario = sys.argv[2].replace("_", "-")
summary = point_dir / f"capacity-{scenario}.summary.json"
if not summary.exists():
    sys.exit(2)
d = json.loads(summary.read_text(encoding="utf-8"))
result = d.get("result", d)
m = result.get("k6", {}).get("measure", {})
cpu = (
    result.get("containers", {})
    .get("by_service", {})
    .get("nazoauth", {})
    .get("cpu_percent_avg", 0)
)
lat = m.get("latency_ms", {})
print(
    m.get("ops_per_s", 0),
    m.get("errors", 0),
    lat.get("p99", 0),
    cpu,
)
