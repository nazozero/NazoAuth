#!/usr/bin/env python3
# Recount Argon2 cold-login ladder strictly from step=login metrics.
# attempted login/s = login step http_reqs/s; successful = attempted*(1-err);
# reject rate = login step error_rate; http_req/s reported separately.
import json, glob, os, sys

rows = []
for d in sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else "/workspace/perf-results/ladder/oidc_cold_login_refresh-c*")):
    conc = d.rsplit("-c", 1)[-1]
    files = glob.glob(os.path.join(d, "*.summary.json"))
    if not files:
        rows.append((conc, "NO_SUMMARY"))
        continue
    s = json.load(open(files[0]))
    steps = {st["step"]: st for st in s.get("steps", [])}
    lg = steps.get("login")
    if not lg:
        rows.append((conc, "NO_LOGIN_STEP"))
        continue
    attempted = lg["rps"]
    err = lg["error_rate"]
    succ = attempted * (1 - err)
    total_rps = s["k6"]["rps"]
    measure_ops = s["k6"].get("measure", {}).get("ops_per_s", 0)
    rows.append((conc, {
        "attempted_login_s": round(attempted, 2),
        "successful_login_s": round(succ, 2),
        "reject_rate": round(err, 4),
        "flow_ops_s": round(measure_ops, 2),
        "http_req_s": round(total_rps, 2),
        "login_p50_ms": lg["latency_ms"]["p50"],
        "login_p95_ms": lg["latency_ms"]["p95"],
        "login_p99_ms": lg["latency_ms"]["p99"],
        "status": s.get("status"),
    }))

for c, v in rows:
    print(c, json.dumps(v) if isinstance(v, dict) else v)
