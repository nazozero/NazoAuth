#!/usr/bin/env python3
"""Short current-B search using the existing point lifecycle and capacity gate."""
from __future__ import annotations

import argparse
import json
import math
import os
import time
from datetime import datetime
from pathlib import Path

import capacity_search as gate
import point_runner as points
import single_instance_scaling as sis

SCENARIOS = {
    "cap_mixed": 100,
    "cap_client_credentials": 250,
    "cap_authorization_code": 80,
    "cap_refresh_token": 100,
    "fapi2_logged_in_high_security": 20,
    "cap_introspect": 500,
    "cap_revoke": 60,
    "mtls_client_credentials": 250,
    "par_signed_request_object": 300,
    "oidc_cold_login_refresh": 1,
}
PRIMARY = tuple(SCENARIOS)[:4]


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def allocations():
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < 4:
        raise RuntimeError("at least four logical CPUs needed for isolated components")
    app_n = max(1, len(allowed) // 4)
    db_n = max(1, len(allowed) // 4)
    app = allowed[:app_n]
    db = allowed[app_n:app_n + db_n]
    valkey = allowed[app_n + db_n:app_n + db_n + 1]
    generator = allowed[app_n + db_n + 1:]
    return {"allowed": allowed, "single": [app[0]], "multi": app,
            "postgres": db, "valkey": valkey, "generator": generator}


def sidecars(cores, duration):
    # Keep every workload; register resource-scaled rates before any search.
    scale = cores / 16
    recipes = [("argon2", "oidc_cold_login_refresh", 8, 8),
               ("meta", "metadata_jwks", 200, 16),
               ("fapi", "fapi2_logged_in_high_security", 30, 32),
               ("refresh", "cap_refresh_token", 600, 64)]
    return [{"name": name, "scenario": scenario,
             "rate": max(1, math.ceil(rate * scale)),
             "pre_vus": vus, "max_vus": vus, "user_count": vus,
             "duration": f"{duration + 30}s"}
            for name, scenario, rate, vus in recipes]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stop-at", required=True, help="ISO time with timezone")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    stop_at = datetime.fromisoformat(args.stop_at).timestamp()
    os.environ.setdefault("SIS_SOURCE_SHA", os.environ["SIS_APP_SHA"])
    sis.RESULTS.mkdir(parents=True, exist_ok=True)
    cpus = allocations()
    points.KEYSET_VOLUME = f"{sis.PROJECT}-keys"
    sis.dc("volume", "create", points.KEYSET_VOLUME)
    for service in ("keyset", "audit-receiver", "perf"):
        sis.dc("tag", f"nazoauth-perf-{service}", f"{sis.PROJECT}-{service}")
    binary = points.image_binary_sha("nazoauth-perf-nazoauth")
    if not binary:
        raise RuntimeError("application binary identity unavailable")
    config = {"cpus": cpus, "app_image": "nazoauth-perf-nazoauth",
              "binary_sha256": binary, "pool_connections": 32,
              "sidecars": {m: sidecars(len(cpus[m]), 180) for m in ("single", "multi")},
              "stop_at": args.stop_at, "gate": "successful-ops-v1",
              "hash_policy": "unchanged application defaults", "source_sha": os.environ["SIS_APP_SHA"],
              "harness_sha": sis.sh(["git", "-C", sis.WORKSPACE, "rev-parse", "HEAD"]).stdout.strip()}
    save(sis.RESULTS / "registered-config.json", config)
    state_path = sis.RESULTS / "search-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    def run(mode, scenario, rate, window=90, confirmation=False):
        if time.time() + window + 240 >= stop_at:
            raise TimeoutError("reserved finalization time reached")
        warmup = 60 if scenario == "cap_mixed" else 15
        duration = window + warmup
        name = f"{mode}-{scenario.replace('_', '-')}-r{rate}-w{window}-{int(time.time())}"
        point = {"name": name, "phase": mode, "image": config["app_image"],
                 "app_cpus": cpus[mode], "postgres_cpus": cpus["postgres"],
                 "valkey_cpus": cpus["valkey"], "infra_cpus": cpus["generator"],
                 "profile": "capacity", "scenario": scenario,
                 "executor": "constant-arrival-rate", "rate": rate,
                 "duration": f"{duration}s", "warmup_ms": warmup * 1000,
                 "pre_vus": 64 if mode == "single" else 256,
                 "max_vus": 64 if mode == "single" else 256,
                 "user_count": 64 if mode == "single" else 256,
                 "vector_count": 48000, "stream_evidence": True,
                 "formal_preflight": True, "grace_s": 300,
                 "expected_binary_sha256": binary,
                 "app_env_overrides": {"DATABASE_MAX_CONNECTIONS": 32},
                 "issuance_retention_seconds": 360,
                 "issuance_max_expired_age_seconds": 120}
        if scenario == "cap_mixed":
            point.update(sidecars=sidecars(len(cpus[mode]), duration), sidecar_delay_s=0)
        rec = points.run_ab_point(point)
        out = sis.RESULTS / mode / name
        summary = out / "load" / "latest.json"
        verdict, metrics = gate.evaluate(gate.load_summary(summary), summary,
                                        rate, duration, scenario, require_stream=True)
        raw, _ = gate.k6_metrics(summary)
        metrics["complete_operation_latency_ms"] = gate._trend(raw, "cap_iter_ms")
        health = points._health_checks(rec, mixed=scenario == "cap_mixed")
        # Every point must retain runtime health and durable audit continuity.
        # Only clean client-credentials has a one-to-one issuance count gate.
        if not all(health.values()):
            m = rec.get("metrics") or {}
            collected = (rec.get("ok") is True
                         and m.get("oom_killed") is not None
                         and m.get("restart_count") is not None
                         and (m.get("audit_log_scan") or {}).get("collected") is True
                         and (rec.get("audit_state_check", {}).get("checks") or {}).get("collected") is True
                         and (rec.get("journal_stats") or {}).get("collected") is True)
            if scenario == "cap_mixed":
                collected = collected and rec.get("audit_queue_post_drain", {}).get("collected") is True
            verdict = "FAIL" if collected else "INVALID"
            metrics["failed_health_checks"] = [k for k, v in health.items() if not v]
            metrics["health_evidence_collected"] = collected
        if scenario == "cap_mixed":
            common = (rec.get("metrics") or {}).get("common_window_s") or {}
            metrics["all_load_common_window"] = common
            if common.get("seconds") is None or common["seconds"] < window:
                verdict = "INVALID"
                metrics["reason"] = "full_sidecar_measurement_window_unavailable"
        maintenance = None
        if confirmation:
            m = rec.get("metrics") or {}
            maintenance = sis.issuance_maintenance_evidence(
                out / "soak-metrics.jsonl", m.get("window_start_ms"),
                m.get("window_end_ms"), point, rec.get("samplers", {}).get("interval_s", 2))
            if maintenance.get("status") != "PASS":
                verdict = maintenance.get("status", "INVALID")
        result = {"name": name, "mode": mode, "scenario": scenario, "rate": rate,
                  "verdict": verdict, "metrics": metrics, "health": health,
                  "confirmation": confirmation, "maintenance": maintenance,
                  "elapsed_s": rec.get("elapsed_s"), "error": rec.get("error"),
                  "point_path": str(out / "point.json")}
        key = f"{mode}/{scenario}"
        state.setdefault(key, []).append(result)
        save(state_path, state)
        print(json.dumps(result), flush=True)
        if (sis.RESULTS / "stop-after-point").exists():
            raise TimeoutError("operator requested stop after completed point")
        return result

    def bounds(key):
        records = state.get(key, [])
        chosen = {}
        for record in records:
            rate = record["rate"]
            window = record["metrics"].get("window_seconds", 0)
            if rate not in chosen or window >= chosen[rate]["metrics"].get("window_seconds", 0):
                chosen[rate] = record
        records = list(chosen.values())
        passed = [r["rate"] for r in records if r["verdict"] == "PASS"]
        lower = max(passed, default=0)
        upper = min((r["rate"] for r in records if r["verdict"] == "FAIL" and r["rate"] > lower), default=None)
        return lower, upper

    def search(mode, scenario, extra=8):
        key = f"{mode}/{scenario}"
        for _ in range(extra):
            lower, upper = bounds(key)
            records = state.get(key, [])
            if lower and upper and upper / lower <= 1.25:
                break
            if records and records[-1]["verdict"] not in ("PASS", "FAIL"):
                break
            if lower and upper:
                rate = (lower + upper) // 2
            elif lower:
                rate = lower * 2
            elif records:
                rate = max(1, records[-1]["rate"] // 2)
                if rate == records[-1]["rate"]:
                    break
            else:
                rate = SCENARIOS[scenario] * len(cpus[mode])
            run(mode, scenario, rate)
        lower, _ = bounds(key)
        for _ in range(3):
            lower, upper = bounds(key)
            if not lower or any(r["verdict"] == "PASS" and r["rate"] == lower
                                and r["metrics"].get("window_seconds", 0) >= 180
                                for r in state.get(key, [])):
                break
            if run(mode, scenario, lower, window=180)["verdict"] == "PASS":
                break
            lower, upper = bounds(key)
            if upper and not lower:
                run(mode, scenario, max(1, upper * 3 // 4), window=180)

    try:
        if args.smoke:
            run("single", "cap_client_credentials", 50, window=60)
            return
        # Give every requested scenario both CPU modes a real observation
        # before spending the remaining budget narrowing the priority paths.
        for scenario in SCENARIOS:
            for mode in ("single", "multi"):
                if not any(r["verdict"] in ("PASS", "FAIL")
                           for r in state.get(f"{mode}/{scenario}", [])):
                    run(mode, scenario, SCENARIOS[scenario] * len(cpus[mode]))
        for mode in ("single", "multi"):
            for scenario in PRIMARY:
                search(mode, scenario)
            lower, _ = bounds(f"{mode}/cap_mixed")
            if lower:
                run(mode, "cap_mixed", lower, window=660, confirmation=True)
        for scenario in list(SCENARIOS)[4:]:
            for mode in ("single", "multi"):
                search(mode, scenario, extra=3)
    except TimeoutError as exc:
        print(str(exc), flush=True)
    finally:
        save(sis.RESULTS / "search-state.json", state)
        print("SEARCH_STOPPED", flush=True)


if __name__ == "__main__":
    main()
