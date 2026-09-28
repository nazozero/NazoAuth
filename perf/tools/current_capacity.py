#!/usr/bin/env python3
"""Short current-B search using the existing point lifecycle and capacity gate."""
from __future__ import annotations

import argparse
import hashlib
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


def point_name(mode, scenario, rate, window, timestamp):
    # The receiver uses this identifier in a single DNS label. The full
    # FAPI scenario plus the 180-second suffix exceeds its 63-byte limit;
    # signed PAR also exceeds it at the configured ladder's high rates.
    slug = {"fapi2_logged_in_high_security": "fapi2-high-security",
            "par_signed_request_object": "par-signed-request"}.get(
                scenario, scenario.replace("_", "-"))
    return f"{mode}-{slug}-r{rate}-w{window}-{int(timestamp)}"


def bounds(state, key):
    chosen = {}
    for record in state.get(key, []):
        rate = record["rate"]
        priority = (record["verdict"] in ("PASS", "FAIL"),
                    record["metrics"].get("window_seconds") or 0)
        previous = chosen.get(rate)
        previous_priority = ((previous["verdict"] in ("PASS", "FAIL"),
                              previous["metrics"].get("window_seconds") or 0)
                             if previous else None)
        if previous_priority is None or priority >= previous_priority:
            chosen[rate] = record
    records = list(chosen.values())
    lower = max((r["rate"] for r in records if r["verdict"] == "PASS"), default=0)
    upper = min((r["rate"] for r in records if r["verdict"] == "FAIL" and r["rate"] > lower), default=None)
    return lower, upper


def allocations():
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < 4:
        # Shared infrastructure is a different deployment profile, not a
        # reason to investigate hidden host resources or abandon the run.
        return {"allowed": allowed, "single": allowed[:1], "multi": allowed,
                "postgres": allowed, "valkey": allowed, "generator": allowed}
    app_n = max(1, len(allowed) // 4)
    db_n = max(1, len(allowed) // 4)
    app = allowed[:app_n]
    db = allowed[app_n:app_n + db_n]
    valkey = allowed[app_n + db_n:app_n + db_n + 1]
    generator = allowed[app_n + db_n + 1:]
    return {"allowed": allowed, "single": [app[0]], "multi": app,
            "postgres": db, "valkey": valkey, "generator": generator}


def sidecars(cores, duration, allocated_vus=None):
    # Keep every workload; register resource-scaled rates before any search.
    scale = cores / 16
    recipes = [("argon2", "oidc_cold_login_refresh", 8, 8),
               ("meta", "metadata_jwks", 200, 16),
               ("fapi", "fapi2_logged_in_high_security", 30, 32),
               ("refresh", "cap_refresh_token", 600, 64)]
    return [{"name": name, "scenario": scenario,
             "rate": max(1, math.ceil(rate * scale)),
             "pre_vus": allocated_vus[i] if allocated_vus else math.ceil(vus * max(1, scale)),
             "max_vus": allocated_vus[i] if allocated_vus else math.ceil(vus * max(1, scale)),
             "user_count": vus,
             "duration": f"{duration + 30}s"}
            for i, (name, scenario, rate, vus) in enumerate(recipes)]


def combined_verdict(*verdicts):
    """Missing/invalid measurement cannot establish a service upper bound."""
    for verdict in verdicts:
        if verdict not in ("PASS", "FAIL"):
            return verdict
    return "FAIL" if "FAIL" in verdicts else "PASS"


def evaluate_point(point, rec, out, *, confirmation=False):
    """Evaluate retained evidence without launching load or rewriting it."""
    scenario = point["scenario"]
    duration = sis._duration_seconds(point["duration"])
    window = duration - point["warmup_ms"] / 1000
    summary = out / "load" / "latest.json"
    verdict, metrics = gate.evaluate(gate.load_summary(summary), summary,
                                    point["rate"], duration, scenario,
                                    require_stream=True)
    metrics["main_verdict"] = verdict
    raw, _ = gate.k6_metrics(summary)
    metrics["complete_operation_latency_ms"] = gate._trend(raw, "cap_iter_ms")
    health = points._health_checks(rec, mixed=scenario == "cap_mixed")
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
        # Local/unknown preparation failures remain invalid even if every
        # independent health snapshot was collected successfully.
        health_verdict = ("FAIL" if collected and health["preparation_valid"]
                          else "INVALID")
        metrics["health_verdict"] = health_verdict
        metrics["failed_health_checks"] = [k for k, v in health.items() if not v]
        metrics["health_evidence_collected"] = collected
        verdict = combined_verdict(verdict, health_verdict)
    if scenario == "cap_mixed":
        common = (rec.get("metrics") or {}).get("common_window_s") or {}
        metrics["all_load_common_window"] = common
        if common.get("seconds") is None or common["seconds"] < window:
            verdict = combined_verdict(verdict, "INVALID")
            metrics["reason"] = "full_sidecar_measurement_window_unavailable"
        expected = {"argon2", "meta", "fapi", "refresh"}
        recipes = point.get("sidecars") or []
        if {sc["name"] for sc in recipes} != expected or len(recipes) != len(expected):
            verdict = combined_verdict(verdict, "INVALID")
            metrics["sidecar_recipe_error"] = "mixed_requires_all_four_sidecars"
        metrics["sidecar_gates"] = {}
        for sc in recipes:
            path = out / sc["name"] / "latest.json"
            sc_verdict, sc_metrics = gate.evaluate(
                gate.load_summary(path), path, sc["rate"],
                sis._duration_seconds(sc["duration"]), sc["scenario"],
                require_stream=True)
            sc_raw, _ = gate.k6_metrics(path)
            sc_metrics["complete_operation_latency_ms"] = (
                gate._trend(sc_raw, "cap_iter_ms")
                if "cap_iter_ms" in sc_raw else None)
            metrics["sidecar_gates"][sc["name"]] = {
                "verdict": sc_verdict, "metrics": sc_metrics}
            verdict = combined_verdict(verdict, sc_verdict)
    maintenance = None
    if confirmation:
        m = rec.get("metrics") or {}
        maintenance = sis.issuance_maintenance_evidence(
            out / "soak-metrics.jsonl", m.get("window_start_ms"),
            m.get("window_end_ms"), point, rec.get("samplers", {}).get("interval_s", 2))
        verdict = combined_verdict(verdict, maintenance.get("status", "INVALID"))
    return verdict, metrics, health, maintenance


def positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def resource_profile(cpus, mode, *, vus=None, users=None, pool=None):
    """CPU-scaled starting recipe; explicit values come from calibration.

    Users are independent of VUs so increasing injector concurrency need
    not silently increase account cardinality in a one-factor experiment.
    """
    cores = len(cpus[mode])
    return {"vus": vus or 64 * cores,
            "users": users or max(64, 16 * cores),
            "pool_connections": pool or 2 * len(cpus["postgres"])}


def recipe_id(config):
    # Controller revisions and stopping times do not change the workload.
    # Binary/images, CPU allocation and effective workload resources do.
    keys = ("cpus", "app_image_id", "runner_image_id", "binary_sha256",
            "resources", "sidecars", "vector_counts", "gate")
    fields = {k: config[k] for k in keys}
    fields["stream_workers"] = config.get("stream_workers", 1)
    encoded = json.dumps(fields, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def reevaluate(paths, output):
    """Offline only: original point files are never modified or promoted."""
    if output.resolve() in {p.resolve() for p in paths}:
        raise ValueError("reassessment output must not overwrite an input point")
    results = []
    for path in paths:
        rec = json.loads(path.read_text())
        point = rec["point"]
        verdict, metrics, health, maintenance = evaluate_point(
            point, rec, path.parent,
            confirmation=bool(point.get("capture_audit_journal")))
        results.append({"point_path": str(path), "point": point,
                        "verdict": verdict, "metrics": metrics,
                        "health": health, "maintenance": maintenance})
    output.parent.mkdir(parents=True, exist_ok=True)
    save(output, results)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stop-at", help="ISO time with timezone; required for load")
    parser.add_argument("--reevaluate", nargs="+", type=Path, metavar="POINT_JSON")
    parser.add_argument("--output", type=Path, help="separate offline reassessment JSON")
    parser.add_argument("--mode", choices=("single", "multi", "all"), default="all")
    parser.add_argument("--scenarios", nargs="+", choices=tuple(SCENARIOS))
    parser.add_argument("--rates", nargs="+", type=positive_int,
                        help="run only these rates for one scenario and CPU mode")
    parser.add_argument("--window", type=positive_int, default=180,
                        help="effective seconds for explicit --rates")
    parser.add_argument("--vus", type=positive_int, help="calibrated pre/max VUs")
    parser.add_argument("--users", type=positive_int, help="fixed account cardinality")
    parser.add_argument("--pool-connections", type=positive_int)
    parser.add_argument("--stream-workers", type=int, choices=range(1, 9), default=1,
                        help="metric-sharded stream observers; frozen per recipe")
    parser.add_argument("--sidecar-vus", nargs=4, type=positive_int,
                        metavar=("ARGON2", "META", "FAPI", "REFRESH"))
    parser.add_argument("--repeat", action="store_true", help="recheck an already measured explicit rate")
    parser.add_argument("--confirm", action="store_true", help="include mixed maintenance and journal checks")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.reevaluate:
        if not args.output:
            parser.error("--reevaluate requires --output")
        results = reevaluate(args.reevaluate, args.output)
        print(json.dumps([{"point": r["point_path"], "verdict": r["verdict"]}
                          for r in results]))
        return
    if not args.stop_at:
        parser.error("load requires --stop-at")
    modes = ("single", "multi") if args.mode == "all" else (args.mode,)
    scenarios = args.scenarios or list(SCENARIOS)
    if args.rates and (len(modes) != 1 or len(scenarios) != 1):
        parser.error("--rates requires one --mode and one --scenarios entry")
    if args.confirm and (not args.rates or scenarios != ["cap_mixed"]):
        parser.error("--confirm requires explicit mixed --rates")
    if args.confirm and args.window < 540:
        parser.error("maintenance confirmation needs at least 360 + 180 effective seconds")
    stop_at = datetime.fromisoformat(args.stop_at).timestamp()
    os.environ.setdefault("SIS_SOURCE_SHA", os.environ["SIS_APP_SHA"])
    sis.RESULTS.mkdir(parents=True, exist_ok=True)
    cpus = allocations()
    if args.stream_workers > 1 and args.stream_workers + 1 > len(cpus["generator"]):
        parser.error("stream workers plus dispatcher exceed the allocated generator CPU set")
    points.KEYSET_VOLUME = f"{sis.PROJECT}-keys"
    sis.dc("volume", "create", points.KEYSET_VOLUME)
    for service in ("keyset", "audit-receiver", "perf"):
        sis.dc("tag", f"nazoauth-perf-{service}", f"{sis.PROJECT}-{service}")
    binary = points.image_binary_sha("nazoauth-perf-nazoauth")
    if not binary:
        raise RuntimeError("application binary identity unavailable")
    config = {"cpus": cpus, "app_image": "nazoauth-perf-nazoauth",
              "binary_sha256": binary,
              "app_image_id": sis.dc("image", "inspect", "nazoauth-perf-nazoauth",
                                     "--format", "{{.Id}}").stdout.strip(),
              "runner_image_id": sis.dc("image", "inspect", sis.PERF_IMAGE,
                                        "--format", "{{.Id}}").stdout.strip(),
              "stream_workers": args.stream_workers,
              "resources": {m: resource_profile(cpus, m, vus=args.vus,
                             users=args.users, pool=args.pool_connections)
                            for m in ("single", "multi")},
              "sidecars": {m: sidecars(len(cpus[m]), 180, args.sidecar_vus)
                           for m in ("single", "multi")},
              "stop_at": args.stop_at, "gate": "successful-ops-v1",
              "vector_counts": {"default": 48000, "fapi2_logged_in_high_security": 49200},
              "exploration_window_seconds": 60, "candidate_window_seconds": 180,
              "mixed_confirmation_window_seconds": 660,
              "hash_policy": "unchanged application defaults", "source_sha": os.environ["SIS_APP_SHA"],
              "harness_sha": sis.sh(["git", "-C", sis.WORKSPACE, "rev-parse", "HEAD"]).stdout.strip()}
    identity = recipe_id(config)
    config["recipe_id"] = identity
    current_config = sis.RESULTS / "registered-config.json"
    if current_config.exists():
        previous = current_config.read_bytes()
        if "recipe_id" not in json.loads(previous):
            legacy_id = hashlib.sha256(previous).hexdigest()[:16]
            (sis.RESULTS / f"registered-config-legacy-{legacy_id}.json").write_bytes(previous)
    save(current_config, config)
    save(sis.RESULTS / f"registered-config-{identity}.json", config)
    state_path = sis.RESULTS / f"search-state-{identity}.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    def run(mode, scenario, rate, window=60, confirmation=False):
        if time.time() + window + 240 >= stop_at:
            raise TimeoutError("reserved finalization time reached")
        warmup = 60 if scenario == "cap_mixed" else 15
        duration = window + warmup
        name = point_name(mode, scenario, rate, window, time.time())
        resources = config["resources"][mode]
        point = {"name": name, "phase": mode, "image": config["app_image"],
                 "capacity_recipe_id": identity,
                 "app_cpus": cpus[mode], "postgres_cpus": cpus["postgres"],
                 "valkey_cpus": cpus["valkey"], "infra_cpus": cpus["generator"],
                 "profile": "capacity", "scenario": scenario,
                 "executor": "constant-arrival-rate", "rate": rate,
                 "duration": f"{duration}s", "warmup_ms": warmup * 1000,
                 "pre_vus": resources["vus"], "max_vus": resources["vus"],
                 "user_count": resources["users"],
                 # FAPI reserves offset 12 * 100 before its bounded 48k
                 # replay pool. Freeze the whole pool before its search so
                 # the runner cannot silently grow it at higher rates.
                 "vector_count": 49200 if scenario == "fapi2_logged_in_high_security" else 48000,
                 "stream_evidence": True,
                 "stream_workers": args.stream_workers,
                 "formal_preflight": True, "grace_s": 300,
                 "expected_binary_sha256": binary,
                 "app_env_overrides": {"DATABASE_MAX_CONNECTIONS": resources["pool_connections"]},
                 "issuance_retention_seconds": 360,
                 "issuance_max_expired_age_seconds": 120}
        if scenario == "cap_mixed":
            point.update(sidecars=sidecars(len(cpus[mode]), duration, args.sidecar_vus),
                         sidecar_delay_s=0)
        if confirmation:
            point["capture_audit_journal"] = True
        rec = points.run_ab_point(point)
        out = sis.RESULTS / mode / name
        verdict, metrics, health, maintenance = evaluate_point(
            point, rec, out, confirmation=confirmation)
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

    def search(mode, scenario, extra=8):
        key = f"{mode}/{scenario}"
        for _ in range(extra):
            lower, upper = bounds(state, key)
            records = state.get(key, [])
            if lower and upper and upper / lower <= 1.25:
                break
            # Do not create a higher short-window candidate when there is
            # insufficient time to recheck it for three minutes as well.
            if time.time() + 60 + 240 + 180 + 240 >= stop_at:
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
        lower, _ = bounds(state, key)
        for _ in range(3):
            lower, upper = bounds(state, key)
            if not lower or any(r["verdict"] == "PASS" and r["rate"] == lower
                                and r["metrics"].get("window_seconds", 0) >= 180
                                for r in state.get(key, [])):
                break
            if run(mode, scenario, lower, window=180)["verdict"] != "FAIL":
                break
            lower, upper = bounds(state, key)
            if upper and not lower:
                run(mode, scenario, max(1, upper * 3 // 4), window=180)

    try:
        if args.rates:
            mode, scenario = modes[0], scenarios[0]
            for rate in args.rates:
                existing = [r for r in state.get(f"{mode}/{scenario}", [])
                            if r["rate"] == rate and r["verdict"] in ("PASS", "FAIL")
                            and (r["metrics"].get("window_seconds") or 0) >= args.window
                            and (not args.confirm or r.get("confirmation"))]
                if existing and not args.repeat:
                    print(f"REUSE {existing[-1]['name']}", flush=True)
                    continue
                run(mode, scenario, rate, window=args.window, confirmation=args.confirm)
            return
        if args.smoke:
            run("single", "cap_client_credentials", 50, window=60)
            return
        # Give every requested scenario both CPU modes a real observation
        # before spending the remaining budget narrowing the priority paths.
        for scenario in scenarios:
            for mode in modes:
                key = f"{mode}/{scenario}"
                for _ in range(3):
                    records = state.get(key, [])
                    if any(r["verdict"] in ("PASS", "FAIL") for r in records):
                        break
                    # Invalid observer evidence is not a service upper bound.
                    # Lower the offered rate to obtain a valid observation,
                    # while preserving the failed evidence and every gate.
                    rate = (max(1, records[-1]["rate"] // 2) if records
                            else SCENARIOS[scenario] * len(cpus[mode]))
                    run(mode, scenario, rate)
        for mode in modes:
            for scenario in (s for s in scenarios if s in PRIMARY):
                search(mode, scenario)
            lower, _ = bounds(state, f"{mode}/cap_mixed")
            confirmed = any(r["verdict"] == "PASS" and r["rate"] == lower
                            and r.get("confirmation")
                            and r["metrics"].get("window_seconds", 0) >= 660
                            for r in state.get(f"{mode}/cap_mixed", []))
            if "cap_mixed" in scenarios and lower and not confirmed:
                run(mode, "cap_mixed", lower, window=660, confirmation=True)
        # Give all secondary candidates a three-minute verification before
        # spending the remaining deadline budget on additional narrowing.
        for scenario in (s for s in scenarios if s not in PRIMARY):
            for mode in modes:
                lower, _ = bounds(state, f"{mode}/{scenario}")
                # Initial failure-only scenes need a lower probe first.
                # Otherwise verify the existing candidate before optional
                # higher probes spend time reserved for matrix coverage.
                search(mode, scenario, extra=0 if lower else 1)
        for scenario in (s for s in scenarios if s not in PRIMARY):
            for mode in modes:
                search(mode, scenario, extra=2)
    except TimeoutError as exc:
        print(str(exc), flush=True)
    finally:
        save(state_path, state)
        print("SEARCH_STOPPED", flush=True)


if __name__ == "__main__":
    main()
