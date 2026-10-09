#!/usr/bin/env python3
"""One-hour current-source baseline; reuse the established point and gate owners.

The clock includes preparation: pass the task's original --started-at. Raw
point evidence stays private; report.md and summary.json are small projections.
This is a short baseline, never a replacement for the accepted capacity matrix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
BASE_RATES = {"cap_client_credentials": 1000, "cap_mixed": 400,
              "cap_authorization_code": 200, "cap_refresh_token": 500}
FINAL_RESERVE = 240
COMMAND_DEADLINE = None
CONFIRM_WINDOW = 570  # 360-second retention + 210 seconds of mature samples
APP_INPUTS = ("crates", "migrations", "Cargo.toml", "Cargo.lock",
              "rust-toolchain.toml", "Containerfile", ".env.yaml.example", "perf/env.yaml")


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def command(args, *, timeout=45):
    if COMMAND_DEADLINE is not None:
        timeout = min(timeout, COMMAND_DEADLINE - time.time())
        if timeout <= 0:
            raise TimeoutError("original task deadline reached")
    return subprocess.run(args, cwd=ROOT, check=True, text=True,
                          capture_output=True, timeout=timeout).stdout.strip()


def started_epoch(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--started-at must include a timezone")
    return parsed.timestamp()


def allocate(allowed, cpu_budget=None):
    usable = sorted(set(allowed))
    if cpu_budget is not None:
        if not math.isfinite(cpu_budget) or cpu_budget <= 0:
            raise ValueError("CPU planning hint must be positive and finite")
        usable = usable[:max(1, math.floor(cpu_budget))]
    if not usable:
        raise ValueError("no common runnable CPU in controller and runner")
    if len(usable) < 4:
        return {"allowed": usable, "single": usable[:1], "multi": usable,
                "postgres": usable, "valkey": usable, "generator": usable,
                "isolation": "SHARED_INFRA"}
    n = max(1, len(usable) // 4)
    return {"allowed": usable, "single": usable[:1], "multi": usable[:n],
            "postgres": usable[n:2*n], "valkey": usable[2*n:2*n+1],
            "generator": usable[2*n+1:], "isolation": "SEPARATE_LOGICAL_CPU_SETS"}


def initial_rate(scenario, cores):
    # Planning seeds, not a capacity prediction or reused historical result.
    return max(1, round(BASE_RATES[scenario] * math.sqrt(cores)))


def cases(multicore=True, short_window=60):
    # Establish mixed before the mature confirmation; leave no long matrix.
    modes = ("single", "multi") if multicore else ("single",)
    return [(mode, scenario, short_window) for scenario in BASE_RATES
            for mode in modes] + [(modes[-1], "cap_mixed", CONFIRM_WINDOW)]


def point_budget(window, mixed):
    # Covers stack, seed, measurement, audit drain and local projection.
    return window + (60 if mixed else 15) + (180 if window == CONFIRM_WINDOW else 120)


def own_cleanup(project):
    """Stop only this task's labelled containers; keep volumes/evidence."""
    outcomes = []
    for label in (f"sis.owner={project}", f"com.docker.compose.project={project}"):
        try:
            ids = command(["docker", "ps", "-aq", "--filter", f"label={label}"], timeout=15).split()
            if ids:
                command(["docker", "rm", "-f", *ids], timeout=35)
            outcomes.append({"label": label, "removed": len(ids)})
        except (subprocess.SubprocessError, OSError) as exc:
            outcomes.append({"label": label, "error": type(exc).__name__})
    return outcomes


def bounded_child(argv, env, log, timeout):
    """Bound orchestration as well as k6; Docker children are cleaned separately."""
    with Path(log).open("wb") as output:
        proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return proc.wait(timeout=max(1, timeout))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            return 124
        except BaseException:
            # An operator interrupt must not leave the controller child
            # alive to recreate containers after the parent's cleanup.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
            raise


def token_state_verdict(state, scenario):
    if state.get("collected") is not True:
        return "INVALID"
    required = ["fresh_rows", "legacy_rows", "issuance_rows"]
    if scenario == "cap_client_credentials":
        required.append("issuance_inserts")
    if any(type(state.get(k)) is not int or state[k] < 0 for k in required):
        return "INVALID"
    if state.get("fresh_rows") != 0 or state.get("legacy_rows") != 0:
        return "FAIL"
    if scenario == "cap_client_credentials" and (
            state.get("issuance_rows") != 0 or state.get("issuance_inserts") != 0):
        return "FAIL"
    return "PASS"


def token_state_snapshot(sis):
    sql = """SELECT json_build_object(
        'fresh_rows', (SELECT count(*) FROM oauth_token_issuances WHERE single_use_key_blake3 IS NULL),
        'legacy_rows', (SELECT count(*) FROM oauth_token_issuances WHERE NOT principal_epoch_bound),
        'issuance_rows', (SELECT count(*) FROM oauth_token_issuances),
        'issuance_inserts', (SELECT n_tup_ins FROM pg_stat_user_tables WHERE relid='oauth_token_issuances'::regclass),
        'subject_bindings', (SELECT count(*) FROM oauth_subject_bindings),
        'database_bytes', pg_database_size(current_database()))"""
    try:
        return {"collected": True, **json.loads(sis.psql(sql))}
    except (ValueError, RuntimeError, subprocess.SubprocessError):
        return {"collected": False}


def worker(point_path):
    # Import after the controller has set the isolated SIS environment.
    import current_capacity as cc
    import point_runner as points
    import single_instance_scaling as sis
    point = json.loads(Path(point_path).read_text())
    points.KEYSET_VOLUME = f"{sis.PROJECT}-keys"
    rec = points.run_ab_point(point)
    out = sis.RESULTS / point["phase"] / point["name"]
    state = token_state_snapshot(sis) if rec.get("ok") else {"collected": False}
    result = {"name": point["name"], "mode": point["phase"],
              "scenario": point["scenario"], "rate": point["rate"],
              "window_seconds": point["effective_seconds"],
              "app_cpus": len(point["app_cpus"]), "confirmation": point["confirmation"],
              "point_path": str((out / "point.json").relative_to(sis.RESULTS)),
              "token_state": state, "verdict": "INVALID"}
    try:
        verdict, metrics, health, maintenance = cc.evaluate_point(
            point, rec, out, confirmation=point["confirmation"])
        provenance = rec.get("provenance") or {}
        identity_ok = all(provenance.get(k) is True for k in (
            "source_sha_eq_image_revision", "source_sha_eq_file", "k6_oauth_eq_workspace"))
        pin = (rec.get("stack") or {}).get("pin") or {}
        identity_ok = identity_ok and pin.get("app_verified") is True and pin.get("pg_verified") is True
        state_verdict = token_state_verdict(state, point["scenario"])
        if not identity_ok:
            verdict = cc.combined_verdict(verdict, "INVALID")
        verdict = cc.combined_verdict(verdict, state_verdict)
        m = rec.get("metrics") or {}
        result.update(verdict=verdict, metrics=metrics, health=health,
                      maintenance=maintenance, provenance_valid=identity_ok,
                      token_state_verdict=state_verdict,
                      cost={k: m.get(k) for k in (
                          "wal_windowed", "wal_per_success_bytes", "wal_io_windowed",
                          "wal_writes_per_op", "wal_fsyncs_per_op", "wait_per_acq_ms",
                          "acquire_per_op_windowed", "oom_killed", "restart_count")},
                      component_cpu_cores=points._proc_cpu(out, rec),
                      audit=rec.get("audit_state_check"),
                      queue=rec.get("audit_queue_post_drain"),
                      collection_contract=rec.get("collection_contract"),
                      unverified_internal_gates=rec.get("unverified_internal_gates"),
                      elapsed_s=rec.get("elapsed_s"))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        result["error_kind"] = type(exc).__name__
    save(out / "short-result.json", result)


def image_info(image):
    return json.loads(command(["docker", "image", "inspect", image]))[0]


def prepare(args, out):
    from runtime_cpu_probe import probe
    if command(["git", "status", "--porcelain", "--untracked-files=no"]):
        raise ValueError("commit tracked changes before freezing the benchmark")
    head = command(["git", "rev-parse", "HEAD"])
    app = image_info(args.app_image)
    runner = image_info(args.runner_image)
    source = app.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("app image needs its actual 40-character source revision")
    command(["git", "diff", "--exit-code", source, head, "--", *APP_INPUTS])
    baked_source = command(["docker", "run", "--rm", "--entrypoint", "cat",
                            app["Id"], "/etc/nazoauth-source-sha"])
    if baked_source != source:
        raise ValueError("application source file differs from image revision")
    binary = command(["docker", "run", "--rm", "--entrypoint", "sha256sum",
                      app["Id"], "/usr/local/bin/nazoauth"]).split()[0]
    # Verify what the load image executes, not merely its mutable tag.
    files = [p for p in command(["git", "ls-files", "perf"]).splitlines()
             if p.endswith((".py", ".js", ".sh"))
             and not p.startswith(("perf/tests/", "perf/results/"))]
    expected = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in files}
    code = "import hashlib,json,sys; print(json.dumps({p:hashlib.sha256(open('/'+p,'rb').read()).hexdigest() for p in json.loads(sys.argv[1])}))"
    actual = json.loads(command(["docker", "run", "--rm", "--entrypoint", "python",
                                 runner["Id"], "-c", code, json.dumps(files)], timeout=60))
    if actual != expected:
        raise ValueError("runner source differs: rebuild its COPY perf layer")
    controller = probe()
    runtime = json.loads(command(["docker", "run", "--rm", "--entrypoint", "python",
        "-v", f"{ROOT / 'perf/tools/runtime_cpu_probe.py'}:/probe.py:ro",
        runner["Id"], "/probe.py", "probe"], timeout=60))
    cpus = allocate(set(controller["runnable"]) & set(runtime["runnable"]), args.cpu_budget)
    project = "short-" + datetime.now(timezone.utc).strftime("%m%d%H%M%S") + "-" + os.urandom(3).hex()
    helpers = {}
    for service in ("keyset", "audit-receiver"):
        helpers[service] = image_info(f"nazoauth-perf-{service}")["Id"]
        command(["docker", "tag", helpers[service], f"{project}-{service}"])
    command(["docker", "tag", runner["Id"], f"{project}-perf"])
    command(["docker", "volume", "create", f"{project}-keys"])
    manifest = {"source_sha": source, "harness_sha": head, "app_image": app["Id"],
                "runner_image": runner["Id"], "binary_sha256": binary, "helpers": helpers,
                "project": project, "cpus": cpus, "runtime_probe": runtime,
                "controller_probe": controller, "runtime_script_sha256": expected,
                "memory_ceiling": "NOT_INFERRED_FROM_HOST", "cpu_budget_hint": args.cpu_budget}
    save(out / "manifest.json", manifest)
    return manifest


def make_point(manifest, mode, scenario, rate, window, index):
    import current_capacity as cc
    cpus = manifest["cpus"]
    cores, generators = len(cpus[mode]), len(cpus["generator"])
    warmup = 60 if scenario == "cap_mixed" else 15
    vus = max(32, min(64 * cores, 32 * generators))
    point = {"name": f"s{index}-{mode}-{int(time.time())}", "phase": mode,
             "image": manifest["app_image"], "profile": "capacity", "scenario": scenario,
             "app_cpus": cpus[mode], "postgres_cpus": cpus["postgres"],
             "valkey_cpus": cpus["valkey"], "infra_cpus": cpus["generator"],
             "executor": "constant-arrival-rate", "rate": rate,
             "duration": f"{window + warmup}s", "effective_seconds": window,
             "warmup_ms": warmup * 1000, "pre_vus": vus, "max_vus": vus,
             # runner.ensure_user_capacity enforces at least one seeded
             # user per VU. Freeze that effective count, not a smaller
             # requested count that the runner would silently increase.
             "user_count": max(64, 16 * cores, vus),
             # Include the FAPI sidecar's 1,200-vector offset before its
             # bounded 48k slice, including on large logical CPU sets.
             "vector_count": 49200 if scenario == "cap_mixed" else 48000,
             "stream_evidence": True, "stream_workers": max(1, min(8, generators // 8)),
             "formal_preflight": True, "grace_s": 120, "state_wait_s": 120,
             "expected_binary_sha256": manifest["binary_sha256"],
             "app_env_overrides": {"DATABASE_MAX_CONNECTIONS": 2 * len(cpus["postgres"])},
             "issuance_retention_seconds": 360, "issuance_max_expired_age_seconds": 120,
             "confirmation": window == CONFIRM_WINDOW}
    if scenario == "cap_mixed":
        point.update(sidecars=cc.sidecars(cores, window + warmup), sidecar_delay_s=0)
    if point["confirmation"]:
        point["capture_audit_journal"] = True
    return point


def report(out, manifest, rows, started, error=None):
    required = cases(len(manifest.get("cpus", {}).get("multi", [0, 1])) > 1,
                     manifest.get("short_window_seconds", 60))
    covered = {(r["mode"], r["scenario"], r["window_seconds"]) for r in rows
               if r["verdict"] in ("PASS", "FAIL")}
    missing = [list(c) for c in required if c not in covered]
    status = "INCOMPLETE" if missing or error else "COMPLETE"
    passed = {(r["mode"], r["scenario"], r["window_seconds"]) for r in rows
              if r["verdict"] == "PASS"}
    acceptance = ("INCOMPLETE" if status != "COMPLETE" else
                  "PASS" if all(c in passed for c in required) else "FAIL")
    summary = {"schema_version": 1, "status": status, "source_sha": manifest.get("source_sha"),
               "acceptance_status": acceptance,
               "harness_sha": manifest.get("harness_sha"), "elapsed_seconds": round(time.time()-started, 1),
               "scope": "current-source short points; no A/B, no production or maximum-capacity claim",
               "multicore_available": len(manifest.get("cpus", {}).get("multi", [])) > 1,
               "missing_valid_cases": missing, "error_kind": error,
               "confirmation_passed": any(r.get("confirmation") and r["verdict"] == "PASS" for r in rows),
               "points": rows}
    save(out / "summary.json", summary)
    lines = ["# One-hour current-source short baseline", "",
             f"Measurement status: **{status}**; required-point acceptance: **{acceptance}**.",
             f"Source: `{manifest.get('source_sha')}`; harness: `{manifest.get('harness_sha')}`.", "",
             "Logical operations/s; complete-operation latency in ms. FAIL is a failed offered point, INVALID is unusable evidence.", "",
             "| Mode | CPUs | Scenario | Target | Success/s | P50/P95/P99 | Window s | Verdict | WAL generated B/success |",
             "|---|---:|---|---:|---:|---|---:|---|---:|"]
    for row in rows:
        m = row.get("metrics", {})
        latency = m.get("measure", {}).get("iter_latency_ms") or m.get("complete_operation_latency_ms") or {}
        delay = "/".join(str(latency.get(k, "N/A")) for k in ("p50", "p95", "p99"))
        lines.append(f"| {row['mode']} | {row.get('app_cpus', 'N/A')} | {row['scenario']} | {row['rate']} | {m.get('successful_ops_s', 'N/A')} | {delay} | {row['window_seconds']} | {row['verdict']} | {row.get('cost', {}).get('wal_per_success_bytes', 'N/A')} |")
    lines += ["", "WAL generated and WAL write bytes are distinct counters. Window deltas use the existing sampler interpolation; costs include sidecars and background work. SQL-level WAL attribution is not inferred.",
              "", "See summary.json for exact cohort errors, drops, rejection/unfinished counts, HTTP rates, sidecar gates, pool waits, maintenance, audit/journal and token-state evidence.",
              "", "The accepted current-capacity.json remains pinned to its original code/environment. These points neither replace it nor establish a speedup against it. A PASS is authority for the recorded point only; no failing bound means no maximum-capacity claim."]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    return summary


def main():
    global COMMAND_DEADLINE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--started-at", help="original task start, ISO 8601 with timezone")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--app-image", default="nazoauth-perf-nazoauth")
    parser.add_argument("--runner-image", default="nazoauth-perf-perf")
    parser.add_argument("--cpu-budget", type=float, help="optional known budget of this deployment, never a host probe")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    if not args.started_at or not args.output:
        parser.error("--started-at and a new --output directory are required")
    started = started_epoch(args.started_at)
    if started > time.time() + 5 or time.time() >= started + 3600 - FINAL_RESERVE:
        parser.error("original task clock is invalid or its load budget has expired")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    COMMAND_DEADLINE = started + 3600 - FINAL_RESERVE
    manifest, rows, error = {}, [], None
    try:
        manifest = prepare(args, out)
        env = {**os.environ, "SIS_WORKSPACE": str(ROOT), "SIS_RESULTS": str(out),
               "SIS_BIN": str(out / "bin"), "SIS_PROJECT": manifest["project"],
               "SIS_PERF_IMAGE": manifest["runner_image"], "SIS_SOURCE_SHA": manifest["source_sha"],
               "SIS_APP_SHA": manifest["source_sha"], "SIS_LOAD_BUDGET_S": "2700"}
        multicore = len(manifest["cpus"]["multi"]) > 1
        queue = cases(multicore)
        planned = sum(point_budget(window, scenario == "cap_mixed")
                      for _, scenario, window in queue)
        # Freeze one fallback duration before any load when preparation
        # consumed more than its 15-minute allocation. Never shorten the
        # maturity proof or relabel a partial window as complete.
        short_window = 60 if time.time() + planned <= COMMAND_DEADLINE else 30
        manifest["short_window_seconds"] = short_window
        save(out / "manifest.json", manifest)
        queue = cases(multicore, short_window)
        required_count = len(queue)
        # Optional pressure probes consume only leftover time after all
        # required points. No broad search or guessed maximum is reported.
        queue += [(mode, "cap_mixed", short_window) for mode in ("single", "multi")
                  if mode == "single" or len(manifest["cpus"]["multi"]) > 1]
        for index, (mode, scenario, window) in enumerate(queue):
            left = started + 3600 - FINAL_RESERVE - time.time()
            if left < point_budget(window, scenario == "cap_mixed"):
                break
            rate = initial_rate(scenario, len(manifest["cpus"][mode]))
            if window == CONFIRM_WINDOW or index >= required_count:
                good = [r["rate"] for r in rows if r["mode"] == mode
                        and r["scenario"] == scenario and r["verdict"] == "PASS"]
                if index >= required_count:
                    if not good:
                        continue
                    rate = max(1, math.ceil(max(good) * 1.25))
                else:
                    rate = max(good) if good else max(1, rate // 2)
            point = make_point(manifest, mode, scenario, rate, window, index)
            spec = out / f"request-{index}.json"
            save(spec, point)
            timeout = min(left, point_budget(window, scenario == "cap_mixed"))
            rc = bounded_child([sys.executable, str(Path(__file__).resolve()), "--worker", str(spec)],
                               env, out / f"point-{index}.log", timeout)
            result_path = out / mode / point["name"] / "short-result.json"
            if rc == 0 and result_path.exists():
                row = json.loads(result_path.read_text())
            else:
                row = {"mode": mode, "scenario": scenario, "rate": rate,
                       "window_seconds": window, "verdict": "INVALID",
                       "confirmation": point["confirmation"], "exit_code": rc}
                own_cleanup(manifest["project"])
            rows.append(row)
            report(out, manifest, rows, started)
            print(json.dumps({k: row[k] for k in ("mode", "scenario", "rate", "verdict")}), flush=True)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        # Details stay in the private console/log; public summary has no secrets.
        error = type(exc).__name__
        print(f"setup/orchestration error: {error}; resolve within the original clock", file=sys.stderr)
        raise
    finally:
        COMMAND_DEADLINE = started + 3600 - 60
        if manifest.get("project"):
            save(out / "cleanup.json", own_cleanup(manifest["project"]))
        summary = report(out, manifest, rows, started, error)
        print(f"{summary['status']} {out / 'report.md'}", flush=True)
    if summary["status"] != "COMPLETE":
        raise SystemExit(2)
    if summary["acceptance_status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
