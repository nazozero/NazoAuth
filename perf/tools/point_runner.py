#!/usr/bin/env python3
"""Single load-point lifecycle machinery for the formal harness.

Runs one measurement point end to end: pinned stack bring-up, k6 load via
single_instance_scaling, audit receiver/DB state reconciliation, journal
contiguity, per-second CPU accounting, and post-run point health checks.

This module carries the point-orchestration code that used to live in
the one-shot A/B experiment drivers (prepared_rsa_ab, audit_batch_ab,
group_commit_ab, token_audit_preflight_ab, residency_run). Those drivers
are gone; the formal capacity/stability runner (pool_size_ab) is the
sole consumer of what remains.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import single_instance_scaling as sis  # noqa: E402


KEYSET_VOLUME = "sisprsa-confirm-keys"


# Optional callable executed by stack_up_pinned AFTER the infra services
# (postgres/migrate/keyset/valkey) are healthy and BEFORE the nazoauth
# container starts. Drivers use it for DB-side experiment settings that
# must be in place before the app's pool sessions open. Returns a JSON-
# serialisable evidence dict stored under stack["pre_app"]. Keep it None
# outside single-variable A/B tasks.


def image_binary_sha(image: str) -> str | None:
    """sha256 of the nazoauth binary inside an image — run before any
    load; identical hashes for A and B mean the build cache produced the
    same binary and the experiment must not proceed."""
    proc = sis.dc("run", "--rm", "--entrypoint", "sha256sum", image,
                  "/usr/local/bin/nazoauth", check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.split()[0].strip() or None


def image_binary_sha_in_container(container: str) -> str | None:
    """sha256 of the running app's binary — per-point identity evidence."""
    proc = sis.dcx(container, ["sha256sum", "/usr/local/bin/nazoauth"],
                   check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.split()[0].strip() or None

# ---------------------------------------------------------------------
# receiver state vs DB reconciliation (task-scoped, uses existing
# receiver endpoints — no new collector)
# ---------------------------------------------------------------------

def _receiver_token(rcv_name: str) -> str | None:
    proc = sis.dc("inspect", rcv_name, "--format",
                  "{{range .Config.Env}}{{println .}}{{end}}", check=False)
    for line in (proc.stdout or "").splitlines():
        if line.startswith("ANCHOR_RECEIVER_TOKEN="):
            return line.split("=", 1)[1]
    return None


def _receiver_get(run_id: str, path: str, token: str) -> dict:
    """GET a receiver endpoint from inside the perf network with proper
    TLS verification against the per-run CA cert."""
    rcv = f"sis-rcv-{run_id}"
    tls_host = f"{sis.WORKSPACE}/perf-results/anchor-tls/{run_id}"
    py = (
        "import json,ssl,sys,urllib.request;"
        "ctx=ssl.create_default_context(cafile='/tls/receiver.crt');"
        "req=urllib.request.Request(sys.argv[1],headers="
        "{'Authorization':'Bearer '+sys.argv[2]});"
        "sys.stdout.write(urllib.request.urlopen(req,context=ctx,"
        "timeout=10).read().decode())"
    )
    proc = sis.dc("run", "--rm", "--network", sis.NETWORK,
                  "-v", f"{tls_host}:/tls:ro",
                  "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
                  sis.PERF_IMAGE, "python", "-c", py,
                  f"https://{rcv}:9443{path}", token, check=False)
    if proc.returncode != 0:
        return {"collected": False, "error": (proc.stderr or "")[:200]}
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"collected": False, "error": "non-json response"}
    out["collected"] = True
    return out


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.b64decode(text + pad, altchars=b"-_", validate=True)


def _hex_bytes(value) -> bytes | None:
    """DB-side hash: encode(...,'hex') text output -> bytes."""
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def _wire_hash_bytes(value) -> bytes | None:
    """Receiver-side hash: wire.rs encode_hash = base64url-no-pad, 32B."""
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = _b64url_decode(value)
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def db_chain_state() -> dict:
    """security_audit_chain_state facts + pending depth."""
    try:
        row = sis.psql(
            "SELECT (SELECT count(*) FROM security_audit_events),"
            " last_sequence, encode(last_hash,'hex'),"
            " anchor_deployment_id, anchor_sequence,"
            " encode(anchor_hash,'hex')"
            " FROM security_audit_chain_state")
        pending, last_seq, last_hash, dep, anchor_seq, anchor_hash = \
            row.split("|")
        return {
            "collected": True,
            "pending": int(pending),
            "last_sequence": int(last_seq),
            "last_hash": last_hash or None,
            "anchor_deployment_id": dep or None,
            "anchor_sequence": int(anchor_seq) if anchor_seq else None,
            "anchor_hash": anchor_hash or None,
        }
    except Exception as e:  # noqa: BLE001 - evidence path
        return {"collected": False, "error": str(e)[:200]}


def audit_state_snapshot(run_id: str) -> dict:
    """Structured receiver + DB state at one instant."""
    rcv = f"sis-rcv-{run_id}"
    token = _receiver_token(rcv)
    state = _receiver_get(run_id, "/__state", token) if token else \
        {"collected": False, "error": "receiver token unavailable"}
    checkpoint = _receiver_get(run_id, "/checkpoint", token) if token else \
        {"collected": False, "error": "receiver token unavailable"}
    return {"receiver_state": state, "receiver_checkpoint": checkpoint,
            "db": db_chain_state()}


def _journal_scan(lines, deployment: str, seq_lo: int, seq_hi: int) -> dict:
    """Pure scanner over journal.jsonl lines (bytes or str). Counts
    events by type inside (seq_lo, seq_hi], verifies deployment binding,
    batch-chain contiguity, duplicate sequences and event_count honesty.
    Also buckets in-range events per occurred_at second for same-interval
    CPU accounting."""
    sha = hashlib.sha256()
    n_bytes = 0
    by_type: dict[str, int] = {}
    seen: set[int] = set()
    duplicates = 0
    batches = 0
    foreign_deployment = 0
    malformed = 0
    prev_last = None
    gaps = 0
    per_second: dict[int, int] = {}
    for raw in lines:
        if isinstance(raw, str):
            raw = raw.encode()
        sha.update(raw)
        n_bytes += len(raw)
        try:
            env = json.loads(raw)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if env.get("checkpoint_kind") != "batch":
            continue
        if env.get("deployment_id") != deployment:
            foreign_deployment += 1
            continue
        batches += 1
        events = env.get("events") or []
        first = env.get("first_sequence")
        if isinstance(prev_last, int) and isinstance(first, int) \
                and first != prev_last + 1:
            gaps += 1
        if isinstance(env.get("last_sequence"), int):
            prev_last = env["last_sequence"]
        if isinstance(env.get("event_count"), int) \
                and env["event_count"] != len(events):
            malformed += 1
        for ev in events:
            seq = ev.get("sequence")
            if not isinstance(seq, int):
                malformed += 1
                continue
            if seq in seen:
                duplicates += 1
                continue
            seen.add(seq)
            if seq_lo < seq <= seq_hi:
                et = ev.get("event_type") or "<missing>"
                by_type[et] = by_type.get(et, 0) + 1
                occ = ev.get("occurred_at")
                if isinstance(occ, str):
                    try:
                        ms = int(datetime.datetime.fromisoformat(
                            occ.replace("Z", "+00:00"))
                            .timestamp() * 1000)
                        sec = ms // 1000
                        per_second[sec] = per_second.get(sec, 0) + 1
                    except ValueError:
                        pass
    in_range = sorted(s for s in seen if seq_lo < s <= seq_hi)
    expected = seq_hi - seq_lo
    return {
        "journal_sha256": sha.hexdigest(),
        "journal_bytes": n_bytes,
        "batches": batches,
        "malformed_lines": malformed,
        "foreign_deployment_batches": foreign_deployment,
        "sequence_gaps": gaps,
        "duplicate_sequences": duplicates,
        "events_in_range": len(in_range),
        "expected_in_range": expected,
        "range_contiguous": len(in_range) == expected
            and in_range == list(range(seq_lo + 1, seq_hi + 1)),
        "by_event_type": by_type,
        "token_issued_in_range": by_type.get("token_issued", 0),
        "per_second_counts": per_second,
    }


def journal_event_counts(run_id: str, deployment: str,
                         seq_lo: int, seq_hi: int) -> dict:
    """Count persisted audit events by event_type over (seq_lo, seq_hi]
    from the receiver's own journal.jsonl.

    The DB-side `security_audit_events.sequence` column no longer exists
    and ACKed events are deleted, so the receiver journal is the only
    honest per-type source. It is streamed line-by-line (never fully
    loaded), hashed as read, and read only after load + drain so the
    exporter is never disturbed.

    Returns collected=False on any failure — callers must treat missing
    as missing, never as zero.
    """
    rcv = f"sis-rcv-{run_id}"
    result: dict = {
        "collected": False,
        "remote_path": f"{rcv}:/data/journal.jsonl",
        "deployment": deployment,
        "range": [seq_lo, seq_hi],
    }
    proc = subprocess.Popen(
        ["docker", "exec", rcv, "cat", "/data/journal.jsonl"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    try:
        stats = _journal_scan(proc.stdout, deployment, seq_lo, seq_hi)
        proc.wait(timeout=120)
        stderr = proc.stderr.read().decode(errors="replace") \
            if proc.stderr else ""
    except Exception as e:  # noqa: BLE001 - evidence path
        proc.kill()
        result["error"] = f"{type(e).__name__}: {e}"[:300]
        return result
    if proc.returncode != 0:
        result["error"] = f"journal read failed: {stderr[:200]}"
        return result
    result.update(stats)
    result["collected"] = True
    return result


def reconcile_audit_state(pre: dict, post: dict, point_name: str,
                          expected_issuances: int | None,
                          journal: dict | None) -> dict:
    """Two-sided persisted-prefix check for one point.

    Passes only when ALL hold:
      pending == 0; DB last==anchor (sequence AND hash); receiver
      checkpoint sequence/hash equal the DB anchor; receiver and DB
      deployment identity match the run deployment; receiver fault none;
      the receiver checkpoint advanced across the load; the receiver
      journal is readable, carries only this deployment, has a contiguous
      non-duplicated sequence range matching the checkpoint delta and the
      receiver's own accepted_events increment.

    For the client-credentials scenario the journal's token_issued count
    is additionally compared against the whole-run completed-iterations
    count (only valid when the run had zero failures/rejections — the
    caller passes None otherwise and the check is marked UNAVAILABLE
    rather than silently passing).
    """
    result: dict = {"point": point_name, "checks": {}, "verdict": "FAIL"}
    checks = result["checks"]

    db = post.get("db") or {}
    state = post.get("receiver_state") or {}
    ckpt = post.get("receiver_checkpoint") or {}
    checks["collected"] = all(
        s.get("collected") is True for s in (db, state, ckpt))
    if not checks["collected"]:
        result["reason"] = "missing structured audit state"
        return result

    checks["fault_none"] = state.get("fault") == "none"
    checks["pending_zero"] = db.get("pending") == 0
    checks["db_head_eq_anchor_seq"] = (
        isinstance(db.get("last_sequence"), int)
        and db.get("last_sequence") == db.get("anchor_sequence"))
    db_last_hash = _hex_bytes(db.get("last_hash"))
    db_anchor_hash = _hex_bytes(db.get("anchor_hash"))
    rcv_hash = _wire_hash_bytes(ckpt.get("last_hash"))
    checks["db_head_eq_anchor_hash"] = (
        db_last_hash is not None and db_last_hash == db_anchor_hash)
    checks["rcv_seq_eq_anchor"] = (
        ckpt.get("last_sequence") is not None
        and ckpt.get("last_sequence") == db.get("anchor_sequence"))
    checks["rcv_hash_eq_anchor"] = (
        rcv_hash is not None and rcv_hash == db_anchor_hash)

    dep = (post.get("deployment_id") or db.get("anchor_deployment_id"))
    checks["deployment_match"] = (
        dep is not None
        and ckpt.get("deployment_id") == dep
        and db.get("anchor_deployment_id") in (None, dep))

    pre_ckpt = pre.get("receiver_checkpoint") or {}
    pre_seq = pre_ckpt.get("last_sequence")
    post_seq = ckpt.get("last_sequence")
    checks["checkpoint_advanced"] = (
        isinstance(pre_seq, int) and isinstance(post_seq, int)
        and post_seq > pre_seq)
    delta = (post_seq - pre_seq
             if isinstance(pre_seq, int) and isinstance(post_seq, int)
             else None)
    result["delta_events"] = delta

    # Receiver-side accepted_events increment must equal the chain
    # sequence delta — no double-counted deliveries.
    pre_acc = pre_ckpt.get("accepted_events")
    post_acc = ckpt.get("accepted_events")
    checks["accepted_events_delta_eq"] = (
        isinstance(pre_acc, int) and isinstance(post_acc, int)
        and delta is not None and post_acc - pre_acc == delta)
    result["accepted_events_delta"] = (
        post_acc - pre_acc
        if isinstance(pre_acc, int) and isinstance(post_acc, int)
        else None)

    # Journal: real per-event-type counts, deployment-bound, contiguous.
    if journal is None:
        journal = {"collected": False, "error": "journal not read"}
    result["journal"] = {
        k: journal.get(k) for k in
        ("collected", "journal_sha256", "journal_bytes", "batches",
         "remote_path", "events_in_range", "expected_in_range",
         "by_event_type", "token_issued_in_range", "malformed_lines",
         "foreign_deployment_batches", "sequence_gaps",
         "duplicate_sequences", "range_contiguous", "error")
        if journal.get(k) is not None}
    checks["journal_collected"] = journal.get("collected") is True
    if journal.get("collected"):
        checks["journal_clean"] = (
            journal.get("malformed_lines") == 0
            and journal.get("foreign_deployment_batches") == 0
            and journal.get("duplicate_sequences") == 0
            and journal.get("sequence_gaps") == 0)
        checks["journal_range_eq_delta"] = (
            journal.get("range_contiguous") is True
            and journal.get("events_in_range") == delta)

    # One token_issued per successful issuance (CC scenario contract).
    # `expected_issuances` is the whole-run completed-iterations count,
    # legitimate only when the run had zero unexpected outcomes, zero
    # local_no_request, zero expected rejections and a clean termination —
    # the caller computes that and passes None when it does not hold.
    if expected_issuances is None:
        # No legitimate whole-run denominator (mixed grants, or the run
        # had failures/rejections). Report the count as evidence scope,
        # but do not pretend a 1:1 check ran.
        result["token_issued_delta"] = journal.get("token_issued_in_range")
        result["expected_issuances"] = None
        result["token_issued_scope"] = (
            "reported_only_no_clean_denominator")
    else:
        issued = journal.get("token_issued_in_range") \
            if journal.get("collected") else None
        result["token_issued_delta"] = issued
        result["expected_issuances"] = expected_issuances
        checks["token_issued_eq_expected"] = (
            issued is not None and issued == expected_issuances)

    result["verdict"] = (
        "PASS" if all(v is True for v in checks.values()) else "FAIL")
    return result


# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# point orchestration (thin wrapper over sis primitives + audit states)
# ---------------------------------------------------------------------

def _ensure_pinset_binary() -> None:
    path = Path(sis.BIN_DIR) / "pinset"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        src = Path(sis.BIN_DIR) / "pinset.c"
        src.write_text(sis.PINSET_C)
        sis.sh(["gcc", "-O2", "-static", "-o", str(path), str(src)])
    os.chmod(path, 0o755)


def keyset_fingerprint() -> dict:
    """sha256 of every file in the key dir inside the running app
    container (key PEMs are root:600, so exec as root) — proves all
    points ran with the same RS256/PS256 key material, not merely
    'an RSA2048 key'. Also records the volume mounted at the key dir."""
    proc = sis.dc("exec", "-u", "0", sis.APP, "sh", "-c",
                  "sha256sum /var/lib/nazo_oauth/keys/*", check=False)
    files = {}
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2:
                files[parts[1]] = parts[0]
    mount = sis.dc("inspect", sis.APP, "--format",
                   "{{range .Mounts}}{{if eq .Destination "
                   "\"/var/lib/nazo_oauth\"}}{{.Source}}{{end}}{{end}}",
                   check=False)
    return {"files": files, "collected": bool(files),
            "key_dir_volume": (mount.stdout or "").strip()}


def stack_up_pinned(point: dict) -> dict:
    """stack_up variant for this experiment: the app container is started
    through the existing pinset 'pin self then exec' wrapper so the CPU
    affinity is applied BEFORE Tokio/Actix spawn any threads. Infra
    containers keep the existing post-start pinning. The key material
    lives on an EXTERNAL volume (not removed by `down -v`) so every point
    of the confirmation shares one controlled keyset while postgres /
    valkey / audit state still get fresh volumes per point."""
    evidence: dict = {"point": point["name"], "image": point["image"]}
    for svc in ("nazoauth", "migrate", "audit-worker"):
        sis.dc("tag", point["image"], f"{sis.PROJECT}-{svc}")

    _ensure_pinset_binary()
    app_cpus = sis.format_cpu_list(point["app_cpus"])
    infra_cpus = sis.format_cpu_list(point["infra_cpus"])
    # One override for every compose invocation of this point:
    #   * nazoauth entrypoint = pinset CPULIST (affinity before exec,
    #     before any Tokio/Actix thread exists);
    #   * keyset/nazoauth/migrate mount the external shared key volume
    #     instead of the per-point perf_runtime volume.
    # Optional per-point process-env overrides for the app container
    # (e.g. DATABASE_MAX_CONNECTIONS). Process env takes precedence over
    # the baked /app/.env.yaml (ConfigSource: env > file > generated), so
    # this is the benchmark-level override channel — the image and the
    # production default constant stay untouched.
    env_extra = ""
    for k, v in (point.get("app_env_overrides") or {}).items():
        env_extra += f'      {k}: "{v}"\n'
    env_block = ("    environment:\n" + env_extra) if env_extra else ""
    override = sis.RESULTS / f"confirm-override-{point['name']}.yml"
    override.write_text(
        "services:\n"
        "  keyset:\n"
        "    volumes:\n"
        f"      - {KEYSET_VOLUME}:/var/lib/nazo_oauth\n"
        "  migrate:\n"
        "    volumes:\n"
        f"      - {KEYSET_VOLUME}:/var/lib/nazo_oauth\n"
        "  nazoauth:\n"
        f"    entrypoint: [\"/pinbin/pinset\", \"{app_cpus}\"]\n"
        f"{env_block}"
        "    volumes:\n"
        f"      - {KEYSET_VOLUME}:/var/lib/nazo_oauth\n"
        f"      - {sis.BIN_DIR}:/pinbin:ro\n"
        "volumes:\n"
        f"  {KEYSET_VOLUME}:\n"
        "    external: true\n")
    up_args = ("compose", "-f", sis.COMPOSE_FILE, "-f", str(override),
               "-p", sis.PROJECT)
    sis.dc(*up_args, "up", "-d", "--no-build",
           "postgres", "valkey", "postgres-init", "keyset", "migrate")
    evidence["healthy"] = {
        "postgres": sis.wait_healthy(sis.POSTGRES),
        "valkey": sis.wait_healthy(sis.VALKEY),
        "keyset": sis.wait_healthy(sis.KEYSET),
        "migrate": sis.wait_healthy(sis.MIGRATE),
    }
    if not all(evidence["healthy"].values()):
        raise RuntimeError(f"infra unhealthy: {evidence['healthy']}")


    sis.dc(*up_args, "up", "-d", "--no-build", "nazoauth")
    evidence["healthy"]["nazoauth"] = sis.wait_app_ready()
    if not evidence["healthy"]["nazoauth"]:
        raise RuntimeError("app not ready after pinned exec start")
    evidence["keyset"] = keyset_fingerprint()
    evidence["app_binary_sha256"] = image_binary_sha_in_container(
        sis.APP)

    # pin_container injects /tmp/pinset and retargets stray threads;
    # verify_pin shells the same binary — so pin must run before verify.
    evidence["pin"] = {
        "app_exec_mode": "pinset-exec",
        "app_cpus": app_cpus,
        "postgres": sis.pin_container(sis.POSTGRES, infra_cpus),
        "valkey": sis.pin_container(sis.VALKEY, infra_cpus),
        "keyset": sis.pin_container(sis.KEYSET, infra_cpus),
        "pg_verified": sis.verify_pin(sis.POSTGRES, infra_cpus),
    }
    # Record the proc masks after exec-pinning for the thread/CPU evidence.
    evidence["pin"]["app"] = sis.pin_container(sis.APP, app_cpus)
    evidence["pin"]["app_verified"] = sis.verify_pin(sis.APP, app_cpus)

    depid = ""
    for _ in range(30):
        out = sis.dcx(sis.VALKEY, ["valkey-cli", "keys", "nazo:state:v1:*"],
                      check=False).stdout.split("\n")[0].strip().split(":")
        depid = out[3] if len(out) > 3 else ""
        if depid:
            break
        time.sleep(2)
    evidence["deployment_id"] = depid or None
    return evidence


def run_ab_point(point: dict) -> dict:
    """run_point equivalent with receiver-state baselines around load."""
    run_id = point["name"]
    out_dir = sis.RESULTS / point["phase"] / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    sis.CURRENT_POINT = point

    rec: dict = {"point": point, "run_id": run_id}
    # load_seconds is one shared elapsed window per point (main and
    # sidecars run concurrently, tracked via max()), so the planned
    # estimate must be the longest container duration plus margin,
    # not a sum of durations.
    planned = sis._duration_seconds(point["duration"])
    for sc in point.get("sidecars") or []:
        planned = max(planned, sis._duration_seconds(sc["duration"]))
    planned += 30
    sis.budget_check(planned)
    started = time.time()

    try:
        if point.get("formal_preflight"):
            # Bind the run to this checkout: every harness file the
            # point executes or bind-mounts must live under WORKSPACE —
            # a stale checkout silently producing observability was the
            # previous INVALID's root cause.
            rec["workspace_provenance"] = sis.workspace_provenance()
            if not rec["workspace_provenance"]["ok"]:
                raise RuntimeError(
                    "HARNESS_WORKSPACE files missing/empty: "
                    f"{rec['workspace_provenance']['missing']}")
            bad_mounts = [f for f, ok
                          in sis.verify_mount_sources().items() if not ok]
            rec["mount_sources_ok"] = not bad_mounts
            if bad_mounts:
                raise RuntimeError(
                    f"bind-mount sources missing/empty: {bad_mounts}")
        sis.stack_down()
        rec["stack"] = stack_up_pinned(point)
        rec["provenance"] = sis.provenance(point, out_dir)
        if point.get("formal_preflight"):
            # Runtime binary identity: running PID1 exe vs the image's
            # recorded binary (sha of the file, never string search).
            rec["binary_provenance"] = sis.runtime_binary_provenance(
                image_sha=image_binary_sha(point["image"]),
                expected_sha=point.get("expected_binary_sha256"))
            if not rec["binary_provenance"]["ok"]:
                raise RuntimeError(
                    "PROVENANCE_INVALID: "
                    f"{rec['binary_provenance']}")
            rec["perf_schema"] = sis.app_perf_schema(
                out_path=out_dir / "perf-metrics-preflight.json")
            if not rec["perf_schema"]["ok"]:
                raise RuntimeError(
                    f"perf metrics schema missing fields: "
                    f"{rec['perf_schema']}")
        depid = rec["stack"].get("deployment_id")
        if not depid:
            raise RuntimeError("deployment id unavailable after stack up")
        point["deployment_id"] = depid
        rec["audit"] = sis.audit_pair_up(run_id, depid)
        sis.ledger("pre", run_id, out_dir)
        rec["pgss_reset"] = sis.pgss_reset()
        pgss_pre = sis.pgss_snapshot("pre", out_dir)
        wal_pre = sis.wal_snapshot("pre", out_dir)
        rec["samplers"] = sis.start_samplers(run_id, str(out_dir))
        # Optional high-frequency residency observer (attribution tasks
        # only). Starts with the samplers — stack/network exist by then —
        # and is stopped with them in the finally below.
        if point.get("residency_observer"):
            obs = point["residency_observer"]
            obs_name = f"sis-residency-{run_id}"
            sis._remove_owned_by_name(obs_name)
            proc = sis.dc(
                "run", "-d", "--name", obs_name, "--network", sis.NETWORK,
                "--label", f"{sis.SIS_LABEL}={sis.PROJECT}",
                "-v", f"{sis.TOOLS}/residency_observer.py:/tmp/obs.py:ro",
                "-v", f"{out_dir}:/out",
                "-e", f"RUN_ID={run_id}",
                "-e", "OUT_PATH=/out/residency.jsonl",
                "-e", f"INTERVAL_S={obs.get('interval_s', 0.25)}",
                "-e", f"RUNTIME_ROLE={obs['runtime_role']}",
                sis.PERF_IMAGE, "python3", "/tmp/obs.py")
            sis._record_extra(proc.stdout, obs_name, "residency_observer")
            sis.pin_container(obs_name, sis.format_cpu_list(
                point["infra_cpus"]))
            rec["residency_observer"] = {"container": obs_name,
                                         "role": obs["runtime_role"]}

        if point.get("formal_preflight"):
            # Sampler health gate: every sampler must be running and
            # emitting a meta row that matches THIS worktree's script —
            # before any business load is launched.
            rec["sampler_health"] = sis.sampler_health(
                run_id, out_dir,
                expect_residency=bool(point.get("residency_observer")))
            if not rec["sampler_health"]["ok"]:
                raise RuntimeError(
                    f"sampler health failed before load: "
                    f"{rec['sampler_health']}")

        # Pre-load structured baseline: seed/startup events land here and
        # are excluded from the measured increment.
        rec["audit_state_pre"] = audit_state_snapshot(run_id)

        # Optional generator memory gate: stack + samplers are up but the
        # main k6 container has not started. Insufficient MemAvailable
        # aborts the point BEFORE any load — no budget is spent and the
        # point is not a capacity result.
        mem_min = point.get("generator_mem_min_gib")
        if mem_min is not None:
            rec["generator_preflight"] = sis.generator_mem_preflight()
            avail = rec["generator_preflight"].get("mem_available_gib")
            if not isinstance(avail, (int, float)) or avail < mem_min:
                rec["blocked"] = "BLOCKED_LOAD_GENERATOR_MEMORY"
                raise RuntimeError(
                    f"BLOCKED_LOAD_GENERATOR_MEMORY: MemAvailable="
                    f"{avail}GiB < required {mem_min}GiB")

        try:
            rec["load"] = sis.run_load(point, run_id, out_dir)
        finally:
            sis._spend_load_budget(run_id, rec)

        rec["audit_drain"] = sis.audit_drain()
        rec["audit_state_post"] = audit_state_snapshot(run_id)
        rec["audit_state_post"]["deployment_id"] = depid

        # Per-event-type journal counting — streamed, post-drain only.
        pre_seq = ((rec["audit_state_pre"].get("receiver_checkpoint") or {})
                   .get("last_sequence"))
        post_seq = ((rec["audit_state_post"].get("receiver_checkpoint") or {})
                    .get("last_sequence"))
        if isinstance(pre_seq, int) and isinstance(post_seq, int):
            rec["journal_stats"] = journal_event_counts(
                run_id, depid, pre_seq, post_seq)
        else:
            rec["journal_stats"] = {"collected": False,
                                    "error": "sequence bounds unavailable"}

        sis.ledger("post", run_id, out_dir)
        pgss_post = sis.pgss_snapshot("post", out_dir)
        wal_post = sis.wal_snapshot("post", out_dir)
        rec["wal_delta"] = sis.wal_delta(wal_pre, wal_post)
        rec["app_log_scan"] = sis.app_log_scan(rec["load"]["started_ts"])
        rec["container_health"] = sis.container_health()
        sis.stop_samplers(run_id)

        summary_files = list((out_dir / "load").glob("*.summary.json"))
        rec["summary_files"] = [f.name for f in summary_files]
        if summary_files:
            combined = json.loads(summary_files[0].read_text())
            rec["metrics"] = sis.extract_point_metrics(combined)
            m = rec["metrics"]
            http = m.get("http_reqs") or 0
            rec["pgss_delta"] = sis.pgss_delta(pgss_pre, pgss_post, http)
            soak_path = out_dir / "soak-metrics.jsonl"
            wal_w = sis.windowed_series_delta(
                soak_path, "wal_bytes",
                m.get("window_start_ms"), m.get("window_end_ms"))
            acq_w = sis.windowed_series_delta(
                soak_path, "pool.acq",
                m.get("window_start_ms"), m.get("window_end_ms"))
            wait_w = sis.windowed_series_delta(
                soak_path, "pool.wait_ns",
                m.get("window_start_ms"), m.get("window_end_ms"))
            wal_io_w = {
                k: sis.windowed_series_delta(
                    soak_path, f"wal_io.{k}",
                    m.get("window_start_ms"), m.get("window_end_ms"))
                for k in ("writes", "write_bytes", "write_time_ms",
                          "fsyncs", "fsync_time_ms")}
            success = m.get("outcome_success")
            m["wal_windowed"] = wal_w
            m["wal_per_success_bytes"] = (
                round(wal_w["delta"] / success, 3)
                if wal_w.get("delta") and success else None)
            m["acquire_windowed"] = acq_w
            m["acquire_per_op_windowed"] = (
                round(acq_w["delta"] / success, 4)
                if acq_w.get("delta") and success else None)
            m["pool_wait_ns_windowed"] = wait_w
            m["wait_per_acq_ms"] = (
                round(wait_w["delta"] / acq_w["delta"] / 1e6, 3)
                if wait_w.get("delta") and acq_w.get("delta") else None)
            m["wal_io_windowed"] = wal_io_w
            win_s = (wal_io_w["fsyncs"].get("window_s")
                     or wal_w.get("window_s"))
            if win_s:
                m["wal_writes_per_s"] = (
                    round(wal_io_w["writes"]["delta"] / win_s, 1)
                    if wal_io_w["writes"].get("delta") is not None
                    else None)
                m["wal_fsyncs_per_s"] = (
                    round(wal_io_w["fsyncs"]["delta"] / win_s, 1)
                    if wal_io_w["fsyncs"].get("delta") is not None
                    else None)
                m["wal_bytes_per_s"] = (
                    round(wal_w["delta"] / win_s, 1)
                    if wal_w.get("delta") else None)
            if success:
                m["wal_writes_per_op"] = (
                    round(wal_io_w["writes"]["delta"] / success, 4)
                    if wal_io_w["writes"].get("delta") is not None
                    else None)
                m["wal_fsyncs_per_op"] = (
                    round(wal_io_w["fsyncs"]["delta"] / success, 4)
                    if wal_io_w["fsyncs"].get("delta") is not None
                    else None)
            # Same-interval CPU/success: proc-detail rows bound the CPU
            # interval [t_first, t_last]; the denominator is the journal's
            # per-second completion counts over that SAME interval — not
            # the full measurement window. UNAVAILABLE when the journal
            # did not yield a per-second series (e.g. mixed grants whose
            # completions are not 1:1 audit events).
            m["cpu_per_success_ms"] = _same_interval_cpu_per_success(
                out_dir / "proc-detail.jsonl",
                rec["journal_stats"],
                m.get("window_start_ms"), m.get("window_end_ms"),
                cc_only=(point["scenario"] == "cap_client_credentials"))
        else:
            rec["metrics"] = {"status": "no_summary"}

        ooms = [(rec["container_health"].get(c) or {}).get("oom_killed")
                for c in rec["container_health"]]
        rec["metrics"]["oom_killed"] = (
            True if any(ooms)
            else False if ooms and all(o is False for o in ooms) else None)
        rsts = [(rec["container_health"].get(c) or {}).get("restart_count")
                for c in rec["container_health"]]
        rec["metrics"]["restart_count"] = (
            sum(rsts) if rsts and all(isinstance(x, int) for x in rsts)
            else None)
        rec["metrics"]["audit_db_drained"] = sis.audit_db_drained_of(
            rec["audit_drain"])
        rec["metrics"]["audit_log_scan"] = rec["app_log_scan"]
        rec["metrics"]["refresh_invariants"] = sis.refresh_invariants(
            out_dir / "ledger-post.txt")
        if rec["load"].get("sidecars") is not None:
            rec["metrics"]["sidecar_terminal_complete"] = all(
                s["terminal_summary"] and not s["interrupted"]
                for s in rec["load"]["sidecars"])
            # run_load stamps started_ts on point["sidecars"], not on the
            # result entries — merge it in so non-contract sidecars can
            # still contribute a conservative container-bound window.
            starts = {s["name"]: s.get("started_ts")
                      for s in point.get("sidecars") or []}
            for s in rec["load"]["sidecars"]:
                s.setdefault("started_ts", starts.get(s["name"]))
            rec["metrics"]["sidecar_evidence"] = _sidecar_evidence(
                out_dir, rec["load"]["sidecars"])
            rec["metrics"]["common_window_s"] = _common_window_seconds(
                rec["metrics"], rec["metrics"]["sidecar_evidence"],
                rec["load"]["sidecars"])

        # Whole-run completed iterations is a legitimate expected
        # issuance count ONLY when the run was completely clean.
        m = rec["metrics"]
        clean_run = (
            point["scenario"] == "cap_client_credentials"
            and m.get("outcome_unexpected") == 0
            and m.get("outcome_local_no_request") == 0
            and m.get("outcome_expected_rejection") == 0
            and m.get("outcome_prepare_failed") in (0, None)
            and rec["load"].get("load_status") == "completed")
        expected = m.get("iterations_completed") if clean_run else None
        rec["audit_state_check"] = reconcile_audit_state(
            rec["audit_state_pre"], rec["audit_state_post"], run_id,
            expected, rec["journal_stats"])
        rec["ok"] = True
    except Exception as e:  # noqa: BLE001 - evidence path
        rec["ok"] = False
        rec["error"] = f"{type(e).__name__}: {e}"[:500]
    finally:
        rec["elapsed_s"] = round(time.time() - started, 1)
        sis.stop_samplers(run_id)
        if point.get("residency_observer"):
            sis._remove_owned_by_name(f"sis-residency-{run_id}",
                                      stop=True)
        sis.jdump(out_dir / "point.json", rec)
    return rec


def _cpu_sample_interval(proc_jsonl: Path,
                         start_ms, end_ms) -> tuple | None:
    """[t_first, t_last] ms of proc-detail samples inside the window and
    the app CPU ms consumed between them. Returns (t0, t1, cpu_ms)."""
    if not proc_jsonl.exists() or not start_ms or not end_ms:
        return None
    hz = 100
    rows = []
    for line in proc_jsonl.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("kind") == "meta":
            hz = r.get("clk_tck") or hz
            continue
        app = r.get("app")
        if isinstance(app, dict) and isinstance(app.get("total_jif"), int) \
                and isinstance(r.get("ts"), (int, float)):
            rows.append((r["ts"] * 1000.0, app["total_jif"]))
    rows.sort()
    inside = [r for r in rows if start_ms <= r[0] <= end_ms]
    if len(inside) < 2:
        return None
    cpu_ms = (inside[-1][1] - inside[0][1]) * 1000.0 / hz
    return inside[0][0], inside[-1][0], cpu_ms


def _same_interval_cpu_per_success(proc_jsonl: Path, journal: dict,
                                   start_ms, end_ms,
                                   cc_only: bool) -> dict:
    """CPU ms per successful completion over the SAME interval.

    Numerator: app CPU consumed between the first and last proc-detail
    samples inside the measurement window.
    Denominator: journal events whose occurred_at falls in that same
    (t0, t1] interval — the existing per-second completion counts.
    Returns UNAVAILABLE-shaped dict when no per-second denominator
    exists (journal unreadable, or non-CC scenarios where completed
    operations are not 1:1 audit events). Boundary seconds are partial:
    flagged as an estimate.
    """
    result = {"status": "UNAVAILABLE",
              "cpu_ms": None, "success_in_interval": None,
              "cpu_per_success_ms": None, "estimate": None}
    if not cc_only:
        result["reason"] = ("non-CC scenario: audit events are not a 1:1 "
                            "completion counter")
        return result
    interval = _cpu_sample_interval(proc_jsonl, start_ms, end_ms)
    if interval is None:
        result["reason"] = "proc-detail samples insufficient in window"
        return result
    t0, t1, cpu_ms = interval
    result["cpu_ms"] = round(cpu_ms, 1)
    result["cpu_interval_ms"] = [t0, t1]
    if not journal.get("collected"):
        result["reason"] = "journal unavailable — no per-second counts"
        return result
    per_second = journal.get("per_second_counts") or {}
    if not per_second:
        result["reason"] = "journal has no occurred_at timestamps"
        return result
    # Same interval: seconds strictly inside (t0, t1]. Events whose
    # occurred_at second covers the boundary are still counted — the
    # boundary seconds are partial, so the ratio is an estimate.
    lo, hi = t0 / 1000.0, t1 / 1000.0
    n = sum(c for sec, c in per_second.items() if lo < sec <= hi)
    result["success_in_interval"] = n
    result["estimate"] = True
    if n <= 0:
        result["reason"] = "zero completions counted in CPU interval"
        return result
    result["status"] = "OK"
    result["cpu_per_success_ms"] = round(cpu_ms / n, 4)
    return result


def _sidecar_evidence(out_dir: Path, sidecars: list[dict]) -> dict:
    """Per-sidecar summary facts: http_reqs, scenario window, exit."""
    out = {}
    for sc in sidecars:
        name = sc["name"]
        entry: dict = {"exit_code": sc.get("exit_code"),
                       "interrupted": sc.get("interrupted"),
                       "terminal_summary": sc.get("terminal_summary")}
        files = list((out_dir / name).glob("*.summary.json")) \
            + list((out_dir / name).glob("latest.json"))
        if files:
            try:
                combined = json.loads(files[0].read_text())
                k6 = (combined.get("k6") or {})
                meas = (k6.get("measure") or {})
                contract = (meas.get("measurement_contract") or {})
                entry["http_reqs"] = k6.get("http_reqs")
                entry["window_start_ms"] = contract.get("window_start_ms")
                entry["window_end_ms"] = contract.get("window_end_ms")
            except (json.JSONDecodeError, OSError):
                entry["summary_parse"] = "failed"
        entry["started_ts"] = sc.get("started_ts")
        out[name] = entry
    return out


def _common_window_seconds(main_metrics: dict, sidecar_ev: dict,
                           sidecars: list[dict]) -> dict:
    """Intersection of the main measurement window with every sidecar's
    own window; non-cap sidecars without a contract window contribute a
    conservative bound (container start + warmup .. container end) so no
    point can claim coverage it did not have."""
    m_start, m_end = (main_metrics.get("window_start_ms"),
                      main_metrics.get("window_end_ms"))
    if not isinstance(m_start, (int, float)) \
            or not isinstance(m_end, (int, float)):
        return {"seconds": None, "reason": "main window missing"}
    lo, hi = m_start, m_end
    method = "contract"
    for name, ev in sidecar_ev.items():
        ws, we = ev.get("window_start_ms"), ev.get("window_end_ms")
        if isinstance(ws, (int, float)) and isinstance(we, (int, float)):
            lo, hi = max(lo, ws), min(hi, we)
            continue
        # Conservative bound: sidecar was certainly loading between its
        # container start + warmup and its terminal summary.
        started = ev.get("started_ts")
        if isinstance(started, (int, float)):
            lo = max(lo, started * 1000 + 15000)
            method = "mixed_contract_and_container_bounds"
        else:
            return {"seconds": None,
                    "reason": f"sidecar {name} window unavailable"}
    seconds = (hi - lo) / 1000.0
    return {"seconds": round(seconds, 1), "method": method,
            "start_ms": lo, "end_ms": hi}


# ---------------------------------------------------------------------
def _point(name: str, phase: str, image: str, cpus: dict, **kw) -> dict:
    p = {"name": name, "phase": phase, "image": image,
         "app_cpus": cpus["X8"], "infra_cpus": cpus["INFRA"],
         "profile": "cap", "warmup_ms": 15000,
         "user_count": 64, "vector_count": 48000}
    p.update(kw)
    return p



# ---------------------------------------------------------------------
# point health evaluation
# ---------------------------------------------------------------------

def runtime_role_from_image(image: str) -> tuple[str, str]:
    """Read the baked /app/.env.yaml inside the exact image under test and
    parse the DATABASE_URL username — the authoritative runtime role, not
    a hardcoded assumption."""
    proc = sis.dc("run", "--rm", "--entrypoint", "sh", image,
                  "-c", "grep '^DATABASE_URL' /app/.env.yaml",
                  check=False, timeout=60)
    line = (proc.stdout or "").strip()
    m = re.search(r"[a-zA-Z][a-zA-Z0-9+.-]*://([^:/?#]+):", line)
    if not m:
        raise RuntimeError(
            f"cannot parse runtime role from image env: {line[:200]!r}")
    return m.group(1), line







WAL_WAIT_EVENTS = {"WALWrite", "WalSync"}
def _wal_wait_share(point_dir: Path, rec: dict) -> dict:
    """Fraction of runtime-role ACTIVE backend samples whose wait event
    is WALWrite or WalSync, inside the measurement window. Source: the
    250ms residency observer stream (role-scoped pg_stat_activity)."""
    m = rec.get("metrics") or {}
    w0 = (m.get("window_start_ms") or 0) / 1000.0
    w1 = (m.get("window_end_ms") or 0) / 1000.0
    path = point_dir / "residency.jsonl"
    active = wal = 0
    samples = 0
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("kind") != "sample" or not (w0 <= r["ts"] <= w1):
                continue
            samples += 1
            for b in r.get("backends") or []:
                if b.get("state") != "active":
                    continue
                active += 1
                if b.get("we") in WAL_WAIT_EVENTS:
                    wal += 1
    return {"active_samples": active,
            "wal_wait_samples": wal,
            "wal_wait_share": round(wal / active, 4) if active else None,
            "window_samples": samples}


def _proc_cpu(point_dir: Path, rec: dict) -> dict:
    """Mean per-target CPU cores inside the measurement window, derived
    from proc-detail cgroup usage_usec deltas (same source the previous
    task used for app/PG CPU headroom evidence — not a gate)."""
    m = rec.get("metrics") or {}
    w0 = (m.get("window_start_ms") or 0) / 1000.0
    w1 = (m.get("window_end_ms") or 0) / 1000.0
    path = point_dir / "proc-detail.jsonl"
    rates: dict = {}
    prev: dict = {}
    clk = 100.0
    if not path.exists():
        return {}
    for line in path.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("kind") == "meta":
            clk = float(r.get("clk_tck") or clk)
            continue
        ts = r.get("ts")
        if not isinstance(ts, (int, float)) or not (w0 <= ts <= w1):
            continue
        for name in ("app", "postgres"):
            jif = (r.get(name) or {}).get("total_jif")
            p = prev.get(name)
            if isinstance(jif, (int, float)) and p:
                dt = ts - p[0]
                if dt > 0:
                    a = rates.setdefault(name, [0.0, 0])
                    a[0] += (jif - p[1]) / (dt * clk)
                    a[1] += 1
            if isinstance(jif, (int, float)):
                prev[name] = (ts, jif)
    return {n: round(v[0] / v[1], 2) for n, v in rates.items() if v[1]}




def audit_queue_final(out_dir: Path) -> dict:
    """Last audit_queue counters sampled by the soak sampler.

    The sampler keeps ticking until after audit_drain, so the final row
    carrying audit_queue data is the post-drain in-process truth: the
    enqueued==persisted and pending_in_process==0 gates read it here
    instead of a live endpoint that is already gone."""
    path = out_dir / "soak-metrics.jsonl"
    if not path.exists():
        return {"collected": False, "error": "sampler stream missing"}
    last = None
    for line in path.read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        q = row.get("audit_queue")
        if isinstance(q, dict):
            last = q
    if last is None:
        return {"collected": False, "error": "no audit_queue samples"}
    out = dict(last)
    out["collected"] = True
    return out


def _bounded(value, limit) -> bool:
    return isinstance(value, (int, float)) and value <= limit


def _refresh_ok(inv: dict) -> dict:
    return {
        "active_per_scope_le_10": _bounded(
            inv.get("max_active_per_scope"), 10)
            and inv.get("max_active_per_scope") is not None,
        "spent_per_family_le_64": _bounded(
            inv.get("spent_max_per_family"), 64)
            and inv.get("spent_max_per_family") is not None,
        "expired_backlog_zero": inv.get("spent_expired_backlog") == 0,
    }



def _health_checks(rec: dict, mixed: bool) -> dict:
    m = rec.get("metrics") or {}
    scan = m.get("audit_log_scan") or {}
    asc = rec.get("audit_state_check") or {}
    journal = asc.get("journal") or {}
    checks = {
        "point_completed": rec.get("ok") is True,
        "unexpected_zero": m.get("outcome_unexpected") == 0,
        "oom_none": m.get("oom_killed") is False,
        "no_restarts": m.get("restart_count") == 0,
        "queue_full_zero": scan.get("queue_full") == 0,
        "dropped_required_zero": scan.get("dropped_required") == 0,
        "db_outbox_drained": m.get("audit_db_drained") is True,
        "audit_reconciled": asc.get("verdict") == "PASS",
        "journal_contiguous": (
            journal.get("duplicate_sequences") == 0
            and journal.get("sequence_gaps") == 0
            and journal.get("range_contiguous") is True),
    }
    if not mixed:
        # cap_client_credentials sends only fresh client-credentials
        # issuance, so both classes must stay at zero. cap_mixed counts
        # protocol-correct bounded-family invalid_grant rejections and
        # dead-family local no-request exits by design, so the mixed gate
        # only requires unexpected == 0.
        checks["local_no_request_zero"] = (
            m.get("outcome_local_no_request") == 0)
        checks["expected_rejection_zero"] = (
            m.get("outcome_expected_rejection") in (0, None))
    if mixed:
        q = rec.get("audit_queue_post_drain") or {}
        checks.update(_refresh_ok(m.get("refresh_invariants") or {}))
        checks["sidecars_complete"] = (
            m.get("sidecar_terminal_complete") is True)
        checks["queue_dropped_zero"] = q.get("dropped") == 0
        checks["pending_zero_post_drain"] = q.get("pending_in_process") == 0
        checks["enqueued_eq_persisted"] = (
            isinstance(q.get("enqueued"), int)
            and q.get("enqueued") == q.get("persisted"))
    return checks
