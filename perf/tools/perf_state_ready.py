#!/usr/bin/env python3
"""Prepared perf-state readiness marker.

The seeding runner produces /perf-state/{secrets,vectors}.json and then
publishes perf-state-ready.json ATOMICALLY (tmp + rename) carrying the
content hashes. Sidecars sharing the volume must wait for the marker and
verify it against the actual files — a startup race against seed output
is a load-model failure, never an exit-1 surprise mid-init.

Fail-closed rules:
  * marker run_id must equal the point's PERF_STATE_RUN_ID (when set);
    a stale marker from another point is ignored, never consumed;
  * vectors.json/secrets.json must exist, parse, and hash-match the
    marker — mismatch means corrupt shared state;
  * waiting longer than timeout_s raises StateNotReady.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

READY_NAME = "perf-state-ready.json"
DEFAULT_TIMEOUT_S = 60.0


class StateNotReady(RuntimeError):
    """Sidecar could not obtain a valid prepared-state marker in time."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def marker_path(state_dir) -> Path:
    return Path(state_dir) / READY_NAME


def clear_ready(state_dir) -> None:
    try:
        marker_path(state_dir).unlink()
    except OSError:
        pass


def write_ready(state_dir, run_id: str) -> dict:
    """Hash the prepared files and publish the marker atomically."""
    state_dir = Path(state_dir)
    vectors = state_dir / "vectors.json"
    secrets = state_dir / "secrets.json"
    doc = json.loads(vectors.read_text())
    json.loads(secrets.read_text())  # parseable or fail
    marker = {
        "run_id": run_id,
        "vectors_sha256": _sha256(vectors),
        "secrets_sha256": _sha256(secrets),
        "vector_count": len(doc),
        "created_at": round(time.time(), 3),
    }
    tmp = state_dir / f".{READY_NAME}.tmp"
    tmp.write_text(json.dumps(marker, indent=2), encoding="utf-8")
    os.replace(tmp, state_dir / READY_NAME)
    return marker


def _verify(marker: dict, state_dir: Path) -> dict:
    vectors = state_dir / "vectors.json"
    secrets = state_dir / "secrets.json"
    problems = []
    for name, key in ((vectors, "vectors_sha256"),
                      (secrets, "secrets_sha256")):
        if not name.is_file():
            problems.append(f"missing:{name.name}")
            continue
        if _sha256(name) != marker.get(key):
            problems.append(f"hash_mismatch:{name.name}")
    if problems:
        raise StateNotReady("perf-state hash mismatch: "
                            + ";".join(problems))
    return marker


def wait_ready(state_dir, run_id: str = "",
               timeout_s: float = DEFAULT_TIMEOUT_S,
               poll_s: float = 0.5) -> dict:
    """Wait for a marker matching run_id, then verify content hashes.

    A marker whose run_id differs belongs to another point — it is
    ignored (and will fail the timeout rather than be consumed). When
    run_id is empty any marker is accepted (non-tagged harnesses).
    """
    state_dir = Path(state_dir)
    deadline = time.time() + timeout_s
    seen_stale = False
    while True:
        mp = marker_path(state_dir)
        if mp.is_file():
            try:
                marker = json.loads(mp.read_text())
            except (OSError, json.JSONDecodeError):
                marker = None
            if isinstance(marker, dict):
                if not run_id or marker.get("run_id") == run_id:
                    out = _verify(marker, state_dir)
                    out["validated_at"] = round(time.time(), 3)
                    return out
                seen_stale = True
        if time.time() >= deadline:
            detail = ("stale run_id marker only" if seen_stale
                      else "no marker")
            raise StateNotReady(
                f"SIDECAR_STATE_NOT_READY: {detail} in {state_dir} "
                f"after {timeout_s}s")
        time.sleep(poll_s)
