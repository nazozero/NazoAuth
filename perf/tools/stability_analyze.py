#!/usr/bin/env python3
"""30-minute 3000/s stability analysis for the F3000-30M point.

Offline-computable: consumes the point directory's recorded streams
(k6 metrics, soak sampler, residency observer, proc detail, run.log)
and produces the per-minute diagnostic table, SUSTAINED_CLIFF
classification, per-checkpoint correlation windows, and generator
resource evidence. It never redefines the whole-window formal gate —
the minute buckets are explanatory diagnostics only.

SUSTAINED_CLIFF (pre-registered, any of):
  A. any 5 consecutive 60s buckets where >=4 have p95>100ms or
     p99>250ms;
  B. any 5 consecutive minutes with pool waiting mean > 500 AND
     checked_out mean >= 31;
  C. any 5 consecutive minutes with measured completion rate < 2850/s
     (diagnostic cliff threshold, NOT the formal 99.5% gate).
"""
import json
import math
import re
import sys
from pathlib import Path

BUCKET_MS = 60_000
CLIFF_SPAN = 5          # consecutive minutes
CLIFF_MIN_BAD = 4       # of 5 buckets breaching latency
P95_GATE_MS = 100
P99_GATE_MS = 250
POOL_WAIT_MEAN_CLIFF = 500
CHECKED_OUT_MEAN_CLIFF = 31
RATE_CLIFF_OPS_S = 2850
REAUTH_BUCKET_LIMIT = 500   # per-minute expired_reauth herd detector


def _jload(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _jsonl(p: Path) -> list[dict]:
    try:
        return [json.loads(l) for l in p.read_text().splitlines()
                if l.strip()]
    except OSError:
        return []


def _cnt(metrics: dict, name: str) -> int:
    e = metrics.get(name, {})
    vals = e.get("values", e) if isinstance(e, dict) else {}
    return int(vals.get("count", 0) or 0)


def _lat(metrics: dict, name: str, pct: str):
    e = metrics.get(name, {})
    vals = e.get("values", e) if isinstance(e, dict) else {}
    v = vals.get(pct)
    return float(v) if isinstance(v, (int, float)) else None


def _bucket_index(ts_ms: float, window_start_ms: float,
                  bucket_ms: int = BUCKET_MS) -> int:
    return int((ts_ms - window_start_ms) // bucket_ms) + 1


# ---------------------------------------------------------------------
# Source extraction
# ---------------------------------------------------------------------

def k6_buckets(metrics: dict, window_s: float,
               bucket_ms: int = BUCKET_MS) -> dict[int, dict]:
    """Per-minute measurement buckets from cap_m{i}_* metrics."""
    n_buckets = int(math.ceil(window_s * 1000 / bucket_ms))
    out = {}
    for i in range(1, n_buckets + 2):  # +1 overflow bucket
        ops = _cnt(metrics, f"cap_m{i}_ops")
        beg = _cnt(metrics, f"cap_m{i}_iter_begin")
        if not ops and not beg:
            continue
        span_s = min(bucket_ms, window_s * 1000
                     - (i - 1) * bucket_ms) / 1000.0
        out[i] = {
            "bucket": i,
            "span_s": round(span_s, 3),
            "scheduled": int(3000 * span_s),
            "began": beg,
            "ops": ops,
            "ops_per_s": round(ops / span_s, 1) if span_s else None,
            "errors": _cnt(metrics, f"cap_m{i}_errors"),
            "p50": _lat(metrics, f"cap_m{i}_ms", "med"),
            "p95": _lat(metrics, f"cap_m{i}_ms", "p(95)"),
            "p99": _lat(metrics, f"cap_m{i}_ms", "p(99)"),
            "subject_initial_mint": _cnt(
                metrics, f"cap_m{i}_subject_initial_mint"),
            "subject_refresh_update": _cnt(
                metrics, f"cap_m{i}_subject_refresh_update"),
            "subject_expired_reauth": _cnt(
                metrics, f"cap_m{i}_subject_expired_reauth"),
        }
    return out


def checkpoint_events(soak_rows: list[dict]) -> list[dict]:
    """Per-checkpoint deltas from cumulative pg_stat_checkpointer
    counters. Start boundary: the sample where num_timed/num_requested
    first increments; completion: where num_done increments and the
    write/sync/buffers deltas land (PG records them at completion)."""
    rows = [r for r in soak_rows
            if r.get("kind") != "meta" and r.get("checkpoints")]
    events = []
    open_evt = None
    prev = None
    prev_ts = None
    for r in rows:
        c = r["checkpoints"]
        if prev is not None:
            started = (c.get("timed", 0) > prev.get("timed", 0)
                       or c.get("requested", 0) > prev.get("requested", 0))
            done = c.get("done", 0) > prev.get("done", 0)
            if started and open_evt is None:
                # the checkpoint began somewhere inside the sampling
                # interval: prev_ts <= start <= r.ts
                open_evt = {"start_ts": prev_ts,
                            "start_observed_ts": r["ts"],
                            "kind":
                            "timed" if c.get("timed", 0)
                            > prev.get("timed", 0) else "requested"}
            if done:
                ev = dict(open_evt or {})
                ev.setdefault("start_ts", None)
                ev.update({
                    "end_ts": r["ts"],
                    "done_delta": c["done"] - prev["done"],
                    "write_time_ms_delta":
                        c.get("write_time_ms", 0)
                        - prev.get("write_time_ms", 0),
                    "sync_time_ms_delta":
                        c.get("sync_time_ms", 0)
                        - prev.get("sync_time_ms", 0),
                    "buffers_written_delta":
                        c.get("buffers_written", 0)
                        - prev.get("buffers_written", 0),
                })
                events.append(ev)
                open_evt = None
        prev = c
        prev_ts = r["ts"]
    if open_evt is not None:
        open_evt["incomplete"] = True
        events.append(open_evt)
    return events


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    vs = sorted(values)
    k = min(len(vs) - 1, max(0, int(math.ceil(q * len(vs))) - 1))
    return vs[k]


def active_vu_series(log_text: str, window: tuple[float, float]
                     ) -> dict:
    """Parse `running (MMmSS.Ss), NNNN/MAX VUs` progress lines into a
    measurement-window active-VU series."""
    series = []
    for m in re.finditer(
            r"running \((\d+)m([\d.]+)s\),\s*(\d+)/(\d+) VUs", log_text):
        t = float(m.group(1)) * 60 + float(m.group(2))
        v = int(m.group(3))
        series.append((t, v))
    lo, hi = window
    win = [v for t, v in series if lo <= t < hi]
    return {
        "samples": len(win),
        "mean": round(sum(win) / len(win), 1) if win else None,
        "p95": _pct([float(v) for v in win], 0.95),
        "max": max(win) if win else None,
        "first300s_max": max((v for t, v in series if t < 300),
                             default=None),
    }


def per_bucket_pool(residency_rows: list[dict], window_start_s: float,
                    n_buckets: int) -> dict[int, dict]:
    """Pool waiting/checked_out means+maxima per minute bucket from the
    250ms residency observer stream."""
    acc: dict[int, dict[str, list]] = {}
    for r in residency_rows:
        if r.get("kind") != "sample" or not r.get("pool"):
            continue
        i = _bucket_index(r["ts"] * 1000, window_start_s * 1000)
        if i < 1 or i > n_buckets:
            continue
        b = acc.setdefault(i, {"waiting": [], "checked": []})
        p = r["pool"]
        b["waiting"].append(float(p.get("waiting", 0) or 0))
        con = p.get("con", p.get("size", 0)) or 0
        idle = p.get("idle", 0) or 0
        b["checked"].append(float(con) - float(idle))
    return {
        i: {"waiting_mean": round(sum(v["waiting"]) / len(v["waiting"]), 1),
            "waiting_max": max(v["waiting"]),
            "checked_out_mean": round(sum(v["checked"])
                                      / len(v["checked"]), 1),
            "checked_out_max": max(v["checked"])}
        for i, v in acc.items() if v["waiting"]
    }


def per_bucket_wal(residency_rows: list[dict], window_start_s: float,
                   n_buckets: int) -> dict[int, dict]:
    """WAL wait share among active backends + active count per bucket."""
    acc: dict[int, dict[str, int]] = {}
    for r in residency_rows:
        if r.get("kind") != "sample":
            continue
        i = _bucket_index(r["ts"] * 1000, window_start_s * 1000)
        if i < 1 or i > n_buckets:
            continue
        b = acc.setdefault(i, {"active": 0, "wal": 0})
        for be in r.get("backends", []):
            if be.get("state") == "active":
                b["active"] += 1
                if "wal" in str(be.get("we") or "").lower():
                    b["wal"] += 1
    return {
        i: {"active_mean": round(v["active"] / max(
                sum(1 for r in residency_rows
                    if r.get("kind") == "sample"
                    and _bucket_index(r["ts"] * 1000,
                                      window_start_s * 1000) == i), 1), 2),
            "wal_share": round(v["wal"] / v["active"], 3)
            if v["active"] else None}
        for i, v in acc.items()
    }


def per_bucket_ckpt(soak_rows: list[dict], window_start_s: float,
                    n_buckets: int) -> dict[int, dict]:
    """pg_stat_checkpointer cumulative-counter deltas per bucket."""
    rows = [r for r in soak_rows
            if r.get("kind") != "meta" and r.get("checkpoints")]
    out: dict[int, dict] = {}
    prev = None
    for r in rows:
        c = r["checkpoints"]
        i = _bucket_index(r["ts"] * 1000, window_start_s * 1000)
        if prev is not None and 1 <= i <= n_buckets:
            b = out.setdefault(i, {"num_done": 0, "write_time_ms": 0.0,
                                   "sync_time_ms": 0.0,
                                   "buffers_written": 0})
            b["num_done"] += c.get("done", 0) - prev.get("done", 0)
            b["write_time_ms"] += (c.get("write_time_ms", 0)
                                   - prev.get("write_time_ms", 0))
            b["sync_time_ms"] += (c.get("sync_time_ms", 0)
                                  - prev.get("sync_time_ms", 0))
            b["buffers_written"] += (c.get("buffers_written", 0)
                                     - prev.get("buffers_written", 0))
        prev = c
    return out


# ---------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------

def sustained_cliff(buckets: dict[int, dict],
                    pool: dict[int, dict]) -> dict:
    """Pre-registered 5-consecutive-minute cliff detector."""
    ids = sorted(buckets)
    triggers = []
    for w in range(len(ids) - CLIFF_SPAN + 1):
        win = ids[w:w + CLIFF_SPAN]
        if len(win) < CLIFF_SPAN:
            break
        bad_lat = sum(
            1 for i in win
            if (buckets[i]["p95"] is not None
                and buckets[i]["p95"] > P95_GATE_MS)
            or (buckets[i]["p99"] is not None
                and buckets[i]["p99"] > P99_GATE_MS))
        if bad_lat >= CLIFF_MIN_BAD:
            triggers.append({"rule": "A_latency", "buckets": win,
                             "bad_buckets": bad_lat})
        pool_ok = all(i in pool for i in win)
        if pool_ok and all(
                pool[i]["waiting_mean"] > POOL_WAIT_MEAN_CLIFF
                and pool[i]["checked_out_mean"] >= CHECKED_OUT_MEAN_CLIFF
                for i in win):
            triggers.append({"rule": "B_pool_exhaustion",
                             "buckets": win})
        if all(buckets[i]["ops_per_s"] is not None
               and buckets[i]["ops_per_s"] < RATE_CLIFF_OPS_S
               for i in win):
            triggers.append({"rule": "C_rate_under_2850",
                             "buckets": win})
    return {"sustained_cliff": bool(triggers), "triggers": triggers}


def anomaly_buckets(buckets: dict[int, dict],
                    ckpt_windows: list[tuple[float, float]]) -> list:
    """Every minute bucket breaching the latency gates, flagged for
    checkpoint-write-window overlap (correlation, not causation)."""
    out = []
    for i, b in sorted(buckets.items()):
        if ((b["p95"] is not None and b["p95"] > P95_GATE_MS)
                or (b["p99"] is not None and b["p99"] > P99_GATE_MS)):
            out.append({**b,
                        "in_checkpoint_write_window": any(
                            lo <= i * BUCKET_MS / 1000 <= hi or
                            lo <= (i - 1) * BUCKET_MS / 1000 <= hi or
                            (i - 1) * BUCKET_MS / 1000 <= lo <= i
                            * BUCKET_MS / 1000
                            for lo, hi in ckpt_windows)})
    return out


def reauth_herd(buckets: dict[int, dict]) -> dict:
    peak = max((b["subject_expired_reauth"] for b in buckets.values()),
               default=0)
    return {"max_per_minute": peak,
            "herd": peak > REAUTH_BUCKET_LIMIT}


# ---------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------

def analyze(point_dir: Path, window_start_s: float, window_s: float,
            run_log: str | None = None) -> dict:
    """point_dir: the F3000-30M point directory containing load/,
    soak-metrics.jsonl, residency.jsonl, proc-detail.jsonl.
    window_start_s/window_s: measurement window bounds on the soak
    sampler's epoch-second axis."""
    point_dir = Path(point_dir)
    k6j = next((point_dir / "load").glob("*.k6.json"), None)
    metrics = (_jload(k6j) or {}).get("metrics", {}) if k6j else {}
    n_buckets = int(math.ceil(window_s * 1000 / BUCKET_MS))

    buckets = k6_buckets(metrics, window_s)
    soak = _jsonl(point_dir / "soak-metrics.jsonl")
    residency = _jsonl(point_dir / "residency.jsonl")
    pool = per_bucket_pool(residency, window_start_s, n_buckets)
    wal = per_bucket_wal(residency, window_start_s, n_buckets)
    ckpt_b = per_bucket_ckpt(soak, window_start_s, n_buckets)
    ckpt_events = checkpoint_events(soak)
    ckpt_windows = [(e["start_ts"], e["end_ts"]) for e in ckpt_events
                    if e.get("start_ts") and e.get("end_ts")]
    ckpt_windows_rel = [(lo - window_start_s, hi - window_start_s)
                        for lo, hi in ckpt_windows]

    for i, b in buckets.items():
        if i in pool:
            b["pool"] = pool[i]
        if i in wal:
            b["wal"] = wal[i]
        if i in ckpt_b:
            b["checkpoint"] = ckpt_b[i]

    if run_log is None:
        rl = point_dir / "load" / "run.log"
        run_log = rl.read_text(errors="replace") if rl.exists() else ""
    # k6 progress clock is scenario-relative: measurement starts 15s in.
    vu = active_vu_series(run_log, (15.0, 15.0 + window_s))

    proc = _jsonl(point_dir / "proc-detail.jsonl")
    k6_key = next((k for r in proc for k in r
                   if str(k).startswith("sis-load-")), None)
    rss, cpu = [], []
    prev = None
    for r in proc:
        e = r.get(k6_key) if k6_key else None
        if not e:
            continue
        rss.append((e.get("rss_kb") or 0) / 1048576)
        if prev and r["ts"] > prev["ts"]:
            dj = e.get("total_jif", 0) - prev["e"].get("total_jif", 0)
            dt = r["ts"] - prev["ts"]
            c = dj / dt / 100
            if 0 <= c < 64:
                cpu.append(c)
        prev = {"ts": r["ts"], "e": e}
    memavail = [r["host_mem_kb"]["MemAvailable"] / 1048576
                for r in proc
                if isinstance(r.get("host_mem_kb"), dict)
                and r["host_mem_kb"].get("MemAvailable")]

    cliff = sustained_cliff(buckets, pool)
    return {
        "buckets": [buckets[i] for i in sorted(buckets)],
        "sustained_cliff": cliff,
        "anomaly_buckets": anomaly_buckets(buckets, ckpt_windows_rel),
        "reauth_herd": reauth_herd(buckets),
        "checkpoint_events": ckpt_events,
        "active_vu": vu,
        "generator": {
            "rss_gib_avg": round(sum(rss) / len(rss), 2) if rss else None,
            "rss_gib_max": round(max(rss), 2) if rss else None,
            "cpu_cores_avg": (round(sum(cpu) / len(cpu), 2)
                              if cpu else None),
            "cpu_cores_max": round(max(cpu), 2) if cpu else None,
        },
        "host_mem_available_gib_min": (round(min(memavail), 2)
                                       if memavail else None),
    }


def main(argv: list[str]) -> int:
    point_dir = Path(argv[1])
    ws = float(argv[2])
    wsec = float(argv[3])
    print(json.dumps(analyze(point_dir, ws, wsec), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
