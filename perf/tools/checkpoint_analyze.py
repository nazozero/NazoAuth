#!/usr/bin/env python3
"""Checkpoint-jitter evidence analyzer (repaired revision 2).

Two modes:

  stream   Consume k6 JSON points on stdin. Never persists raw per-request
           rows: emits (a) a bounded per-second aggregate series, (b) a
           filtered diag.jsonl.gz containing contract/iteration/http-error
           points plus a capped sample of request metrics, (c) a window
           contract validity file, (d) analyzer self-stats. Memory stays
           bounded regardless of run length.

  report   Join the per-second series with the observer JSONL, the
           postgres checkpoint log and the soak config. Emits
           measurement-reconciliation, checkpoint-windows, wal-envelope,
           steady-state, analysis-validity and a per-second timeline CSV.

Revision-2 corrections over revision-1:
  * The all-load common window is intersected from each load's actual
    scenario measurement window (contract metrics), never from shell or
    container lifecycle timestamps. Loads without recoverable scenario
    bounds contribute only conservative container-derived bounds and the
    resulting window is labelled accordingly.
  * One shared bin-selection policy (effective_bins) feeds expected ops,
    begins, completions, outcomes, drops, histograms, minima, hole areas
    and in-flight reconstruction — no metric may pick bins differently.
    Requested vs effective intervals are both reported; boundary bins are
    never proportionally allocated.
  * Each checkpoint keeps a stable id and its own local window; the union
    is used only for de-duplication and steady-state exclusion. Truncated
    windows carry explicit truncation/coverage/missing-boundary fields and
    the terminal drain artifact is never reported as a normal trough.
  * Recovery is computed per deficit episode from the episode start, and
    the 5 consecutive qualifying bins must be real adjacent covered
    seconds — missing bins break consecutiveness.
  * WAL segments break on stats_reset change, counter regression or source
    identity change even when the new counter exceeds the old one; rolling
    peaks are time windows, not sample counts; the mean is time-weighted.
  * Histogram quantiles report the containing bucket interval plus an
    explicitly-flagged midpoint estimate; they are never presented as
    exact values. Raw-sample quantiles (sample_quantile) remain exact.
  * Analyzer health (parse errors, reader errors, missing required input)
    propagates into validity; nothing emits a clean verdict on bad input.

Stdlib only; compatible with the perf image python.
"""
from __future__ import annotations

import csv
import gzip
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

# ----------------------------- tuning constants ----------------------------
OUT_NAME = "capacity-cap-mixed"
OUTCOME_KEYS = ("success", "expected_rejection", "local_no_request",
                "unexpected", "prepare_failed", "prepare_local_failed",
                "prepare_sut_failed")
# Three evidence tiers (kept explicit — see report and tests):
#   A. AUTHORITATIVE  — series.json / window.json / k6 summary: every
#      counted formal fact (begins/ends/drops/outcomes/latency aggregates
#      by second and cohort). Formal verdicts read ONLY this tier.
#   B. SYSTEM HEALTH  — residency/soak/proc-detail/audit/sidecar evidence
#      collected outside this file.
#   C. FORENSIC       — diag.jsonl.gz: bounded sampled point log for
#      manual debugging. Its completeness NEVER feeds a formal gate.
# Per-op metrics (cap_iter_begin/cap_iter_end/iterations/data_*) are the
# dominant point volume and are already exhaustively counted in tier A —
# diag keeps only sampled copies for forensic value, not every row.
# Contract/window points, drops, failures and slow tails stay unconditional.
KEEP_ALWAYS = {"http_req_failed", "vus", "vus_max", "dropped_iterations"}
KEEP_PREFIX = ("cap_window_",)
SAMPLE_EVERY = 64          # keep 1-in-N per metric-second for high-volume mets
TAIL_MS = 500.0            # always keep individual slow ops/requests
BUDGET_PER_METRIC_SEC = 8
MAX_DIAG_BYTES = 512 * 1024 * 1024   # hard cap on the gzip stream
# Consumer-lag signal: the point stream drains through a FIFO, so a slow
# analyzer mechanically backpressures k6's output writer. This is an
# evidence-pipeline integrity signal (never a generator-resource one).
LAG_INVALID_S = 5.0
# Drops observed before the window contract resolves are buffered, not
# dropped silently: the bound keeps a broken contract from growing memory
# without limit, and overflow is a hard accounting-invalid signal.
MAX_PENDING_DROPS = 100_000


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def parse_iso_ts(s: str) -> float | None:
    try:
        return datetime.fromisoformat(
            s.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


# ----------------------------- histograms ----------------------------------
# stream-v1 histogram schema — the on-disk bucket layout is part of the
# artifact contract and does not change: bucket i counts values with
# `v < bounds[i]` and covers [bounds[i-1], bounds[i]) (lower-inclusive,
# upper-exclusive); the last slot is the overflow bucket [bounds[-1], ∞).
# New output keeps this schema; report mode reads the schema declared by
# the artifact itself and never reinterprets foreign buckets with local
# defaults.
BUCKETS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
HISTOGRAM_SCHEMA = {"version": "stream-v1", "bounds_ms": BUCKETS,
                    "upper_inclusive": False}


def new_hist() -> dict:
    return {"n": 0, "sum": 0.0, "min": None, "max": None,
            "b": [0] * (len(BUCKETS) + 1)}


def hist_add(h: dict, v: float) -> None:
    h["n"] += 1
    h["sum"] = h.get("sum", 0.0) + v
    h["min"] = v if h.get("min") is None else min(h["min"], v)
    h["max"] = v if h.get("max") is None else max(h["max"], v)
    for i, bound in enumerate(BUCKETS):
        if v < bound:
            h["b"][i] += 1
            return
    h["b"][-1] += 1


def hist_merge(a: dict | None, b: dict | None) -> dict:
    if not a or not a.get("n"):
        return dict(b) if b else new_hist()
    if not b or not b.get("n"):
        return dict(a)
    mins = [x for x in (a.get("min"), b.get("min")) if x is not None]
    return {"n": a["n"] + b["n"],
            "sum": a.get("sum", 0.0) + b.get("sum", 0.0),
            "min": min(mins) if mins else None,
            "max": max(x for x in (a.get("max"), b.get("max"))
                       if x is not None),
            "b": [x + y for x, y in zip(a["b"], b["b"])]}


def resolve_hist_schema(series: dict) -> dict | None:
    """Histogram schema of a persisted series artifact.

    Trusted declarations, in order: an explicit `histogram_schema` block,
    else the stream-v1 pair `generator=checkpoint_analyze.stream-v1` +
    `hist_bounds_ms` (known `< bound` semantics). Anything else means the
    bucket semantics are unknown — quantiles must come out unavailable,
    never guessed against local defaults."""
    hs = series.get("histogram_schema")
    if isinstance(hs, dict) and isinstance(hs.get("bounds_ms"), list):
        return {"version": hs.get("version") or "declared",
                "bounds": [float(x) for x in hs["bounds_ms"]],
                "upper_inclusive": bool(hs.get("upper_inclusive"))}
    if (series.get("generator") == "checkpoint_analyze.stream-v1"
            and isinstance(series.get("hist_bounds_ms"), list)):
        return {"version": "stream-v1",
                "bounds": [float(x) for x in series["hist_bounds_ms"]],
                "upper_inclusive": False}
    return None


def _quantile_interval(h: dict, q: float, schema: dict) -> dict:
    """Bucketed quantile: the honest answer is the bucket interval whose
    cumulative count first reaches q*n. For stream-v1 (`v < bound`) that
    interval is [prev, bound); for an upper-inclusive schema it is
    (prev, bound]. The midpoint estimate is flagged — never report it as
    an exact quantile."""
    bounds = schema["bounds"]
    upper_inc = schema["upper_inclusive"]
    n = h["n"]
    target = q * n
    cum = 0
    for i, bound in enumerate(bounds):
        cum += h["b"][i]
        if cum >= target:
            lo = bounds[i - 1] if i else 0.0
            return {"interval_ms": [lo, bound],
                    "interval_semantics": "[lo,hi)" if not upper_inc
                    else "(lo,hi]",
                    "estimate_ms": round((lo + bound) / 2, 3),
                    "estimate": True, "bucket": i}
    return {"interval_ms": [bounds[-1], None],
            "interval_semantics": "[lo,inf)",
            "estimate_ms": None, "estimate": True,
            "bucket": len(bounds), "overflow": True}


def hist_stats(h: dict, schema: dict | None) -> dict:
    """Quantile stats with explicit intervals. `p95.interval_ms` is the
    bucket interval containing the true p95 under the artifact's own
    schema; `estimate_ms` is a flagged midpoint. Unknown schema -> the
    quantiles are reported unavailable, never guessed."""
    if not h["n"]:
        return {"n": 0}
    out = {"n": h["n"], "min": h.get("min"), "max": h.get("max"),
           "mean": round(h.get("sum", 0.0) / h["n"], 3) or None}
    bounds = (schema.get("bounds") or schema.get("bounds_ms")
              if schema else None)
    if bounds is None or len(h.get("b") or []) != len(bounds) + 1:
        unknown = {"unavailable": "histogram schema unknown or bucket "
                                "count does not match declared bounds"}
        out["p50"] = out["p95"] = out["p99"] = unknown
        return out
    out["histogram_schema"] = schema.get("version")
    norm = {"bounds": bounds,
            "upper_inclusive": schema.get("upper_inclusive", False)}
    out["p50"] = _quantile_interval(h, 0.50, norm)
    out["p95"] = _quantile_interval(h, 0.95, norm)
    out["p99"] = _quantile_interval(h, 0.99, norm)
    return out


def sample_quantile(samples: list[float], q: float) -> float | None:
    """Exact quantile for a raw sample list (nearest-rank). Only usable when
    the caller actually holds the raw samples — not a histogram."""
    if not samples:
        return None
    s = sorted(samples)
    return s[min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))]


# --------------------------- contract handling -----------------------------
CONTRACT_FIELDS = ("scenario_start_ms", "measure_start_ms", "measure_end_ms",
                   "duration_ms", "measure_offset_ms", "bucket_ms",
                   "bucket_count", "clock_ok")
# Fields whose absence makes the measurement bounds themselves unrecoverable.
CONTRACT_BOUNDS_FIELDS = ("scenario_start_ms", "measure_start_ms",
                          "measure_end_ms", "duration_ms")


def contract_from_summary(metrics: dict) -> dict:
    """Reconstruct the scenario-window contract from named cap_window_*
    gauges in a k6 summary-export metrics dict.

    A field present with divergent min/max means VUs disagreed — the
    contract is invalid, never silently averaged. Missing BOUNDS fields
    make the window unrecoverable; missing annotation fields (offset,
    bucket hints) are recorded as defects but do not destroy bounds that
    are present and consistent."""
    problems: list[str] = []
    c: dict = {}
    for name in CONTRACT_FIELDS:
        ent = metrics.get(f"cap_window_{name}")
        if not isinstance(ent, dict):
            problems.append(f"missing:cap_window_{name}")
            continue
        v = ent.get("values", ent)
        lo, hi = v.get("min"), v.get("max")
        val = v.get("value", lo)
        if lo is None or hi is None or val is None:
            problems.append(f"null:cap_window_{name}")
            continue
        c[name] = val
        if lo != hi:
            problems.append(f"divergent:cap_window_{name} min={lo} max={hi}")
    divergent = any(p.startswith("divergent:") for p in problems)
    bounds_ok = (all(f in c for f in CONTRACT_BOUNDS_FIELDS)
                 and not divergent)
    if bounds_ok and c["measure_start_ms"] >= c["measure_end_ms"]:
        problems.append("measure_start_ms>=measure_end_ms")
        bounds_ok = False
    if c.get("clock_ok") != 1:
        problems.append("scenario_clock_ok!=1")
        bounds_ok = False
    # Defects: problems that do not destroy the bounds themselves (missing
    # annotation fields like measure_offset_ms). Bounds/divergence/clock
    # problems are fatal to validity, not mere defects.
    fatal = (f"cap_window_{f}" for f in CONTRACT_BOUNDS_FIELDS)
    defects = [p for p in problems
               if not any(f in p for f in fatal)
               and p != "measure_start_ms>=measure_end_ms"
               and not p.startswith("scenario_clock_ok")
               and not p.startswith("divergent:")]
    out = {
        "contract": "cap-scenario-window-v1",
        "scenario_start_ms": c.get("scenario_start_ms"),
        "window_start_ms": c.get("measure_start_ms"),
        "window_end_ms": c.get("measure_end_ms"),
        "duration_ms": c.get("duration_ms"),
        "measure_offset_ms": c.get("measure_offset_ms"),
        "warmup_ms": c.get("measure_offset_ms"),
        "bucket_ms": c.get("bucket_ms"),
        "bucket_count": c.get("bucket_count"),
        "window_seconds": (
            round((c["measure_end_ms"] - c["measure_start_ms"]) / 1000.0, 3)
            if bounds_ok else None),
        "scenario_clock_ok": c.get("clock_ok"),
        "divergent_vus": divergent,
        "problems": problems,
        "defects": defects,
        # valid -> the measurement window itself is usable; `complete`
        # additionally requires every annotation field present.
        "valid": bounds_ok,
        "complete": not problems,
    }
    return out


# --------------------------- stream analyzer -------------------------------
class StreamingSeries:
    """Bounded per-second aggregates over the k6 JSON point stream."""

    def __init__(self) -> None:
        self.bins: dict[int, dict] = {}
        self.contract_vals: dict[str, set] = defaultdict(set)
        self.vu_ids: set = set()
        self.points = 0
        self.parse_errors = 0
        self.reader_error: str | None = None
        self.lag_max_s = 0.0
        self.lag_over_5s = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.diag_budget_exceeded = 0
        self.diag_overflow_dropped = 0
        self._kept_per_ms: dict[tuple, int] = defaultdict(int)
        self._seq_per_ms: dict[tuple, int] = defaultdict(int)
        self._diag_bytes = 0
        self.diag_overflow = False
        self.diag_fh = None
        # Stream-authoritative measurement cohort: exact begin/end/drop
        # counts observed on the point stream, classified against the
        # emitted window contract. The theoretical arrival grid is a
        # diagnostic only — never the drop source of truth.
        self.measure_begins = 0
        self.measure_ends = 0
        self.measure_outcomes: dict[str, int] = defaultdict(int)
        self.drop_pre_window = 0
        self.drop_in_window = 0
        self.drop_post_window = 0
        self._pending_drops: list[tuple[float, int]] = []
        self.pending_drops_overflow = False
        self._window_bounds_s: tuple[float, float] | None = None
        self._contract_divergent = False

    def _maybe_resolve_window(self) -> None:
        """Resolve [window_start_s, window_end_s) once both bounds carry a
        single agreed value. Divergence is terminal — buffered drops are
        reported unclassified rather than guessed."""
        if self._window_bounds_s is not None or self._contract_divergent:
            return
        s = self.contract_vals.get("measure_start_ms")
        e = self.contract_vals.get("measure_end_ms")
        if not s or not e:
            return
        if len(s) > 1 or len(e) > 1:
            self._contract_divergent = True
            return
        self._window_bounds_s = (next(iter(s)) / 1000.0,
                                 next(iter(e)) / 1000.0)
        for ts, n in self._pending_drops:
            self._classify_drop_resolved(ts, n)
        self._pending_drops.clear()

    def _classify_drop_resolved(self, ts: float, n: int) -> None:
        ws, we = self._window_bounds_s
        if ts < ws:
            self.drop_pre_window += n
        elif ts >= we:
            self.drop_post_window += n
        else:
            self.drop_in_window += n

    def _classify_drop(self, ts: float, value: float) -> None:
        n = int(value)
        if self._window_bounds_s is None:
            if len(self._pending_drops) >= MAX_PENDING_DROPS:
                self.pending_drops_overflow = True
                return
            self._pending_drops.append((ts, n))
            return
        self._classify_drop_resolved(ts, n)

    # -- per-second bin ------------------------------------------------------
    def bin(self, ts: float) -> dict:
        sec = int(ts)
        b = self.bins.get(sec)
        if b is None:
            b = self.bins[sec] = {
                "begins": defaultdict(int),       # cohort -> n
                "begins_pair": defaultdict(int),  # "cohort|lw" -> n
                "ends": defaultdict(int),         # "cohort|lw|outcome" -> n
                "iterations": 0, "dropped": 0,
                "vus": 0, "vus_max": 0,
                "http_reqs": 0, "http_req_failed": 0,
                "data_received": 0, "data_sent": 0,
                "cap_measure_ms": new_hist(),
                "cap_iter_ms": new_hist(),
                "http_req_duration": new_hist(),
            }
        return b

    def _keep_diag(self, metric: str, ts: float, value: float,
                   line: str) -> bool:
        if self.diag_fh is None:
            return False
        if self.diag_overflow:
            # Points rejected because the artifact already hit its byte
            # cap — the true truncation volume (budget rejects and
            # overflow rejects are different things).
            self.diag_overflow_dropped += 1
            return False
        sec = int(ts)
        key = (metric, sec)
        self._seq_per_ms[key] += 1
        seq = self._seq_per_ms[key]
        keep = (
            metric in KEEP_ALWAYS
            or metric.startswith(KEEP_PREFIX)
            or value >= TAIL_MS
            or seq % SAMPLE_EVERY == 0
            or self._kept_per_ms[key] < BUDGET_PER_METRIC_SEC
        )
        if not keep:
            self.diag_budget_exceeded += 1
            return False
        self._kept_per_ms[key] += 1
        self._diag_bytes += len(line)
        if self._diag_bytes > MAX_DIAG_BYTES:
            self.diag_overflow = True
            return False
        self.diag_fh.write(line if line.endswith("\n") else line + "\n")
        return True

    def on_point(self, obj: dict, raw: str) -> None:
        data = obj.get("data", obj)
        metric = data.get("metric") or obj.get("metric")
        ts = parse_iso_ts(data.get("time") or "")
        value = data.get("value")
        tags = data.get("tags") or {}
        if metric is None or ts is None or value is None:
            self.parse_errors += 1
            return
        self.points += 1
        # Consumer lag: wall-clock now vs the point's k6-side emission
        # timestamp. A positive value means the analyzer is draining the
        # FIFO behind the producer — the write side can block once the
        # pipe buffer fills. Recorded, never part of cohort accounting.
        lag = time_now() - ts
        if lag > self.lag_max_s:
            self.lag_max_s = lag
        if lag > LAG_INVALID_S:
            self.lag_over_5s += 1
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        vu = tags.get("vu")
        if vu is not None:
            self.vu_ids.add(vu)

        if metric.startswith("cap_window_"):
            self.contract_vals[metric[len("cap_window_"):]].add(value)
            self._maybe_resolve_window()
            self._keep_diag(metric, ts, value, raw)
            return
        if metric == "cap_iter_begin":
            b = self.bin(ts)
            cohort = tags.get("cohort", "?")
            lw = tags.get("lw", "?")
            b["begins"][cohort] += 1
            b["begins_pair"][f"{cohort}|{lw}"] += 1
            if cohort == "measure":
                self.measure_begins += int(value)
            self._keep_diag(metric, ts, value, raw)
            return
        if metric == "cap_iter_end":
            b = self.bin(ts)
            cohort = tags.get("cohort", "?")
            lw = tags.get("lw", "?")
            outcome = tags.get("outcome", "?")
            b["ends"][f"{cohort}|{lw}|{outcome}"] += 1
            if cohort == "measure":
                self.measure_ends += int(value)
                self.measure_outcomes[outcome] += int(value)
            self._keep_diag(metric, ts, value, raw)
            return
        b = self.bin(ts)
        if metric == "iterations":
            b["iterations"] += int(value)
        elif metric == "dropped_iterations":
            b["dropped"] += int(value)
            self._classify_drop(ts, value)
        elif metric == "vus":
            b["vus"] = max(b["vus"], int(value))
        elif metric == "vus_max":
            b["vus_max"] = max(b["vus_max"], int(value))
        elif metric == "http_reqs":
            b["http_reqs"] += int(value)
        elif metric == "http_req_failed":
            b["http_req_failed"] += int(value)
        elif metric == "data_received":
            b["data_received"] += int(value)
        elif metric == "data_sent":
            b["data_sent"] += int(value)
        elif metric == "cap_measure_ms":
            hist_add(b["cap_measure_ms"], float(value))
        elif metric == "cap_iter_ms":
            hist_add(b["cap_iter_ms"], float(value))
        elif metric == "http_req_duration":
            hist_add(b["http_req_duration"], float(value))
        self._keep_diag(metric, ts, float(value), raw)

    def finalize_bins(self) -> dict:
        out = {}
        for sec, b in sorted(self.bins.items()):
            out[str(sec)] = {
                "begins": dict(b["begins"]),
                "begins_pair": dict(b["begins_pair"]),
                "ends": dict(b["ends"]),
                "iterations": b["iterations"], "dropped": b["dropped"],
                "vus": b["vus"], "vus_max": b["vus_max"],
                "http_reqs": b["http_reqs"],
                "http_req_failed": b["http_req_failed"],
                "data_received": b["data_received"],
                "data_sent": b["data_sent"],
                "cap_measure_ms": b["cap_measure_ms"],
                "cap_iter_ms": b["cap_iter_ms"],
                "http_req_duration": b["http_req_duration"],
            }
        return out

    def emit_window(self) -> None:
        fields = {}
        for k, vals in sorted(self.contract_vals.items()):
            sv = sorted(vals)
            fields[k] = {"distinct": len(sv), "values": sv}
        problems: list[str] = []
        for f in CONTRACT_BOUNDS_FIELDS:
            if not fields.get(f, {}).get("values"):
                problems.append(f"missing:{f}")
        consistent = all(v["distinct"] <= 1 for v in fields.values())
        if not consistent:
            problems.append("divergent_fields")
        if (fields.get("measure_start_ms", {}).get("values")
                and fields.get("measure_end_ms", {}).get("values")
                and fields["measure_start_ms"]["values"][0]
                >= fields["measure_end_ms"]["values"][0]):
            problems.append("measure_start_ms>=measure_end_ms")
            consistent = False
        if self.parse_errors:
            problems.append(f"parse_errors:{self.parse_errors}")
        if self.reader_error:
            problems.append(f"reader_error:{self.reader_error}")
        clock_ok_vals = fields.get("clock_ok", {}).get("values", [])
        if clock_ok_vals != [1]:
            problems.append("scenario_clock_ok!=1")
        valid = consistent and not problems and bool(clock_ok_vals)
        # Stream-authoritative measurement cohort: exact begin/end/drop
        # counts from the point stream, classified inside [start, end).
        # The rational arrival plan is a diagnostic elsewhere — never a
        # substitute for these observed numbers.
        ws = self._window_bounds_s
        outcome_sum = sum(self.measure_outcomes.values())
        mc_problems: list[str] = []
        if ws is None:
            mc_problems.append("window_bounds_unresolved")
        if self.pending_drops_overflow:
            mc_problems.append("pending_drops_overflow")
        if self._pending_drops:
            mc_problems.append(
                f"unclassified_drops:{len(self._pending_drops)}")
        if self.measure_begins != self.measure_ends:
            mc_problems.append(
                "unfinished_measure:"
                f"{self.measure_begins - self.measure_ends}")
        if outcome_sum != self.measure_ends:
            mc_problems.append(
                f"outcome_sum_mismatch:{outcome_sum}"
                f"!={self.measure_ends}")
        scheduled_obs = self.measure_begins + self.drop_in_window
        self.window_json = {
            "contract": "cap-scenario-window-v1",
            "valid": valid,
            "consistent": consistent,
            "problems": problems,
            "fields": fields,
            "vus_seen": len(self.vu_ids),
            "points": self.points,
            "parse_errors": self.parse_errors,
            "reader_error": self.reader_error,
            "measurement_cohort": {
                "window_start_s": ws[0] if ws else None,
                "window_end_s": ws[1] if ws else None,
                "measure_started_exact": self.measure_begins,
                "measure_completed_exact": self.measure_ends,
                "measure_dropped_exact": self.drop_in_window,
                "measure_scheduled_observed": scheduled_obs,
                "measure_drop_fraction": (
                    round(self.drop_in_window / scheduled_obs, 6)
                    if scheduled_obs else None),
                "measure_outcomes": dict(self.measure_outcomes),
                "measure_outcome_sum": outcome_sum,
                "drops_pre_window": self.drop_pre_window,
                "drops_post_window": self.drop_post_window,
                "drops_pending_unclassified": len(self._pending_drops),
                "pending_drops_overflow": self.pending_drops_overflow,
                "valid": not mc_problems,
                "problems": mc_problems,
            },
        }

    def stats(self) -> dict:
        return {
            "points": self.points,
            "parse_errors": self.parse_errors,
            "reader_error": self.reader_error,
            "bins": len(self.bins),
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "first_utc": utc(self.first_ts) if self.first_ts else None,
            "last_utc": utc(self.last_ts) if self.last_ts else None,
            "vus_seen": len(self.vu_ids),
            "lag_max_s": round(self.lag_max_s, 3),
            "lag_over_5s": self.lag_over_5s,
            "diag_budget_exceeded": self.diag_budget_exceeded,
            "diag_overflow": self.diag_overflow,
            "diag_overflow_dropped": self.diag_overflow_dropped,
            "max_diag_bytes": MAX_DIAG_BYTES,
        }


def cmd_stream(args) -> int:
    series = StreamingSeries()
    diag_path = args.diag_out
    series.diag_fh = gzip.open(diag_path, "wt", encoding="utf-8")
    last_progress = time_now()
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                series.parse_errors += 1
                continue
            if obj.get("type") == "Point":
                series.on_point(obj, line)
            if time_now() - last_progress > 30:
                sys.stderr.write(
                    f"analyzer: {series.points} points, "
                    f"{len(series.bins)} bins\n")
                last_progress = time_now()
    except Exception as e:  # noqa: BLE001
        series.reader_error = f"{type(e).__name__}: {e}"
    finally:
        try:
            series.diag_fh.write(json.dumps({
                "type": "analyzer_stats",
                **series.stats(),
            }) + "\n")
            series.diag_fh.close()
        except Exception:
            pass
    series.emit_window()
    with open(args.series_out, "w", encoding="utf-8") as fh:
        json.dump({"format": "per-second-v1",
                   "generator": "checkpoint_analyze.stream-v1",
                   "hist_bounds_ms": BUCKETS,
                   "histogram_schema": HISTOGRAM_SCHEMA,
                   "bins": series.finalize_bins()}, fh)
    with open(args.window_out, "w", encoding="utf-8") as fh:
        json.dump(series.window_json, fh, indent=2)
    with open(args.stats_out, "w", encoding="utf-8") as fh:
        json.dump(series.stats(), fh, indent=2)
    return 0


def time_now() -> float:
    import time
    return time.time()


# ----------------------------- shared bin policy ---------------------------
def effective_bins(a: float, b: float, present: set[int]) -> dict:
    """The single bin-selection policy: 1-second bins [s, s+1) fully
    contained in the half-open interval [a, b).

    Returns the selected bin list, the covered subset (present in the
    series), the missing list (evidence absent — never silently zero),
    and the effective covered interval. A trailing or leading partial
    second never enters the set, so the terminal drain artifact and ragged
    boundaries cannot fabricate troughs."""
    if a is None or b is None or b <= a:
        return {"bins": [], "covered": [], "missing": [],
                "requested": [a, b], "effective": None,
                "effective_seconds": 0}
    first = int(math.ceil(a))
    secs = [s for s in range(first, int(math.floor(b))) if s + 1 <= b]
    covered = [s for s in secs if s in present]
    missing = [s for s in secs if s not in present]
    return {
        "bins": secs,
        "covered": covered,
        "missing": missing,
        "requested": [a, b],
        "effective": [secs[0], secs[-1] + 1] if secs else None,
        "effective_seconds": len(secs),
        "covered_seconds": len(covered),
    }


def bin_record(b: dict | None) -> dict | None:
    """Flatten one series bin into the fields every metric shares."""
    if b is None:
        return None
    ends = b.get("ends", {})
    return {
        "begins": sum(b.get("begins", {}).values()),
        "begins_measure": b.get("begins", {}).get("measure", 0),
        "completed": sum(ends.values()),
        "success": sum(v for k, v in ends.items()
                       if k.endswith("|success")),
        "expected_rejection": sum(v for k, v in ends.items()
                                  if k.endswith("|expected_rejection")),
        "local_no_request": sum(v for k, v in ends.items()
                                if k.endswith("|local_no_request")),
        "unexpected": sum(v for k, v in ends.items()
                          if k.endswith("|unexpected")),
        "prepare_failed": sum(v for k, v in ends.items()
                              if k.endswith("|prepare_failed")),
        "prepare_local_failed": sum(v for k, v in ends.items()
                                    if k.endswith("|prepare_local_failed")),
        "prepare_sut_failed": sum(v for k, v in ends.items()
                                  if k.endswith("|prepare_sut_failed")),
        "drops": b.get("dropped", 0),
        "iterations": b.get("iterations", 0),
        "http_reqs": b.get("http_reqs", 0),
        "http_req_failed": b.get("http_req_failed", 0),
        "op_ms": b.get("cap_measure_ms", new_hist()),
        "iter_ms": b.get("cap_iter_ms", new_hist()),
        "http_ms": b.get("http_req_duration", new_hist()),
    }


def deficit_episodes(sel_bins: list[int], records: list[dict | None],
                     target: float, frac: float = 0.99) -> list[dict]:
    """Independent throughput-deficit episodes over ONE bin set.

    An episode is a run of consecutive covered bins below frac*target.
    Recovery is measured from the episode start to the end of the first
    run of >=5 truly adjacent covered bins at/above threshold — a missing
    bin can never count toward the run, and a later dip is a new episode,
    not a continuation."""
    thresh = target * frac
    n = len(sel_bins)
    eps = []
    i = 0
    while i < n:
        r = records[i]
        if r is None or r["completed"] >= thresh:
            i += 1
            continue
        start = i
        j = i
        while j < n and records[j] is not None \
                and records[j]["completed"] < thresh:
            j += 1
        ep_bins = sel_bins[start:j]
        ep_recs = records[start:j]
        hole = sum(max(0.0, target - r["completed"]) for r in ep_recs)
        min_s = min(ep_recs, key=lambda r: r["completed"])
        # recovery: first run of >=5 adjacent covered good bins after j-1
        k = j
        recovered_end = None
        recovery_start_bin = None
        while k < n:
            m = k
            while m < n and records[m] is not None \
                    and records[m]["completed"] >= thresh:
                m += 1
            if m - k >= 5:
                recovered_end = sel_bins[k + 4] + 1
                recovery_start_bin = sel_bins[k]
                break
            if m == k:
                k += 1
            else:
                k = m
        eps.append({
            "episode_start_s": sel_bins[start],
            "episode_end_s": sel_bins[j - 1] + 1,
            "duration_s": j - start,
            "min_completed_s": min_s["completed"],
            "min_at_s": [sel_bins[k2] for k2 in range(start, j)
                         if records[k2]["completed"] == min_s["completed"]],
            "hole_area_ops": round(hole, 3),
            "recovered": recovered_end is not None,
            "recovery_s": (round(recovered_end - sel_bins[start], 3)
                           if recovered_end is not None else None),
            "recovery_run_start_s": recovery_start_bin,
        })
        i = j
    return eps


# ----------------------------- window resolution ---------------------------
def load_windows(cfg: dict) -> dict:
    """Resolve each participating load's actual measurement window.

    Sources, in order of trust:
      contract  — cap_window_measure_start_ms/end_ms emitted by the load's
                  own k6 run (exact scenario-clock bounds).
      bounded   — container/provenance timestamps give only an outer
                  bracket: the measurement window cannot start before the
                  container or end after it, and scenario bounds satisfy
                  container_start <= scenario_start and
                  scenario_start + duration <= container_end. The
                  conservative bounds used downstream are
                  measure_start <= container_end - duration + warmup
                  (upper bound) and measure_end >= container_start +
                  duration (lower bound). These are genuine bounds, not
                  estimates — but they are NOT the exact window.

    Common window:
      exact         — every load has contract bounds.
      conservative  — at least one load contributes only bounds; the
                      reported interval is guaranteed to be inside every
                      load's real measurement window as far as the
                      evidence shows, but it is not the exact intersection.
      unrecoverable — bounds cannot be established or the intersection is
                      empty.
    """
    loads = []
    mc = cfg.get("measurement_contract") or {}
    if (mc.get("window_start_ms") and mc.get("window_end_ms")
            and mc.get("scenario_clock_ok") == 1):
        loads.append({"name": "main", "kind": "contract", "exact": True,
                      "start": mc["window_start_ms"] / 1000.0,
                      "end": mc["window_end_ms"] / 1000.0,
                      "source": "cap_window_measure_* metrics"})
    else:
        loads.append({"name": "main", "kind": "missing", "exact": False,
                      "start": None, "end": None,
                      "source": "measurement_contract absent/invalid"})
    warmup_s = float(cfg.get("warmup_s") or 15)
    for sc in cfg.get("sidecars", []):
        name = sc.get("name", "?")
        win = sc.get("window") or {}
        if (win.get("kind") == "contract"
                and win.get("scenario_clock_ok") == 1
                and not win.get("divergent_vus")
                and win.get("measure_start_s") is not None
                and win.get("measure_end_s") is not None
                and float(win["measure_end_s"]) > float(
                    win["measure_start_s"])):
            loads.append({"name": name, "kind": "contract", "exact": True,
                          "start": float(win["measure_start_s"]),
                          "end": float(win["measure_end_s"]),
                          "source": "cap_window_measure_* metrics"})
            continue
        started = sc.get("started_ts")
        ended = sc.get("ended_ts")
        dur = sc.get("duration_s") or win.get("duration_s")
        if started and ended and dur:
            loads.append({
                "name": name, "kind": "bounded", "exact": False,
                "start": None, "end": None,
                # scenario_start lies in [container_start, container_end -
                # duration]; measurement = scenario_start + warmup ..
                # scenario_start + duration. These are proven bounds, not
                # estimates — but they are bounds, not the exact window.
                "measure_start_lb": float(started) + warmup_s,
                "measure_start_ub": float(ended) - float(dur) + warmup_s,
                "measure_end_lb": float(started) + float(dur),
                "measure_end_ub": float(ended),
                "container_started_ts": started,
                "container_ended_ts": ended,
                "source": "container lifecycle bounds (provenance only)",
            })
        else:
            loads.append({"name": name, "kind": "missing", "exact": False,
                          "start": None, "end": None,
                          "source": "no contract and no usable container "
                                    "bounds"})
    return loads


def common_window(loads: list[dict]) -> dict:
    """Intersect per-load measurement windows. Never uses shell/container
    timestamps as if they were measurement bounds."""
    if not loads or any(l["kind"] == "missing" for l in loads):
        return {"recoverable": False, "basis": "unrecoverable",
                "reason": "at least one load has no usable window evidence",
                "loads": loads}
    exact = all(l["exact"] for l in loads)
    if exact:
        start = max(l["start"] for l in loads)
        end = min(l["end"] for l in loads)
        basis = "contract_exact"
    else:
        start = max(l["start"] if l["exact"] else l["measure_start_ub"]
                    for l in loads)
        end = min(l["end"] if l["exact"] else l["measure_end_lb"]
                  for l in loads)
        basis = "conservative_bounds"
    if end <= start:
        return {"recoverable": False, "basis": basis,
                "reason": "intersection empty", "loads": loads}
    return {"recoverable": True, "basis": basis, "exact": exact,
            "start": start, "end": end, "seconds": round(end - start, 3),
            "start_utc": utc(start), "end_utc": utc(end),
            "loads": loads}


# ----------------------------- observer deltas -----------------------------
def _delta_segments(rows: list[dict], key_fn) -> list[list[dict]]:
    """Split observer rows into segments wherever identity/reset continuity
    breaks. A counter whose stats_reset changed, went backwards, or whose
    source identity changed can NEVER be differenced across the break —
    even if the new value exceeds the old one."""
    segs: list[list[dict]] = []
    cur: list[dict] = []
    prev_key = None
    for r in rows:
        key = key_fn(r)
        if prev_key is not None and key != prev_key:
            if cur:
                segs.append(cur)
            cur = []
        cur.append(r)
        prev_key = key
    if cur:
        segs.append(cur)
    return segs


# (delta key, source column) — PG18's pg_stat_wal has no
# wal_write_time/wal_sync_time columns; absent columns must surface as
# null, never as a silent 0 delta.
WAL_DELTA_FIELDS = (
    ("wal_bytes", "wal_bytes"),
    ("wal_fpi", "wal_fpi"),
    ("wal_records", "wal_records"),
    ("wal_buffers_full", "wal_buffers_full"),
    ("wal_write_ms", "wal_write_time"),
    ("wal_sync_ms", "wal_sync_time"),
)


def wal_deltas(rows: list[dict]) -> tuple[list[dict], int]:
    """(deltas, breaks): per-interval pg_stat_wal deltas. Breaks on
    stats_reset change, wal_bytes regression, or >5s sampling gaps.
    Other counters degrade per field: a null or regressed column yields
    a null delta for that field (with a regressed_fields marker), not a
    fabricated zero."""
    deltas: list[dict] = []
    breaks = 0
    prev = None
    for r in rows:
        wal = ((r.get("pg") or {}).get("wal") or {}).get("row")
        ts = r.get("ts")
        if not wal or ts is None:
            if prev is not None:
                breaks += 1
            prev = None
            continue
        reset = wal.get("stats_reset")
        wb = wal.get("wal_bytes")
        if prev is not None:
            p_wal, p_ts, p_reset = prev
            dt = ts - p_ts
            broken = (reset != p_reset or wb is None
                      or p_wal.get("wal_bytes") is None
                      or wb < p_wal["wal_bytes"] or dt <= 0 or dt > 5)
            if broken:
                breaks += 1
            else:
                d = {"t0": p_ts, "t1": ts, "dt": dt}
                regressed = []
                for key, col in WAL_DELTA_FIELDS:
                    pv, cv = p_wal.get(col), wal.get(col)
                    if pv is None or cv is None:
                        d[key] = None
                    elif cv < pv:
                        d[key] = None
                        regressed.append(col)
                    else:
                        d[key] = cv - pv
                if regressed:
                    d["regressed_fields"] = regressed
                deltas.append(d)
        prev = (wal, ts, reset)
    return deltas, breaks


IO_FIELDS = ("reads", "read_bytes", "read_time",
             "writes", "write_bytes", "write_time",
             "writebacks", "writeback_time",
             "extends", "extend_bytes", "extend_time",
             "hits", "evictions", "reuses",
             "fsyncs", "fsync_time")


def io_deltas(rows: list[dict]) -> tuple[list[dict], int]:
    """(deltas, breaks): per-interval pg_stat_io deltas keyed by the full
    (backend_type, object, context) dimension. Deltas are per field —
    a null column stays null (never silently 0), a regressed counter
    yields null for that field, and a stats_reset change breaks the row's
    continuity even when counters grew."""
    deltas: list[dict] = []
    breaks = 0
    prev: dict | None = None
    prev_ts = None
    for r in rows:
        pg = r.get("pg") or {}
        io_rows = (pg.get("io") or {}).get("rows")
        ts = r.get("ts")
        if io_rows is None or ts is None:
            if prev is not None:
                breaks += 1
            prev = None
            continue
        cur = {}
        for row in io_rows:
            key = (row.get("backend_type"), row.get("object"),
                   row.get("context"))
            cur[key] = row
        if prev is not None:
            dt = ts - prev_ts
            if dt <= 0 or dt > 5:
                breaks += 1
            else:
                for key, row in cur.items():
                    p = prev.get(key)
                    if p is None:
                        continue
                    if (row.get("stats_reset") is not None
                            and p.get("stats_reset") is not None
                            and row["stats_reset"] != p["stats_reset"]):
                        breaks += 1
                        continue
                    d = {"t0": prev_ts, "t1": ts, "dt": dt,
                         "backend_type": key[0], "object": key[1],
                         "context": key[2]}
                    regressed = []
                    for f in IO_FIELDS:
                        pv, cv = p.get(f), row.get(f)
                        if pv is None or cv is None:
                            d[f] = None
                        elif cv < pv:
                            d[f] = None
                            regressed.append(f)
                        else:
                            d[f] = cv - pv
                    if regressed:
                        d["regressed_fields"] = regressed
                    deltas.append(d)
        prev = cur
        prev_ts = ts
    return deltas, breaks


def disk_deltas(rows: list[dict]) -> tuple[dict[str, list[dict]], int]:
    """(per-device deltas, breaks). md/DM and member devices are kept in
    separate lists — never summed, since md bytes already contain member
    traffic."""
    out: dict[str, list[dict]] = defaultdict(list)
    breaks = 0
    prev: dict | None = None
    prev_ts = None
    for r in rows:
        disk = r.get("disk")
        ts = r.get("ts")
        if not isinstance(disk, dict) or "error" in disk or ts is None:
            if prev is not None:
                breaks += 1
            prev = None
            continue
        if prev is not None:
            dt = ts - prev_ts
            if dt <= 0 or dt > 5:
                breaks += 1
            else:
                for dev, cur in disk.items():
                    p = prev.get(dev)
                    if not isinstance(cur, dict) or not isinstance(p, dict):
                        continue
                    try:
                        d = {"t0": prev_ts, "t1": ts, "dt": dt,
                             "device": dev,
                             "write_Bps": (cur["sectors_written"]
                                           - p["sectors_written"]) * 512.0 / dt,
                             "read_Bps": (cur["sectors_read"]
                                          - p["sectors_read"]) * 512.0 / dt,
                             "writes_s": (cur["writes"] - p["writes"]) / dt,
                             "reads_s": (cur["reads"] - p["reads"]) / dt}
                        w = cur["writes"] - p["writes"]
                        rd = cur["reads"] - p["reads"]
                        d["write_await_ms"] = (
                            (cur["ms_writing"] - p["ms_writing"]) / w
                            if w > 0 else None)
                        d["read_await_ms"] = (
                            (cur["ms_reading"] - p["ms_reading"]) / rd
                            if rd > 0 else None)
                        d["util"] = min(1.0, max(0.0,
                            (cur["ms_doing_io"] - p["ms_doing_io"])
                            / (dt * 1000.0)))
                        d["avg_queue"] = max(0.0,
                            (cur["weighted_ms_doing_io"]
                             - p["weighted_ms_doing_io"]) / (dt * 1000.0))
                        out[dev].append(d)
                    except (KeyError, TypeError):
                        continue
        prev = disk
        prev_ts = ts
    return dict(out), breaks


def cpu_deltas(rows: list[dict]) -> tuple[list[dict], int]:
    """(deltas, breaks): CPU tick deltas -> per-interval usage ratios.
    Raw cumulative ticks are never ratioed directly."""
    deltas: list[dict] = []
    breaks = 0
    prev = None
    prev_ts = None
    for r in rows:
        cpu = r.get("cpu")
        ts = r.get("ts")
        if not isinstance(cpu, dict) or "error" in cpu or ts is None:
            if prev is not None:
                breaks += 1
            prev = None
            continue
        if prev is not None:
            dt = ts - prev_ts
            if dt <= 0 or dt > 5:
                breaks += 1
            else:
                try:
                    tot = sum((cpu[k] - prev[k]) for k in
                              ("user", "nice", "system", "idle", "iowait",
                               "irq", "softirq", "steal"))
                    if tot > 0:
                        deltas.append({
                            "t0": prev_ts, "t1": ts, "dt": dt,
                            "iowait_pct": (cpu["iowait"] - prev["iowait"])
                                          / tot * 100.0,
                            "steal_pct": (cpu["steal"] - prev["steal"])
                                         / tot * 100.0,
                            "user_pct": ((cpu["user"] - prev["user"])
                                         + (cpu["nice"] - prev["nice"]))
                                        / tot * 100.0,
                            "system_pct": (cpu["system"] - prev["system"])
                                          / tot * 100.0,
                            "idle_pct": (cpu["idle"] - prev["idle"])
                                        / tot * 100.0,
                        })
                except (KeyError, TypeError):
                    pass
        prev = cpu
        prev_ts = ts
    return deltas, breaks


def pool_deltas(rows: list[dict]) -> tuple[list[dict], int]:
    deltas: list[dict] = []
    breaks = 0
    prev = None
    prev_ts = None
    for r in rows:
        pool = r.get("pool")
        ts = r.get("ts")
        if not isinstance(pool, dict) or "error" in pool or ts is None \
                or pool.get("acquire_count") is None:
            if prev is not None:
                breaks += 1
            prev = None
            continue
        if prev is not None:
            dt = ts - prev_ts
            if dt <= 0 or dt > 5:
                breaks += 1
            elif pool["acquire_count"] >= prev["acquire_count"]:
                deltas.append({
                    "t0": prev_ts, "t1": ts, "dt": dt,
                    "acquires": pool["acquire_count"] - prev["acquire_count"],
                    "wait_ms": ((pool.get("wait_nanos_total") or 0)
                                - (prev.get("wait_nanos_total") or 0)) / 1e6,
                })
            else:
                breaks += 1
        prev = pool
        prev_ts = ts
    return deltas, breaks


def clip_deltas(deltas: list[dict], a: float, b: float) -> list[dict]:
    """Keep intervals whose midpoint lies inside [a, b) — honest to the
    ~1s sampling resolution; no fractional-interval pretence."""
    return [d for d in deltas
            if d["t0"] is not None and a <= (d["t0"] + d["t1"]) / 2 < b]


def rolling_time_volume(deltas: list[dict], field: str,
                        width_s: float) -> float | None:
    """Peak volume of `field` inside any `width_s`-long time window —
    windows are seconds of wall-clock, never a count of samples.
    Returns None when the field is null everywhere (unavailable)."""
    best = None
    j = 0
    acc = 0.0
    have = False
    for d in deltas:
        v = d.get(field)
        if v is not None:
            acc += v
            have = True
        while deltas[j]["t1"] <= d["t1"] - width_s:
            pv = deltas[j].get(field)
            if pv is not None:
                acc -= pv
            j += 1
        if have and (best is None or acc > best):
            best = acc
    return best


def sum_in_window(deltas: list[dict], field: str) -> float | None:
    """Sum of a delta field; None when the field is null in every delta —
    unavailable data must not collapse into a plausible-looking 0."""
    vals = [d[field] for d in deltas if d.get(field) is not None]
    return sum(vals) if vals else None


# ----------------------------- pg checkpoint log ---------------------------
# docker logs --timestamps prefixes each line with RFC3339 time; the
# postgres log prefix itself may also carry its own timestamp. Both forms
# are accepted; the DOCKER prefix is preferred when present.
CKPT_START_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)?.*?"
    r"LOG:\s+checkpoint starting: (?P<reason>\S+)")
CKPT_DONE_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)?.*?"
    r"LOG:\s+checkpoint complete: wrote (?P<bufs>\d+) buffers "
    r"\((?P<pct>[\d.]+)%\)(?:, wrote (?P<slru>\d+) SLRU buffers)?;"
    r".*?(?:write=(?P<write>[\d.]+) s, sync=(?P<sync>[\d.]+) s, "
    r"total=(?P<total>[\d.]+) s; )?sync files=(?P<files>\d+).*?"
    r"distance=(?P<dist>\d+) kB, estimate=(?P<est>\d+) kB")


def parse_pg_log(text: str) -> list[dict]:
    """Ordered checkpoint events. Each keeps its own identity; a `starting`
    is paired only with the NEXT `complete` line — ambiguous or missing
    boundaries are reported, never invented."""
    events: list[dict] = []
    pending: dict | None = None
    seq = 0
    for line in text.splitlines():
        ms = CKPT_START_RE.search(line)
        if ms:
            if pending is not None:
                # a starting arrived with no complete in between
                pending["missing"] = "checkpoint_complete"
                pending["ambiguous"] = True
                events.append(pending)
            seq += 1
            ts = parse_iso_ts(ms.group("ts") or "") if ms.group("ts") else None
            pending = {"seq": seq, "kind": "start", "ts": ts,
                       "reason": ms.group("reason"),
                       "raw": line.strip()[:200]}
            continue
        md = CKPT_DONE_RE.search(line)
        if md:
            done_ts = (parse_iso_ts(md.group("ts") or "")
                       if md.group("ts") else None)
            if pending is None:
                seq += 1
                events.append({"seq": seq, "kind": "orphan_complete",
                               "ts": done_ts,
                               "missing": "checkpoint_starting",
                               "raw": line.strip()[:200]})
                continue
            pending.update({
                "kind": "complete_pair",
                "complete_ts": done_ts,
                "buffers": int(md.group("bufs")),
                "write_s": (float(md.group("write"))
                            if md.group("write") else None),
                "sync_s": (float(md.group("sync"))
                           if md.group("sync") else None),
                "total_s": (float(md.group("total"))
                            if md.group("total") else None),
                "distance_kb": int(md.group("dist")),
                "estimate_kb": int(md.group("est")),
                "sync_files": int(md.group("files")),
            })
            events.append(pending)
            pending = None
    if pending is not None:
        pending["missing"] = "checkpoint_complete"
        events.append(pending)
    return events


# ----------------------------- report --------------------------------------
def load_observer(path: str) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    meta: dict = {}
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "meta":
                meta = obj
            elif obj.get("type") == "sample":
                rows.append(obj)
    return rows, meta


def window_metrics(sel: dict, series_bins: dict,
                   target: float) -> dict:
    """Every statistic for a window derives from THE SAME selected bins."""
    records = [bin_record(series_bins.get(str(s))) for s in sel["bins"]]
    covered = [r for r in records if r is not None]
    n_sel = len(sel["bins"])
    out = {
        "requested_interval": sel["requested"],
        "effective_interval": sel["effective"],
        "effective_seconds": sel["effective_seconds"],
        "covered_bins": len(covered),
        "missing_bins": sel["missing"],
        "expected_ops": round(target * sel["effective_seconds"], 3),
        "completed": sum(r["completed"] for r in covered),
        "success": sum(r["success"] for r in covered),
        "expected_rejection": sum(r["expected_rejection"] for r in covered),
        "local_no_request": sum(r["local_no_request"] for r in covered),
        "unexpected": sum(r["unexpected"] for r in covered),
        "begins": sum(r["begins"] for r in covered),
        "drops": sum(r["drops"] for r in covered),
        "min_completed_s": (min((r["completed"] for r in covered),
                                default=None)),
        "episodes": deficit_episodes(sel["bins"], records, target),
        "hole_area_ops": round(sum(
            max(0.0, target - r["completed"]) for r in covered), 3),
    }
    return out


def cmd_report(args) -> int:
    with open(args.config, encoding="utf-8") as fh:
        cfg = json.load(fh)
    with open(args.series, encoding="utf-8") as fh:
        series = json.load(fh)
    series_bins = series.get("bins", {})
    present = {int(s) for s in series_bins}
    obs_rows, obs_meta = load_observer(args.observer) if args.observer else (
        [], {})
    with open(args.pglog, encoding="utf-8", errors="replace") as fh:
        ckpt_events = parse_pg_log(fh.read())

    target = float(cfg.get("target_rate") or 0)
    contract = cfg.get("measurement_contract") or {}
    window_json = {}
    if args.window and os.path.exists(args.window):
        try:
            window_json = json.loads(open(args.window).read())
        except (OSError, json.JSONDecodeError) as e:
            window_json = {"valid": False, "reader_error": str(e)}

    # ---- analysis validity -------------------------------------------------
    validity_problems: list[str] = []
    if not contract.get("window_start_ms") or not contract.get("window_end_ms"):
        validity_problems.append("main measurement contract bounds missing")
    elif contract["window_start_ms"] >= contract["window_end_ms"]:
        validity_problems.append("main contract window_start>=window_end")
    if contract.get("scenario_clock_ok") not in (1,):
        validity_problems.append("scenario_clock_ok != 1")
    if contract.get("divergent_vus"):
        validity_problems.append("contract divergent across VUs")
    if window_json and not window_json.get("valid"):
        validity_problems.append(
            "stream window invalid: "
            + ",".join(window_json.get("problems") or ["unknown"]))
    if not series_bins:
        validity_problems.append("per-second series empty")

    # ---- windows -----------------------------------------------------------
    meas_a = meas_b = None
    if contract.get("window_start_ms") and contract.get("window_end_ms"):
        meas_a = contract["window_start_ms"] / 1000.0
        meas_b = contract["window_end_ms"] / 1000.0
    loads = load_windows(cfg)
    common = common_window(loads)

    meas_sel = effective_bins(meas_a, meas_b, present) if meas_a else None
    common_sel = (effective_bins(common["start"], common["end"], present)
                  if common.get("recoverable") else None)

    # ---- per-checkpoint local windows --------------------------------------
    # Each checkpoint has TWO local windows, never one continuous span:
    #   start_local    = checkpoint_start   + [-30 s, +90 s]
    #   complete_local = checkpoint_complete + [-30 s, +90 s]
    # A checkpoint's combined evidence is the UNION of the two locals —
    # the middle write phase between start+90 and complete-30 stays out
    # of checkpoint-local analysis (it remains visible in steady state).
    # Local windows clip to the all-load common window when recoverable,
    # else to the main measurement window; clipping is reported per part.
    LOCAL_PRE_S = 30.0
    LOCAL_POST_S = 90.0
    if common.get("recoverable"):
        clip_a, clip_b = common["start"], common["end"]
        clip_basis = "all-load common window (%s)" % common["basis"]
    else:
        clip_a, clip_b = meas_a, meas_b
        clip_basis = "main measurement window (common unrecoverable)"

    def local_sel(req_a: float, req_b: float) -> dict:
        a = max(req_a, clip_a) if clip_a is not None else req_a
        b = min(req_b, clip_b) if clip_b is not None else req_b
        sel = effective_bins(a, b, present)
        sel["truncated_start"] = bool(clip_a is not None and req_a < clip_a)
        sel["truncated_end"] = bool(clip_b is not None and req_b > clip_b)
        return sel

    def local_metrics(sel: dict) -> dict:
        m = window_metrics(sel, series_bins, target)
        m["selected_bins"] = len(sel["bins"])
        m["truncated_start"] = sel.get("truncated_start", False)
        m["truncated_end"] = sel.get("truncated_end", False)
        return m

    def union_sel(*sels: dict) -> dict:
        bins = sorted({s for sel in sels for s in sel["bins"]})
        return {"bins": bins,
                "requested": [min(sel["requested"][0] for sel in sels),
                              max(sel["requested"][1] for sel in sels)],
                "effective": ([bins[0], bins[-1] + 1] if bins else None),
                "effective_seconds": len(bins),
                "covered": [s for s in bins if s in present],
                "missing": [s for s in bins if s not in present]}

    checkpoints = []
    union_bins: set[int] = set()
    for ev in ckpt_events:
        entry = {
            "id": f"ckpt-{ev['seq']}",
            "reason": ev.get("reason"),
            "kind": ev["kind"],
            "start_s": ev.get("ts"),
            "complete_s": ev.get("complete_ts"),
            "start_utc": utc(ev["ts"]) if ev.get("ts") else None,
            "complete_utc": (utc(ev["complete_ts"])
                             if ev.get("complete_ts") else None),
            "write_s": ev.get("write_s"),
            "sync_s": ev.get("sync_s"),
            "total_s": ev.get("total_s"),
            "distance_kb": ev.get("distance_kb"),
            "estimate_kb": ev.get("estimate_kb"),
            "buffers": ev.get("buffers"),
            "sync_files": ev.get("sync_files"),
            "missing_boundary": ev.get("missing"),
            "ambiguous": ev.get("ambiguous", False),
            "clip_basis": clip_basis,
        }
        s_sel = (local_sel(ev["ts"] - LOCAL_PRE_S, ev["ts"] + LOCAL_POST_S)
                 if ev.get("ts") else None)
        c_sel = None
        if (ev["kind"] == "complete_pair" and ev.get("ts")
                and ev.get("complete_ts")):
            c_sel = local_sel(ev["complete_ts"] - LOCAL_PRE_S,
                              ev["complete_ts"] + LOCAL_POST_S)
            uni = union_sel(s_sel, c_sel)
            missing_any = (s_sel["missing"] or c_sel["missing"])
            entry.update({
                "start_window": local_metrics(s_sel),
                "complete_window": local_metrics(c_sel),
                "local_union": local_metrics(uni),
                "truncated": (s_sel["truncated_start"]
                              or s_sel["truncated_end"]
                              or c_sel["truncated_start"]
                              or c_sel["truncated_end"]),
                "evidence_sufficient": bool(
                    ev.get("write_s") is not None
                    and ev.get("sync_s") is not None
                    and s_sel["covered"] and c_sel["covered"]
                    and not missing_any),
                "terminal_drain_artifact": False,
            })
            union_bins |= set(uni["covered"])
        elif ev["kind"] == "start" and ev.get("ts") and s_sel is not None:
            entry.update({
                "start_window": local_metrics(s_sel),
                "complete_window": None,
                "local_union": local_metrics(union_sel(s_sel)),
                "truncated": (s_sel["truncated_start"]
                              or s_sel["truncated_end"]),
                "evidence_sufficient": False,
                "terminal_drain_artifact": bool(s_sel["truncated_end"]),
                "note": "no checkpoint complete record — a trailing "
                        "truncated local window contains the end-of-run "
                        "drain, not a throughput trough",
            })
            union_bins |= set(s_sel["covered"])
        else:
            entry.update({"start_window": None, "complete_window": None,
                          "local_union": None, "evidence_sufficient": False,
                          "terminal_drain_artifact": False})
        checkpoints.append(entry)

    # ---- in-flight reconstruction on one cut -------------------------------
    def in_flight_upto(cut: float) -> int:
        begins = ends = 0
        for s in sorted(int(x) for x in series_bins):
            if s >= cut:
                break
            r = bin_record(series_bins[str(s)])
            begins += r["begins"]
            ends += r["completed"]
        return begins - ends

    hist_schema = resolve_hist_schema(series)

    # ---- per-second dips inside the measurement window ---------------------
    dips = []
    if meas_sel:
        for s in meas_sel["bins"]:
            r = bin_record(series_bins.get(str(s)))
            if r is not None and r["completed"] < target * 0.99:
                dips.append({"s": s, "ts_utc": utc(s),
                             "completed": r["completed"],
                             "in_checkpoint_local": s in union_bins})
    dip_seconds = [d["s"] for d in dips]

    # ---- steady state -------------------------------------------------------
    # steady = all-load common-window bins MINUS the union of checkpoint
    # local windows. NOT checkpoint-free: a checkpoint's middle write phase
    # is outside both local windows and stays inside steady state. The
    # common window also excludes pre-common VU-ramp bins by construction.
    steady = {
        "basis": "common_window_minus_checkpoint_local_windows",
        "semantics": "excludes only checkpoint start/complete local "
                     "windows; a checkpoint's middle write phase remains "
                     "inside steady state",
    }
    if common_sel:
        steady_bins = [s for s in common_sel["bins"] if s not in union_bins]
        steady_sel = {
            "bins": steady_bins,
            "covered": [s for s in steady_bins if s in present],
            "missing": [s for s in steady_bins if s not in present],
            "requested": [common["start"], common["end"]],
            "effective": ([steady_bins[0], steady_bins[-1] + 1]
                          if steady_bins else None),
            "effective_seconds": len(steady_bins),
        }
        steady_rec = [bin_record(series_bins.get(str(s)))
                      for s in steady_bins]
        covered = [r for r in steady_rec if r is not None]
        op_ms = new_hist()
        iter_ms = new_hist()
        http_ms = new_hist()
        for r in covered:
            op_ms = hist_merge(op_ms, r["op_ms"])
            iter_ms = hist_merge(iter_ms, r["iter_ms"])
            http_ms = hist_merge(http_ms, r["http_ms"])
        n = len(covered)
        steady.update({
            "seconds": n,
            "common_seconds": len(common_sel["bins"]),
            "excluded_checkpoint_local_bins": len(union_bins),
            "missing_bins": steady_sel["missing"],
            "histogram_schema": hist_schema,
            "throughput_ops_per_s": (
                round(sum(r["completed"] for r in covered) / n, 3)
                if n else None),
            "successful_ops_per_s": (
                round(sum(r["success"] for r in covered) / n, 3)
                if n else None),
            "unexpected": sum(r["unexpected"] for r in covered),
            "drops": sum(r["drops"] for r in covered),
            "dips_in_steady": [
                d for d in dips if d["s"] in set(steady_bins)],
            "op_latency_ms": hist_stats(op_ms, hist_schema),
            "iter_latency_ms": hist_stats(iter_ms, hist_schema),
            "http_latency_ms": hist_stats(http_ms, hist_schema),
        })
    else:
        steady["unavailable"] = "all-load common window unrecoverable"

    # ---- WAL envelope -------------------------------------------------------
    # Numerator and every per-second figure share ONE effective interval:
    # the measurement window's full-second effective bins [eff_a, eff_b),
    # identical to the operation denominator below.
    eff_a, eff_b = (meas_sel["effective"] if meas_sel and
                    meas_sel.get("effective") else (None, None))
    wal, wal_breaks = wal_deltas(obs_rows)
    wal_win = clip_deltas(wal, eff_a, eff_b) if eff_a else wal
    covered_time = sum(d["dt"] for d in wal_win)
    wal_bytes_total = sum_in_window(wal_win, "wal_bytes")
    wal_env = {
        "basis": "pg_stat_wal counter deltas (publication counters, "
                 "not physical I/O timings)",
        "interval": [eff_a, eff_b],
        "interval_utc": [utc(eff_a), utc(eff_b)] if eff_a else None,
        "interval_basis": "measurement window effective full-second bins "
                          "(same interval as the ops denominator)",
        "deltas": len(wal_win), "segment_breaks": wal_breaks,
        "covered_seconds": round(covered_time, 3),
        "wal_bytes": wal_bytes_total,
        "wal_records": sum_in_window(wal_win, "wal_records"),
        "wal_fpi": sum_in_window(wal_win, "wal_fpi"),
        "wal_write_ms": sum_in_window(wal_win, "wal_write_ms"),
        "wal_sync_ms": sum_in_window(wal_win, "wal_sync_ms"),
        "mean_Bps": (round(wal_bytes_total / covered_time, 1)
                     if covered_time and wal_bytes_total is not None
                     else None),
        "peak_rate_1s_Bps": (round(
            max((d["wal_bytes"] / d["dt"] for d in wal_win
                 if d.get("wal_bytes") is not None),
                default=None), 1) if wal_win else None),
        "volume_peak_10s_B": rolling_time_volume(wal_win, "wal_bytes", 10),
        "volume_peak_60s_B": rolling_time_volume(wal_win, "wal_bytes", 60),
        "volume_peak_300s_B": rolling_time_volume(wal_win, "wal_bytes", 300),
        "volume_peak_600s_B": rolling_time_volume(wal_win, "wal_bytes", 600),
        "resolution_note": "midpoint-clipped ~1s deltas; boundary deltas "
                           "count fully — resolution +/-1s per boundary",
    }

    # ---- io breakdown -------------------------------------------------------
    io, io_breaks = io_deltas(obs_rows)
    io_win = clip_deltas(io, eff_a, eff_b) if eff_a else io

    def _add(v: float | None) -> float:
        return v if v is not None else 0.0

    def _any_null(d: dict, fields: tuple) -> bool:
        return any(d.get(f) is None for f in fields)

    by_role: dict[str, dict] = defaultdict(
        lambda: {"write_bytes": 0, "fsyncs": 0, "fsync_ms": 0.0,
                 "writes": 0, "objects": set(), "null_field_deltas": 0})
    by_object: dict[str, dict] = defaultdict(
        lambda: {"write_bytes": 0, "fsyncs": 0, "fsync_ms": 0.0})
    by_dim: dict[str, dict] = defaultdict(
        lambda: {"write_bytes": 0, "fsyncs": 0, "fsync_ms": 0.0,
                 "writes": 0, "null_field_deltas": 0})
    dip_set = set(dip_seconds)
    fsync_at_dips: dict[str, float] = {}
    for d in io_win:
        role = by_role[str(d["backend_type"])]
        role["write_bytes"] += _add(d.get("write_bytes"))
        role["fsyncs"] += _add(d.get("fsyncs"))
        role["fsync_ms"] += _add(d.get("fsync_time"))
        role["writes"] += _add(d.get("writes"))
        role["objects"].add(str(d["object"]))
        if _any_null(d, ("write_bytes", "fsyncs", "fsync_time")):
            role["null_field_deltas"] += 1
        obj = by_object[str(d["object"])]
        obj["write_bytes"] += _add(d.get("write_bytes"))
        obj["fsyncs"] += _add(d.get("fsyncs"))
        obj["fsync_ms"] += _add(d.get("fsync_time"))
        dim = by_dim["|".join(str(x) for x in
                             (d["backend_type"], d["object"], d["context"]))]
        dim["write_bytes"] += _add(d.get("write_bytes"))
        dim["fsyncs"] += _add(d.get("fsyncs"))
        dim["fsync_ms"] += _add(d.get("fsync_time"))
        dim["writes"] += _add(d.get("writes"))
        if _any_null(d, ("write_bytes", "fsyncs", "fsync_time")):
            dim["null_field_deltas"] += 1
        if (d["backend_type"] == "client backend" and d["object"] == "wal"
                and d["context"] == "normal"
                and d.get("fsync_time") is not None
                and int(d["t1"]) in dip_set):
            fsync_at_dips[utc(d["t1"])] = round(
                d["fsync_time"] / d["dt"], 1)
    io_summary = {
        "deltas": len(io_win), "segment_breaks": io_breaks,
        "by_backend": {k: {**v, "objects": sorted(v["objects"])}
                       for k, v in sorted(by_role.items())},
        "by_object": dict(sorted(by_object.items())),
        "by_dimension": {k: v for k, v in sorted(by_dim.items())
                         if (v["write_bytes"] or v["fsyncs"]
                             or v["fsync_ms"] or v["writes"]
                             or v["null_field_deltas"])},
        "dimension_key": "backend_type|object|context",
        "client_backend_wal_fsync_ms_per_s_at_dips": fsync_at_dips,
        "note": "fsync_time is cumulative milliseconds spent in fsync "
                "across all backends — a wait-time total, not a CPU or "
                "device measure",
    }

    # ---- disk / cpu / pool --------------------------------------------------
    disk, disk_breaks = disk_deltas(obs_rows)
    disk_win = {dev: clip_deltas(ds, eff_a, eff_b) if eff_a else ds
                for dev, ds in disk.items()}
    disk_summary = {}
    for dev, ds in sorted(disk_win.items()):
        if not ds:
            disk_summary[dev] = {"deltas": 0}
            continue
        disk_summary[dev] = {
            "deltas": len(ds),
            "write_Bps_mean": round(
                sum(d["write_Bps"] * d["dt"] for d in ds)
                / sum(d["dt"] for d in ds), 1),
            "write_Bps_peak": round(max(d["write_Bps"] for d in ds), 1),
            "write_await_ms_peak": max(
                (d["write_await_ms"] for d in ds
                 if d["write_await_ms"] is not None), default=None),
            "avg_queue_peak": max(d["avg_queue"] for d in ds),
            "util_peak": max(d["util"] for d in ds),
        }
    cpu, cpu_breaks = cpu_deltas(obs_rows)
    cpu_win = clip_deltas(cpu, eff_a, eff_b) if eff_a else cpu
    pool, pool_breaks = pool_deltas(obs_rows)
    pool_win = clip_deltas(pool, eff_a, eff_b) if eff_a else pool
    pool_rates = sorted(d["wait_ms"] / d["dt"] for d in pool_win)
    dip_pool = {utc(d["t1"]): round(d["wait_ms"] / d["dt"], 1)
                for d in pool_win if int(d["t1"]) in dip_set}
    pool_summary = {
        "deltas": len(pool_win), "segment_breaks": pool_breaks,
        "wait_ms_per_s_peak": (round(
            max((d["wait_ms"] / d["dt"] for d in pool_win),
                default=None) or 0, 3) if pool_win else None),
        "wait_ms_per_s_mean": (round(
            sum(d["wait_ms"] for d in pool_win)
            / sum(d["dt"] for d in pool_win), 3) if pool_win else None),
        "wait_ms_per_s_median": (round(
            pool_rates[len(pool_rates) // 2], 3)
            if pool_rates else None),
        "wait_ms_per_s_p95": (round(
            pool_rates[min(len(pool_rates) - 1,
                           int(0.95 * len(pool_rates)))], 3)
            if pool_rates else None),
        "wait_ms_per_s_at_dip_bins": dip_pool,
        "wait_ms_per_s_dip_range": (
            [round(min(dip_pool.values()), 1),
             round(max(dip_pool.values()), 1)] if dip_pool else None),
        "acquires": sum(d["acquires"] for d in pool_win),
        "note": "wait_nanos_total is cumulative pool wait; per-second "
                "figures are deltas, never the lifetime max gauge",
    }
    cpu_summary = {
        "deltas": len(cpu_win), "segment_breaks": cpu_breaks,
        "iowait_pct_mean": (round(
            sum(d["iowait_pct"] * d["dt"] for d in cpu_win)
            / sum(d["dt"] for d in cpu_win), 3) if cpu_win else None),
        "iowait_pct_peak": (round(
            max(d["iowait_pct"] for d in cpu_win), 3) if cpu_win else None),
        "steal_pct_peak": (round(
            max(d["steal_pct"] for d in cpu_win), 3) if cpu_win else None),
    }

    # ---- reconciliation ------------------------------------------------------
    begins_by_cohort = defaultdict(int)
    begins_by_pair = defaultdict(int)
    ends_by_outcome = defaultdict(int)          # outcome -> n (all cohorts)
    ends_by_cohort_outcome = defaultdict(int)   # "cohort|outcome" -> n
    ends_measure = 0
    for s, b in series_bins.items():
        for k, v in b["begins"].items():
            begins_by_cohort[k] += v
        for k, v in b["begins_pair"].items():
            begins_by_pair[k] += v
        for k, v in b["ends"].items():
            cohort, lw, outcome = k.split("|")
            ends_by_outcome[outcome] += v
            ends_by_cohort_outcome[f"{cohort}|{outcome}"] += v
            if cohort == "measure":
                ends_measure += v
    rec = {
        "contract": contract,
        "common_window": common,
        "measurement_window": {
            "requested": [meas_a, meas_b],
            "effective": (meas_sel["effective"] if meas_sel else None),
            "effective_seconds": (meas_sel["effective_seconds"]
                                  if meas_sel else None),
            "missing_bins": meas_sel["missing"] if meas_sel else None,
        },
        "arrival_fidelity": {
            "started_total": begins_by_cohort.get("measure", 0)
                             + begins_by_cohort.get("pre", 0)
                             + begins_by_cohort.get("post", 0),
            "begins_by_cohort": dict(begins_by_cohort),
            "ends_total": sum(ends_by_outcome.values()),
            "interrupted": (sum(begins_by_cohort.values())
                            - sum(ends_by_outcome.values())),
        },
        "measure_cohort": {
            "begins": begins_by_cohort.get("measure", 0),
            "ends": ends_measure,
            "by_outcome": {
                o: ends_by_cohort_outcome.get(f"measure|{o}", 0)
                for o in OUTCOME_KEYS},
            "basis": "cap_iter_end stream points tagged cohort=measure; "
                     "grace completions stay in their arrival cohort",
        },
        "legacy_vs_unified": {
            "legacy_rule_ops": sum(v for k, v in begins_by_pair.items()
                                   if k.endswith("|1")),
            "unified_measure_ops": begins_by_cohort.get("measure", 0),
            "late_vu_missed_by_legacy": begins_by_pair.get("measure|0", 0),
            "pre_window_counted_by_legacy": begins_by_pair.get("pre|1", 0),
            "post_window_counted_by_legacy": begins_by_pair.get("post|1", 0),
        },
        "in_flight_boundary": (
            {
                "cut_start_s": meas_sel["effective"][0],
                "cut_end_s": meas_sel["effective"][1],
                "in_flight_at_start": in_flight_upto(meas_sel["effective"][0]),
                "in_flight_at_end": in_flight_upto(meas_sel["effective"][1]),
                "begins_in_window": sum(
                    bin_record(series_bins[str(s)])["begins"]
                    for s in meas_sel["covered"]),
                "completed_in_window": sum(
                    bin_record(series_bins[str(s)])["completed"]
                    for s in meas_sel["covered"]),
                "begins_measure_in_window": sum(
                    bin_record(series_bins[str(s)])["begins_measure"]
                    for s in meas_sel["covered"]),
                "completed_measure_in_window": sum(
                    sum(v for k, v in series_bins[str(s)]["ends"].items()
                        if k.startswith("measure|"))
                    for s in meas_sel["covered"]),
            } if meas_sel and meas_sel["effective"] else None),
        "steady_state": steady,
        "dips_below_99pct": dips,
    }
    if rec["in_flight_boundary"]:
        b = rec["in_flight_boundary"]
        b["reconciled"] = (
            b["completed_in_window"]
            == b["begins_in_window"] + b["in_flight_at_start"]
            - b["in_flight_at_end"])

    # ---- wal per op ----------------------------------------------------------
    if meas_sel and covered_time and eff_a is not None:
        ops_in_window = sum(
            bin_record(series_bins[str(s)])["begins_measure"]
            for s in meas_sel["covered"])
        have_wal = wal_bytes_total is not None and ops_in_window
        wal_env["wal_per_op"] = {
            "bytes_per_op": (round(wal_bytes_total / ops_in_window, 1)
                             if have_wal else None),
            "KiB_per_op": (round(wal_bytes_total / ops_in_window / 1024.0, 3)
                           if have_wal else None),
            "effective_interval": [eff_a, eff_b],
            "numerator": ("pg_stat_wal.wal_bytes deltas midpoint-clipped "
                          "to effective_interval [%s, %s) — the same "
                          "interval as the denominator"
                          % (utc(eff_a), utc(eff_b))),
            "denominator": "measure-cohort iteration begins on the "
                           "full-second bins of the same "
                           "effective_interval (all sidecars' own WAL is "
                           "included in the numerator; denominator is "
                           "main-scenario ops only — not a pure per-op "
                           "WAL cost)",
            "ops_in_window": ops_in_window,
            "window_seconds": round(eff_b - eff_a, 3),
            "wal_covered_seconds": round(covered_time, 3),
            "resolution_caveat": "observer deltas are midpoint-clipped "
                                 "~1s samples; boundary deltas count "
                                 "fully — +/-1s per boundary",
        }

    # ---- validity -------------------------------------------------------------
    missing_required = []
    for cp in checkpoints:
        if cp["kind"] == "complete_pair" and not cp.get(
                "evidence_sufficient"):
            parts = []
            if cp.get("write_s") is None or cp.get("sync_s") is None:
                parts.append("write/sync fields unavailable")
            sw = cp.get("start_window") or {}
            cw = cp.get("complete_window") or {}
            if sw.get("missing_bins") or cw.get("missing_bins"):
                parts.append(
                    "missing bins start=%s complete=%s"
                    % (sw.get("missing_bins"), cw.get("missing_bins")))
            if not sw.get("covered_bins") or not cw.get("covered_bins"):
                parts.append("no covered bins")
            missing_required.append(
                f"{cp['id']}: insufficient evidence "
                f"({'; '.join(parts) or 'incomplete'}; "
                f"missing_boundary={cp.get('missing_boundary')})")
    stream_stats = None
    if getattr(args, "stats", None):
        try:
            with open(args.stats, encoding="utf-8") as fh:
                stream_stats = json.load(fh)
        except Exception as e:
            validity_problems.append(f"stream_stats_unreadable: {e}")
    if stream_stats:
        if stream_stats.get("reader_error"):
            validity_problems.append(
                f"stream_reader_error: {stream_stats['reader_error']}")
        if stream_stats.get("parse_errors"):
            validity_problems.append(
                f"stream_parse_errors: {stream_stats['parse_errors']}")
    contract_defects = [
        p for p in (contract.get("problems") or [])
        if not any(f"cap_window_{f}" in p for f in CONTRACT_BOUNDS_FIELDS)
    ] if isinstance(contract.get("problems"), list) else []
    validity = {
        "valid": not validity_problems and not missing_required,
        "problems": validity_problems,
        "contract_defects": contract_defects,
        "checkpoint_evidence_gaps": missing_required,
        "stream_stats": {
            "parse_errors": stream_stats.get("parse_errors"),
            "reader_error": stream_stats.get("reader_error"),
            "events": stream_stats.get("events"),
        } if stream_stats else "not provided",
        "window_json": {
            "valid": window_json.get("valid"),
            "problems": window_json.get("problems"),
            "reader_error": window_json.get("reader_error"),
        } if window_json else "not provided",
    }

    out = args.out
    os.makedirs(out, exist_ok=True)

    def dump(name: str, obj: dict) -> None:
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)

    dump("measurement-reconciliation.json", rec)
    dump("checkpoint-windows.json", {
        "basis": "each checkpoint has TWO local windows: start_local = "
                 "start + [-30s,+90s] and complete_local = complete + "
                 "[-30s,+90s], clipped to the all-load common window; "
                 "local_union = start ∪ complete only — the middle write "
                 "phase is NOT checkpoint-local; union_bins dedupes "
                 "overlaps for steady-state exclusion",
        "common_window": common,
        "measurement_window": rec["measurement_window"],
        "checkpoints": checkpoints,
    })
    dump("wal-envelope.json", {**wal_env, "io": io_summary,
                               "disk": disk_summary, "cpu": cpu_summary,
                               "pool": pool_summary})
    dump("steady-state.json", steady)
    dump("analysis-validity.json", validity)

    # per-second timeline CSV
    with open(os.path.join(out, "checkpoint-timeline.csv"), "w",
              newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["s", "ts_utc", "begins", "completed", "success",
                    "unexpected", "drops", "in_ckpt_local",
                    "bin_present"])
        all_secs = sorted(present)
        for s in all_secs:
            r = bin_record(series_bins.get(str(s)))
            w.writerow([s, utc(s), r["begins"], r["completed"],
                        r["success"], r["unexpected"], r["drops"],
                        s in union_bins, True])
        if meas_sel:
            for s in meas_sel["missing"]:
                w.writerow([s, utc(s), "", "", "", "", "", "", False])

    print(json.dumps({
        "valid": validity["valid"],
        "problems": validity_problems,
        "common_window": common.get("recoverable") and {
            "basis": common["basis"], "start": common["start_utc"],
            "end": common["end_utc"], "seconds": common["seconds"]},
        "checkpoints": [
            {"id": c["id"], "kind": c["kind"],
             "write_s": c.get("write_s"),
             "truncated": c.get("truncated"),
             "evidence_sufficient": c.get("evidence_sufficient")}
            for c in checkpoints],
    }, indent=2))
    return 0


# ----------------------------- cli ------------------------------------------
def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("stream")
    sp.add_argument("--diag-out", required=True)
    sp.add_argument("--series-out", required=True)
    sp.add_argument("--window-out", required=True)
    sp.add_argument("--stats-out", required=True)
    sp = sub.add_parser("report")
    sp.add_argument("--series", required=True)
    sp.add_argument("--observer")
    sp.add_argument("--pglog", required=True)
    sp.add_argument("--config", required=True)
    sp.add_argument("--window")
    sp.add_argument("--stats")
    sp.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "stream":
        return cmd_stream(args)
    return cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
