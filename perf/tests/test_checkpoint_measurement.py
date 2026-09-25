#!/usr/bin/env python3
"""Offline regression tests for the unified measurement window fix.

Run: python3 -m unittest perf.tests.test_checkpoint_measurement -v
(or: python3 perf/tests/test_checkpoint_measurement.py)

Covered:
  * measurement-window math mirrored in JS (k6) — edge boundaries,
    late-VU cohort membership, bucket counts, duration parsing;
  * stream analyzer: cohort/lw/outcome accounting, window contract
    consistency, legacy-vs-unified reconstruction, per-second bins,
    parse/reader errors propagating into validity;
  * report analyzer: real scenario-window common bounds (never container
    lifecycle), shared bin policy, per-checkpoint stable ids, truncated
    windows, deficit episodes, recovery adjacency, WAL reset breaks,
    io/disk/cpu role-preserving deltas, steady-state exclusion;
  * evaluator: capRun detection by markers, INVALID on broken contract,
    zero-ops on contract basis, full-scenario basis for non-capRun;
  * observer: real transformation/query-handling functions (fetch_pg row
    dimensionality, dec_default, /proc parsers);
  * histogram quantiles report containing intervals, raw-sample quantiles
    stay exact;
  * historical fixture denominator checks (1900/2000 runs) — audit math
    only, never re-presented as reruns.
"""
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / "perf" / "tools" / "checkpoint_analyze.py"
OBSERVER = ROOT / "perf" / "tools" / "checkpoint_observer.py"
CAPSEARCH = ROOT / "perf" / "tools" / "capacity_search.py"
CLOCK_JS = ROOT / "perf" / "k6" / "measurement_clock.js"

sys.path.insert(0, str(ROOT / "perf" / "tools"))
import checkpoint_analyze as ca  # noqa: E402
import capacity_search as cs  # noqa: E402
import checkpoint_observer as obs  # noqa: E402

# fixed epoch used by every synthetic report fixture (2026-01-01T00:00:00Z)
FIXTURE_BASE = 1767225600


def k6_point(metric, ts, value, tags=None):
    return json.dumps({
        "type": "Point",
        "data": {"metric": metric, "time": ts, "value": value,
                 "tags": tags or {}},
        "metric": metric})


def run_stream(points):
    """Feed k6 JSON lines through the analyzer; return artifacts dict."""
    tmp = Path(tempfile.mkdtemp())
    p = subprocess.run(
        [sys.executable, str(ANALYZER), "stream",
         "--diag-out", str(tmp / "diag.jsonl.gz"),
         "--series-out", str(tmp / "series.json"),
         "--window-out", str(tmp / "window.json"),
         "--stats-out", str(tmp / "stats.json")],
        input="\n".join(points), text=True, capture_output=True, timeout=120)
    assert p.returncode == 0, p.stderr
    out = {
        "series": json.loads((tmp / "series.json").read_text()),
        "window": json.loads((tmp / "window.json").read_text()),
        "stats": json.loads((tmp / "stats.json").read_text()),
    }
    with gzip.open(tmp / "diag.jsonl.gz", "rt") as fh:
        out["diag_lines"] = fh.read()
    shutil.rmtree(tmp)
    return out


class WindowContractTest(unittest.TestCase):
    def test_consistent_contract_valid(self):
        pts = [
            k6_point("cap_window_scenario_start_ms", "2026-01-01T00:00:01Z",
                     1767225600000),
            k6_point("cap_window_measure_start_ms", "2026-01-01T00:00:01Z",
                     1767225615000),
            k6_point("cap_window_measure_end_ms", "2026-01-01T00:00:01Z",
                     1767225795000),
            k6_point("cap_window_duration_ms", "2026-01-01T00:00:01Z",
                     180000),
            k6_point("cap_window_clock_ok", "2026-01-01T00:00:01Z", 1),
        ]
        r = run_stream(pts)
        self.assertTrue(r["window"]["valid"])
        self.assertTrue(r["window"]["consistent"])
        self.assertEqual(r["window"]["fields"]["scenario_start_ms"]["distinct"], 1)

    def test_divergent_contract_invalid(self):
        # Two VUs disagree on scenario start -> INVALID, never silently fixed.
        pts = [
            k6_point("cap_window_scenario_start_ms", "2026-01-01T00:00:01Z",
                     1767225600000),
            k6_point("cap_window_scenario_start_ms", "2026-01-01T00:00:02Z",
                     1767225600500),
            k6_point("cap_window_clock_ok", "2026-01-01T00:00:01Z", 1),
        ]
        r = run_stream(pts)
        self.assertFalse(r["window"]["consistent"])
        self.assertFalse(r["window"]["valid"])

    def test_clock_fallback_marked_invalid(self):
        pts = [
            k6_point("cap_window_clock_ok", "2026-01-01T00:00:01Z", 0),
            k6_point("cap_window_scenario_start_ms", "2026-01-01T00:00:01Z",
                     1767225600000),
            k6_point("cap_window_measure_start_ms", "2026-01-01T00:00:01Z",
                     1767225615000),
            k6_point("cap_window_measure_end_ms", "2026-01-01T00:00:01Z",
                     1767225795000),
            k6_point("cap_window_duration_ms", "2026-01-01T00:00:01Z",
                     180000),
        ]
        r = run_stream(pts)
        self.assertFalse(r["window"]["valid"])

    def test_parse_errors_invalidate_window(self):
        # Garbage in the stream must propagate to validity — a window
        # reconstructed from a damaged stream is not evidence.
        pts = [
            k6_point("cap_window_scenario_start_ms", "2026-01-01T00:00:01Z",
                     1767225600000),
            k6_point("cap_window_measure_start_ms", "2026-01-01T00:00:01Z",
                     1767225615000),
            k6_point("cap_window_measure_end_ms", "2026-01-01T00:00:01Z",
                     1767225795000),
            k6_point("cap_window_duration_ms", "2026-01-01T00:00:01Z",
                     180000),
            k6_point("cap_window_clock_ok", "2026-01-01T00:00:01Z", 1),
            "this is not json",
            '{"type":"Point","data":{"metric":',
        ]
        r = run_stream(pts)
        self.assertGreater(r["stats"]["parse_errors"], 0)
        self.assertFalse(r["window"]["valid"])
        self.assertTrue(any(p.startswith("parse_errors:")
                            for p in r["window"]["problems"]))


class GaugeNameConsistencyTest(unittest.TestCase):
    """Regression for the cap_window_offset_ms defect: every entry in the
    clock's gauge map must emit under `cap_window_<field>` — the same name
    contractFromMetrics looks up."""

    def test_gauge_names_match_contract_fields(self):
        src = CLOCK_JS.read_text()
        pairs = re.findall(r"(\w+):\s*new Gauge\('([^']+)'\)", src)
        self.assertTrue(pairs)
        for field, metric in pairs:
            self.assertEqual(metric, f"cap_window_{field}",
                             f"gauge map key {field} emits {metric}")
        # contractFromMetrics must look up exactly those emitted names
        lookup = re.search(
            r"metrics\[`cap_window_\$\{name\}`\]", src)
        self.assertIsNotNone(lookup)


class CohortAccountingTest(unittest.TestCase):
    def test_late_vu_reconstruction(self):
        # 3 VU-local-warmup-exempt iterations land inside the window (lw=0)
        # and 5 legacy-covered ones (lw=1). Ends must reconcile.
        base = "2026-01-01T00:00:{}Z"
        pts = []
        for i in range(5):
            t = base.format(20 + i)
            pts.append(k6_point("cap_iter_begin", t, 1,
                                {"cohort": "measure", "lw": "1"}))
            pts.append(k6_point("cap_iter_end", t, 1,
                                {"cohort": "measure", "lw": "1",
                                 "outcome": "success"}))
        for i in range(3):
            t = base.format(30 + i)
            pts.append(k6_point("cap_iter_begin", t, 1,
                                {"cohort": "measure", "lw": "0"}))
            pts.append(k6_point("cap_iter_end", t, 1,
                                {"cohort": "measure", "lw": "0",
                                 "outcome": "success"}))
        pts.append(k6_point("cap_iter_begin", base.format(5), 1,
                            {"cohort": "pre", "lw": "0"}))
        pts.append(k6_point("cap_iter_end", base.format(5), 1,
                            {"cohort": "pre", "lw": "0", "outcome": "success"}))
        pts.append(k6_point("cap_iter_begin", base.format(59), 1,
                            {"cohort": "post", "lw": "1"}))
        pts.append(k6_point("cap_iter_end", base.format(59), 1,
                            {"cohort": "post", "lw": "1", "outcome": "success"}))
        r = run_stream(pts)
        bins = r["series"]["bins"]
        begins_measure = sum(b["begins"].get("measure", 0)
                             for b in bins.values())
        self.assertEqual(begins_measure, 8)
        lw0 = sum(v for b in bins.values()
                  for k, v in b["begins_pair"].items() if k == "measure|0")
        self.assertEqual(lw0, 3)
        legacy = sum(v for b in bins.values()
                     for k, v in b["begins_pair"].items() if k.endswith("|1"))
        self.assertEqual(legacy, 6)  # 5 measure + 1 post

    def test_interrupted_iterations_leave_begin_without_end(self):
        pts = [
            k6_point("cap_iter_begin", "2026-01-01T00:00:20Z", 1,
                     {"cohort": "measure", "lw": "1"}),
        ]
        r = run_stream(pts)
        bins = r["series"]["bins"]
        self.assertEqual(sum(b["begins"].get("measure", 0)
                             for b in bins.values()), 1)
        self.assertEqual(sum(sum(b["ends"].values()) for b in bins.values()), 0)

    def test_cohort_begin_end_grace_reconciliation(self):
        # begins/ends/abnormal-exit/grace-completion must reconcile:
        # 4 begins, 3 ends inside window, 1 post-window grace completion
        # attributed to its begin cohort, 1 interrupted (begin, no end).
        base = "2026-01-01T00:00:{}Z"
        pts = []
        for i in range(4):
            pts.append(k6_point("cap_iter_begin", base.format(20 + i), 1,
                                {"cohort": "measure", "lw": "1"}))
        for i in range(3):
            pts.append(k6_point("cap_iter_end", base.format(20 + i), 1,
                                {"cohort": "measure", "lw": "1",
                                 "outcome": "success"}))
        # grace completion of a measure-cohort begin lands post-window
        pts.append(k6_point("cap_iter_end", base.format(59), 1,
                            {"cohort": "measure", "lw": "1",
                             "outcome": "success"}))
        r = run_stream(pts)
        bins = r["series"]["bins"]
        total_begins = sum(sum(b["begins"].values()) for b in bins.values())
        total_ends = sum(sum(b["ends"].values()) for b in bins.values())
        self.assertEqual(total_begins, 4)
        self.assertEqual(total_ends, 4)   # 3 in-window + 1 grace
        measure_ends = sum(v for b in bins.values()
                           for k, v in b["ends"].items()
                           if k.startswith("measure|"))
        self.assertEqual(measure_ends, 4)

    def test_http_duration_subsampled_not_fully_persisted(self):
        pts = [k6_point("http_req_duration", "2026-01-01T00:00:20Z", 5.0)
               for _ in range(200)]
        pts.append(k6_point("http_req_duration", "2026-01-01T00:00:21Z", 900.0))
        r = run_stream(pts)
        kept = r["diag_lines"].count("http_req_duration")
        self.assertLess(kept, 50)          # sub-sampled
        self.assertIn("900.0", r["diag_lines"])  # tail sample always kept


class BinPolicyTest(unittest.TestCase):
    """The shared bin policy: non-integer boundaries, missing seconds and
    terminal drain artifacts all feed through one selection."""

    def _series(self, base, counts, missing=frozenset()):
        bins = {}
        for i, c in enumerate(counts):
            if i in missing:
                continue
            sec = base + i
            bins[str(sec)] = {
                "begins": {"measure": c}, "begins_pair": {"measure|1": c},
                "ends": {"measure|1|success": c},
                "iterations": c, "dropped": 0, "vus": 2, "vus_max": 4,
                "http_reqs": c, "http_req_failed": 0,
                "data_received": 0, "data_sent": 0,
                "cap_measure_ms": ca.new_hist(), "cap_iter_ms": ca.new_hist(),
                "http_req_duration": ca.new_hist()}
        return bins

    def test_non_integer_bounds_share_one_bin_set(self):
        base = 1767225600
        bins = self._series(base, [20] * 10)
        # requested [base+0.4, base+9.6): fully-contained 1s bins = 1..8
        sel = ca.effective_bins(base + 0.4, base + 9.6, set(map(int, bins)))
        self.assertEqual(sel["bins"], list(range(base + 1, base + 9)))
        self.assertEqual(sel["effective_seconds"], 8)
        m = ca.window_metrics(sel, bins, 20.0)
        self.assertEqual(m["expected_ops"], 160.0)     # 8 bins * 20
        self.assertEqual(m["completed"], 160)
        self.assertEqual(m["covered_bins"], 8)
        # no proportional boundary allocation: the 0.4s/0.6s edges are out
        self.assertEqual(sel["requested"], [base + 0.4, base + 9.6])

    def test_terminal_partial_bin_and_truncated_checkpoint(self):
        # A final partial bin must not join the analysis; a checkpoint
        # 'starting' without 'complete' is a truncated drain artifact, not
        # a trough.
        base = 1767225600
        # last bin carries the drain collapse; the requested interval ends
        # at 9.4s so [9,10) is NOT fully contained and must be excluded —
        # otherwise it would fake a 3/s trough.
        bins = self._series(base, [20] * 9 + [3])
        sel = ca.effective_bins(base, base + 9.4, set(map(int, bins)))
        self.assertEqual(sel["bins"], list(range(base, base + 9)))
        self.assertNotIn(base + 9, sel["bins"])   # [9,10) not fully inside
        m = ca.window_metrics(sel, bins, 20.0)
        self.assertEqual(m["min_completed_s"], 20)
        self.assertEqual(m["episodes"], [])

    def test_missing_bins_break_recovery_adjacency(self):
        base = 1767225600
        # 20 good, 5 bad, gap(missing 2 bins), 10 good
        counts = [20] * 20 + [5] * 5 + [20] * 12
        bins = self._series(base, counts, missing={27, 28})
        sel = ca.effective_bins(base, base + 37, set(map(int, bins)))
        recs = [ca.bin_record(bins.get(str(s))) for s in sel["bins"]]
        eps = ca.deficit_episodes(sel["bins"], recs, 20.0)
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        self.assertEqual(ep["duration_s"], 5)
        # bins 25,26 good then 27,28 MISSING then 29.. good: recovery run
        # starts only after the gap (>=5 consecutive covered good bins)
        self.assertTrue(ep["recovered"])
        self.assertEqual(ep["recovery_run_start_s"], base + 29)
        self.assertEqual(ep["recovery_s"], (base + 33 + 1) - (base + 20))

    def test_two_dips_are_two_episodes(self):
        base = 1767225600
        counts = [20] * 10 + [5] * 3 + [20] * 8 + [3] * 4 + [20] * 10
        bins = self._series(base, counts)
        sel = ca.effective_bins(base, base + 35, set(map(int, bins)))
        recs = [ca.bin_record(bins.get(str(s))) for s in sel["bins"]]
        eps = ca.deficit_episodes(sel["bins"], recs, 20.0)
        self.assertEqual(len(eps), 2)
        self.assertEqual(eps[0]["episode_start_s"], base + 10)
        self.assertEqual(eps[0]["duration_s"], 3)
        self.assertEqual(eps[1]["episode_start_s"], base + 21)
        self.assertEqual(eps[1]["duration_s"], 4)
        self.assertEqual(eps[0]["hole_area_ops"], 45.0)
        self.assertEqual(eps[1]["hole_area_ops"], 68.0)

    def test_irregular_sampling_missing_not_zero(self):
        base = 1767225600
        # every other second missing -> all reported as missing bins,
        # never silently joined as zeros
        counts = [20] * 20
        bins = self._series(base, counts, missing=set(range(1, 20, 2)))
        sel = ca.effective_bins(base, base + 20, set(map(int, bins)))
        self.assertEqual(sel["missing"],
                         [base + i for i in range(1, 20, 2)])
        self.assertEqual(len(sel["covered"]), 10)


class WalIoDeltaTest(unittest.TestCase):
    def _rows(self, wal_series, reset="t0"):
        rows = []
        for i, wb in enumerate(wal_series):
            rows.append({"type": "sample", "seq": i, "ts": float(100 + i),
                         "pg": {"wal": {"row": {
                             "wal_bytes": wb, "wal_fpi": i * 10,
                             "wal_records": i * 100,
                             "stats_reset": reset if not isinstance(
                                 wb, tuple) else wb[1]}}}})
        return rows

    def test_wal_reset_breaks_even_when_counter_grows(self):
        # stats_reset change -> no delta across the break even though the
        # new counter is LARGER than the old one.
        rows = [
            {"type": "sample", "ts": 100.0,
             "pg": {"wal": {"row": {"wal_bytes": 1000,
                                    "stats_reset": "t0"}}}},
            {"type": "sample", "ts": 101.0,
             "pg": {"wal": {"row": {"wal_bytes": 5000,
                                    "stats_reset": "t1"}}}},  # reset!
            {"type": "sample", "ts": 102.0,
             "pg": {"wal": {"row": {"wal_bytes": 6000,
                                    "stats_reset": "t1"}}}},
        ]
        deltas, breaks = ca.wal_deltas(rows)
        self.assertEqual(breaks, 1)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["wal_bytes"], 1000)  # 6000-5000 only

    def test_wal_counter_regression_breaks(self):
        rows = self._rows([1000, 2000, 500, 1500])
        deltas, breaks = ca.wal_deltas(rows)
        self.assertEqual(breaks, 1)
        self.assertEqual([d["wal_bytes"] for d in deltas], [1000, 1000])

    def test_wal_absent_columns_stay_null_not_zero(self):
        # PG18 pg_stat_wal has no wal_write_time/wal_sync_time columns;
        # deltas must surface null (unavailable), never a fabricated 0.
        rows = self._rows([1000, 2000, 3000])
        deltas, breaks = ca.wal_deltas(rows)
        self.assertEqual(breaks, 0)
        self.assertEqual(len(deltas), 2)
        for d in deltas:
            self.assertIsNone(d["wal_write_ms"])
            self.assertIsNone(d["wal_sync_ms"])
            self.assertEqual(d["wal_bytes"], 1000)
        self.assertIsNone(ca.sum_in_window(deltas, "wal_write_ms"))
        self.assertEqual(ca.sum_in_window(deltas, "wal_bytes"), 2000)

    def test_rolling_volume_is_time_window_not_sample_count(self):
        # 2s-spaced samples: a 10s rolling volume must span ~5 deltas,
        # not 10 samples.
        deltas = [{"t0": 100.0 + 2 * i, "t1": 102.0 + 2 * i, "dt": 2.0,
                   "wal_bytes": 100} for i in range(10)]
        v10 = ca.rolling_time_volume(deltas, "wal_bytes", 10)
        # (t-10, t] over 2s-spaced deltas covers exactly 5 deltas/10s —
        # a sample-COUNT window would wrongly take 10 samples (=20s).
        self.assertEqual(v10, 500)
        v30 = ca.rolling_time_volume(deltas, "wal_bytes", 30)
        self.assertEqual(v30, 1000)

    def test_io_rows_keep_role_and_object_distinct(self):
        rows = []
        for i in range(3):
            rows.append({"type": "sample", "ts": 100.0 + i,
                         "pg": {"io": {"rows": [
                             {"backend_type": "checkpointer",
                              "object": "relation", "context": "normal",
                              "reads": 0, "writes": i * 10,
                              "write_bytes": i * 500_000, "extends": 0,
                              "fsyncs": i, "fsync_time": i * 100,
                              "read_bytes": 0, "read_time": 0,
                              "write_time": i * 50, "extend_time": 0},
                             {"backend_type": "checkpointer",
                              "object": "wal", "context": "normal",
                              "reads": 0, "writes": i * 2,
                              "write_bytes": i * 100_000,
                              "extends": None, "extend_time": None,
                              "fsyncs": i * 4, "fsync_time": i * 40,
                              "read_bytes": 0, "read_time": 0,
                              "write_time": i * 20,
                              "stats_reset": "t0"}]}}})
        deltas, breaks = ca.io_deltas(rows)
        self.assertEqual(breaks, 0)
        keys = {(d["backend_type"], d["object"]) for d in deltas}
        self.assertEqual(keys, {("checkpointer", "relation"),
                                ("checkpointer", "wal")})
        rel = [d for d in deltas if d["object"] == "relation"]
        wal = [d for d in deltas if d["object"] == "wal"]
        self.assertEqual(rel[-1]["write_bytes"], 500_000)
        self.assertEqual(wal[-1]["write_bytes"], 100_000)
        self.assertNotEqual(rel[-1]["fsync_time"], wal[-1]["fsync_time"])
        # null columns stay null — never silently zeroed nor dropped
        self.assertIsNone(wal[-1]["extends"])

    def test_missing_observer_row_counts_as_break(self):
        # A sample row without the counter block interrupts continuity:
        # the delta stream resumes but the break MUST be counted —
        # `prev = None; breaks += 1 if prev is not None` counted nothing.
        rows = self._rows([1000, 2000])
        rows.append({"type": "sample", "seq": 2, "ts": 102.0,
                     "pg": {}})          # missing wal row entirely
        rows += [{"type": "sample", "seq": 3, "ts": 103.0,
                  "pg": {"wal": {"row": {"wal_bytes": 4000,
                                         "stats_reset": "t0"}}}},
                 {"type": "sample", "seq": 4, "ts": 104.0,
                  "pg": {"wal": {"row": {"wal_bytes": 5000,
                                         "stats_reset": "t0"}}}}]
        deltas, breaks = ca.wal_deltas(rows)
        self.assertEqual(breaks, 1)
        self.assertEqual([d["wal_bytes"] for d in deltas], [1000, 1000])
        # same fix on the pool path
        pool_rows = [
            {"type": "sample", "ts": 100.0,
             "pool": {"acquire_count": 10, "wait_nanos_total": 1000}},
            {"type": "sample", "ts": 101.0},           # missing pool
            {"type": "sample", "ts": 102.0,
             "pool": {"acquire_count": 30, "wait_nanos_total": 3000}},
            {"type": "sample", "ts": 103.0,
             "pool": {"acquire_count": 40, "wait_nanos_total": 4000}}]
        deltas, breaks = ca.pool_deltas(pool_rows)
        self.assertEqual(breaks, 1)
        self.assertEqual(len(deltas), 1)

    def test_io_stats_reset_breaks_row_continuity(self):
        row = lambda wb, reset: {"backend_type": "client backend",
                                 "object": "wal", "context": "normal",
                                 "write_bytes": wb, "fsync_time": 0,
                                 "stats_reset": reset}
        rows = [
            {"type": "sample", "ts": 100.0,
             "pg": {"io": {"rows": [row(1000, "t0")]}}},
            {"type": "sample", "ts": 101.0,
             "pg": {"io": {"rows": [row(5000, "t1")]}}},
            {"type": "sample", "ts": 102.0,
             "pg": {"io": {"rows": [row(6000, "t1")]}}},
        ]
        deltas, breaks = ca.io_deltas(rows)
        self.assertEqual(breaks, 1)
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0]["write_bytes"], 1000)

    def test_disk_deltas_per_device_await_and_queue(self):
        def diskrow(ts, dev_writes, dev_ms, dev_sectors, dev_doing,
                    dev_weighted):
            return {"type": "sample", "ts": ts,
                    "disk": {"md0": {"reads": 0, "reads_merged": 0,
                                     "sectors_read": 0, "ms_reading": 0,
                                     "writes": dev_writes,
                                     "writes_merged": 0,
                                     "sectors_written": dev_sectors,
                                     "ms_writing": dev_ms,
                                     "ios_in_progress": 0,
                                     "ms_doing_io": dev_doing,
                                     "weighted_ms_doing_io": dev_weighted},
                             "vdb": {"reads": 0, "reads_merged": 0,
                                     "sectors_read": 0, "ms_reading": 0,
                                     "writes": 1,
                                     "writes_merged": 0,
                                     "sectors_written": 512,
                                     "ms_writing": 2,
                                     "ios_in_progress": 0,
                                     "ms_doing_io": 2,
                                     "weighted_ms_doing_io": 2}}}
        rows = [diskrow(100.0, 10, 100, 1000, 500, 500),
                diskrow(101.0, 20, 300, 3000, 1100, 1400)]
        deltas, breaks = ca.disk_deltas(rows)
        self.assertEqual(breaks, 0)
        md = deltas["md0"][0]
        self.assertAlmostEqual(md["write_Bps"], 2000 * 512.0)
        self.assertAlmostEqual(md["write_await_ms"], 200 / 10)
        self.assertAlmostEqual(md["util"], 0.6)
        self.assertAlmostEqual(md["avg_queue"], 0.9)
        # md0 and vdb are separate entries — never summed
        self.assertIn("vdb", deltas)
        self.assertNotEqual(deltas["md0"], deltas["vdb"])

    def test_cpu_ticks_delta_ratios(self):
        rows = [
            {"type": "sample", "ts": 100.0,
             "cpu": {"user": 0, "nice": 0, "system": 0, "idle": 0,
                     "iowait": 0, "irq": 0, "softirq": 0, "steal": 0}},
            {"type": "sample", "ts": 101.0,
             "cpu": {"user": 100, "nice": 0, "system": 100, "idle": 600,
                     "iowait": 100, "irq": 0, "softirq": 100, "steal": 0}},
        ]
        deltas, breaks = ca.cpu_deltas(rows)
        self.assertEqual(breaks, 0)
        self.assertAlmostEqual(deltas[0]["iowait_pct"], 10.0)
        self.assertAlmostEqual(deltas[0]["idle_pct"], 60.0)


class CommonWindowTest(unittest.TestCase):
    """Common window = intersection of actual scenario measurement
    windows. Container lifecycle timestamps are provenance, never the
    measurement boundary."""

    def test_contract_sidecar_beats_container_times(self):
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_075_000,
                "scenario_clock_ok": 1},
            "sidecars": [{
                "name": "refresh",
                # container bounds LOOK wider than the true window
                "started_ts": 1_000_000.0, "ended_ts": 1_000_090.0,
                "duration_s": 60,
                "window": {"kind": "contract",
                           "measure_start_s": 1_000_020.388,
                           "measure_end_s": 1_000_070.388,
                           "scenario_clock_ok": 1}}]}
        loads = ca.load_windows(cfg)
        cw = ca.common_window(loads)
        self.assertTrue(cw["recoverable"])
        self.assertTrue(cw["exact"])
        # common = max(starts)/min(ends) on MEASUREMENT bounds
        self.assertEqual(cw["start"], 1_000_020.388)
        self.assertEqual(cw["end"], 1_000_070.388)

    def test_independent_warmups_intersect(self):
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_075_000,
                "scenario_clock_ok": 1},
            "sidecars": [
                {"name": "a", "window": {"kind": "contract",
                                         "measure_start_s": 1_000_017.0,
                                         "measure_end_s": 1_000_074.0,
                                         "scenario_clock_ok": 1}},
                {"name": "b", "window": {"kind": "contract",
                                         "measure_start_s": 1_000_022.0,
                                         "measure_end_s": 1_000_072.0,
                                         "scenario_clock_ok": 1}}]}
        cw = ca.common_window(ca.load_windows(cfg))
        self.assertEqual(cw["start"], 1_000_022.0)   # latest measure start
        self.assertEqual(cw["end"], 1_000_072.0)     # earliest measure end

    def test_bounded_sidecar_gives_conservative_window(self):
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_095_000,
                "scenario_clock_ok": 1},
            "sidecars": [{
                "name": "meta",
                "started_ts": 1_000_010.0, "ended_ts": 1_000_093.0,
                "duration_s": 60,
                "window": {"kind": "bounded", "duration_s": 60}}]}
        loads = ca.load_windows(cfg)
        side = loads[1]
        self.assertFalse(side["exact"])
        # proven bounds: start in [container_start+warmup,
        # container_end-duration+warmup]; end in [container_start+duration,
        # container_end]
        self.assertEqual(side["measure_start_lb"], 1_000_025.0)
        self.assertEqual(side["measure_start_ub"], 1_000_048.0)
        self.assertEqual(side["measure_end_lb"], 1_000_070.0)
        self.assertEqual(side["measure_end_ub"], 1_000_093.0)
        cw = ca.common_window(loads)
        self.assertTrue(cw["recoverable"])
        self.assertFalse(cw["exact"])
        self.assertEqual(cw["basis"], "conservative_bounds")
        self.assertEqual(cw["start"], 1_000_048.0)
        self.assertEqual(cw["end"], 1_000_070.0)

    def test_missing_evidence_marks_unrecoverable(self):
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_075_000,
                "scenario_clock_ok": 1},
            "sidecars": [{"name": "x"}]}   # no window, no container times
        cw = ca.common_window(ca.load_windows(cfg))
        self.assertFalse(cw["recoverable"])

    def test_bad_clock_sidecar_cannot_be_exact(self):
        # kind=contract with scenario_clock_ok != 1 must NOT count as an
        # exact contract window — it falls back to bounded provenance.
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_095_000,
                "scenario_clock_ok": 1},
            "sidecars": [{
                "name": "meta",
                "started_ts": 1_000_010.0, "ended_ts": 1_000_093.0,
                "duration_s": 60,
                "window": {"kind": "contract",
                           "measure_start_s": 1_000_020.0,
                           "measure_end_s": 1_000_080.0,
                           "scenario_clock_ok": 0}}]}
        loads = ca.load_windows(cfg)
        self.assertFalse(loads[1]["exact"])
        self.assertEqual(loads[1]["kind"], "bounded")
        cw = ca.common_window(loads)
        self.assertFalse(cw["exact"])
        self.assertEqual(cw["basis"], "conservative_bounds")

    def test_divergent_or_inverted_contract_not_exact(self):
        cfg = {
            "warmup_s": 15,
            "measurement_contract": {
                "window_start_ms": 1_000_015_000,
                "window_end_ms": 1_000_095_000,
                "scenario_clock_ok": 1},
            "sidecars": [{
                "name": "a",
                "started_ts": 1_000_010.0, "ended_ts": 1_000_093.0,
                "duration_s": 60,
                "window": {"kind": "contract",
                           "measure_start_s": 1_000_020.0,
                           "measure_end_s": 1_000_080.0,
                           "scenario_clock_ok": 1,
                           "divergent_vus": True}},
                {"name": "b",
                 "started_ts": 1_000_010.0, "ended_ts": 1_000_093.0,
                 "duration_s": 60,
                 "window": {"kind": "contract",
                            "measure_start_s": 1_000_090.0,
                            "measure_end_s": 1_000_020.0,   # inverted
                            "scenario_clock_ok": 1}}]}
        loads = ca.load_windows(cfg)
        self.assertFalse(loads[1]["exact"])   # divergent_vus
        self.assertFalse(loads[2]["exact"])   # start >= end


class QuantileTest(unittest.TestCase):
    def test_constant_samples_exact_quantile(self):
        self.assertEqual(ca.sample_quantile([20.0] * 100, 0.95), 20.0)

    def test_bucketed_quantile_is_interval_not_fake_exact(self):
        h = ca.new_hist()
        for _ in range(100):
            ca.hist_add(h, 20.0)
        s = ca.hist_stats(h, ca.HISTOGRAM_SCHEMA)
        p95 = s["p95"]
        self.assertTrue(p95["estimate"])
        lo, hi = p95["interval_ms"]
        self.assertLessEqual(lo, 20.0)
        self.assertLessEqual(20.0, hi if hi is not None else float("inf"))
        # the interval is a bucket, not a fabricated 48.5ms precision
        self.assertNotEqual(p95["estimate_ms"], 48.5)

    def test_stream_v1_semantics_are_lower_inclusive(self):
        # stream-v1 assigns `v < bound`: 20 lands in [20,50), not (10,20].
        h = ca.new_hist()
        for _ in range(10):
            ca.hist_add(h, 20.0)
            ca.hist_add(h, 5.0)      # 5 -> [5,10) bucket
        s = ca.hist_stats(h, ca.HISTOGRAM_SCHEMA)
        self.assertEqual(s["p50"]["interval_ms"], [5, 10])
        self.assertEqual(s["p50"]["interval_semantics"], "[lo,hi)")
        # 20 is NOT in (10,20]: under `v < bound` it goes to [20,50)
        self.assertEqual(s["p95"]["interval_ms"], [20, 50])

    def test_resolve_hist_schema_stream_v1_artifact(self):
        bounds = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000,
                  2000, 5000, 10000]
        schema = ca.resolve_hist_schema({
            "generator": "checkpoint_analyze.stream-v1",
            "hist_bounds_ms": bounds})
        self.assertEqual(schema["bounds"], bounds)
        self.assertFalse(schema["upper_inclusive"])
        # a persisted bucket array under these bounds resolves to
        # [prev, bound) intervals
        h = {"n": 100, "sum": 0, "min": 1, "max": 1,
             "b": [0] * (len(bounds) + 1)}
        h["b"][5] = 100            # bucket [20,50)
        s = ca.hist_stats(h, schema)
        self.assertEqual(s["p95"]["interval_ms"], [20.0, 50.0])

    def test_unknown_histogram_schema_is_unavailable(self):
        self.assertIsNone(ca.resolve_hist_schema({"bins": {}}))
        self.assertIsNone(ca.resolve_hist_schema(
            {"generator": "something-else", "hist_bounds_ms": [1, 2]}))
        h = ca.new_hist()
        ca.hist_add(h, 5.0)
        s = ca.hist_stats(h, None)
        self.assertIn("unavailable", s["p95"])
        # bucket count that disagrees with declared bounds is also
        # unavailable — never reinterpreted
        bad = dict(ca.HISTOGRAM_SCHEMA)
        bad["bounds"] = [1, 2, 5]
        s2 = ca.hist_stats(h, bad)
        self.assertIn("unavailable", s2["p95"])

    def test_mergeable_quantiles(self):
        a, b = ca.new_hist(), ca.new_hist()
        for v in range(1, 101):
            ca.hist_add(a if v <= 50 else b, float(v))
        h = ca.hist_merge(a, b)
        s = ca.hist_stats(h, ca.HISTOGRAM_SCHEMA)
        self.assertEqual(s["n"], 100)
        lo95, hi95 = s["p95"]["interval_ms"]
        self.assertLessEqual(lo95, 95.0)
        self.assertLessEqual(95.0, hi95)

    def test_empty_hist(self):
        self.assertEqual(ca.hist_stats(ca.new_hist(), None), {"n": 0})


class EvaluatorTest(unittest.TestCase):
    """capacity_search.evaluate: capRun detection by markers, strict
    contract validity, no fallback denominators."""

    def _summary(self, completed=0, dropped=0, status="passed",
                 p95=10, p99=20):
        return {"status": status,
                "k6": {"iterations_completed": completed,
                       "dropped_iterations": dropped,
                       "rps": completed / 600 if completed else 0,
                       "error_rate": 0.0,
                       "latency_ms": {"p50": 5, "p95": p95, "p99": p99}}}

    def _k6_file(self, tmp, metrics, contract=None):
        d = {"metrics": metrics}
        if contract:
            d["measurement_contract"] = contract
        p = tmp / "x.k6.json"
        p.write_text(json.dumps(d))
        return p

    def _contract(self, **over):
        c = {"contract": "cap-scenario-window-v1",
             "window_start_ms": 1_000_015_000,
             "window_end_ms": 1_000_600_000,
             "window_seconds": 585.0,
             "scenario_start_ms": 1_000_000_000,
             "duration_ms": 600_000,
             "scenario_clock_ok": 1,
             "divergent_vus": False}
        c.update(over)
        return c

    def test_caprun_zero_ops_stays_contract_basis(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = self._k6_file(
                tmp, {"cap_measure_ops": {"values": {"count": 0}},
                      "cap_iter_begin": {"values": {"count": 0}},
                      "cap_iter_begin_measure": {"values": {"count": 0}},
                      "cap_measure_success": {"values": {"count": 0}}},
                contract=self._contract())
            summary = tmp / "latest.json"
            verdict, m = cs.evaluate(self._summary(), summary, 100, 600,
                                     "cap_client_credentials")
            # real markers -> capRun; ops=0 is a legitimate 0 ops/s on the
            # contract basis (585s window), not INVALID and not
            # full_scenario.
            self.assertEqual(m["rate_basis"], "scenario_window")
            self.assertEqual(m["window_seconds"], 585.0)
            self.assertEqual(m["measured_ops_s"], 0.0)
            self.assertEqual(verdict, "FAIL")   # 0 << 99.5% of target
        finally:
            shutil.rmtree(tmp)

    def test_missing_contract_is_invalid(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            # cap markers present but no contract at all
            p = self._k6_file(
                tmp, {"cap_measure_ops": {"values": {"count": 500}}})
            verdict, m = cs.evaluate(self._summary(completed=500),
                                     tmp / "latest.json", 100, 600, "cap_x")
            self.assertEqual(verdict, "INVALID")
            self.assertIn("missing_contract", m["contract_problems"])
        finally:
            shutil.rmtree(tmp)

    def test_inverted_window_is_invalid(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = self._k6_file(
                tmp, {"cap_measure_ops": {"values": {"count": 500}}},
                contract=self._contract(
                    window_end_ms=1_000_010_000))  # end < start
            verdict, m = cs.evaluate(self._summary(completed=500),
                                     tmp / "latest.json", 100, 600, "cap_x")
            self.assertEqual(verdict, "INVALID")
        finally:
            shutil.rmtree(tmp)

    def test_divergent_vus_invalid(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = self._k6_file(
                tmp, {"cap_measure_ops": {"values": {"count": 500}}},
                contract=self._contract(divergent_vus=True))
            verdict, m = cs.evaluate(self._summary(completed=500),
                                     tmp / "latest.json", 100, 600, "cap_x")
            self.assertEqual(verdict, "INVALID")
        finally:
            shutil.rmtree(tmp)

    def test_non_caprun_full_scenario_denominator(self):
        # 600s scenario, 600000 completions -> exactly 1000/s on the
        # full-scenario basis; NEVER completed/(duration-15).
        tmp = Path(tempfile.mkdtemp())
        try:
            p = self._k6_file(tmp, {"iterations": {"values":
                                                   {"count": 600000}}})
            verdict, m = cs.evaluate(self._summary(completed=600000),
                                     tmp / "latest.json", 1000, 600,
                                     "metadata_jwks")
            self.assertEqual(m["rate_basis"], "full_scenario")
            self.assertEqual(m["measured_ops_s"], 1000.0)
            self.assertEqual(verdict, "PASS")
        finally:
            shutil.rmtree(tmp)

    def test_non_caprun_shell_contract_is_not_caprun(self):
        # Regression for the real fapi/capacity-fapi2-logged-in-high-
        # security.k6.json counterexample: older handleSummary attached a
        # measurement_contract shell to EVERY scenario. A shell object with
        # all-null bounds and no cap markers must not be classified capRun
        # (which would produce INVALID instead of a full-scenario rate).
        tmp = Path(tempfile.mkdtemp())
        try:
            shell = {"contract": "cap-scenario-window-v1",
                     "window_start_ms": None, "window_end_ms": None,
                     "window_seconds": None, "scenario_start_ms": None,
                     "duration_ms": None, "scenario_clock_ok": None,
                     "divergent_vus": None}
            p = self._k6_file(
                tmp, {"iterations": {"values": {"count": 600000}},
                      "http_reqs": {"values": {"count": 1200000}}},
                contract=shell)
            verdict, m = cs.evaluate(self._summary(completed=600000),
                                     tmp / "latest.json", 1000, 600,
                                     "fapi2_logged_in_high_security")
            self.assertEqual(m["rate_basis"], "full_scenario")
            self.assertEqual(m["measured_ops_s"], 1000.0)
            self.assertNotEqual(verdict, "INVALID")
            self.assertEqual(verdict, "PASS")
        finally:
            shutil.rmtree(tmp)

    def test_measurement_evidence_errors_are_invalid(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            self._k6_file(
                tmp, {"cap_measure_ops": {"values": {"count": 500}},
                      "cap_iter_begin_measure": {"values": {"count": 500}},
                      "cap_iter_begin": {"values": {"count": 500}},
                      "cap_iter_end": {"values": {"count": 500}},
                      "cap_measure_success": {"values": {"count": 500}}},
                contract=self._contract())
            summary = self._summary(completed=500)
            summary["measurement_evidence"] = {"window_valid": False}
            verdict, m = cs.evaluate(summary, tmp / "latest.json", 100,
                                     600, "cap_x")
            self.assertEqual(verdict, "INVALID")
            self.assertEqual(m["reason"], "measurement_evidence_invalid")
            summary["measurement_evidence"] = {"parse_errors": 3}
            verdict, m = cs.evaluate(summary, tmp / "latest.json", 100,
                                     600, "cap_x")
            self.assertEqual(verdict, "INVALID")
            summary["measurement_evidence"] = {"reader_error": "boom"}
            verdict, m = cs.evaluate(summary, tmp / "latest.json", 100,
                                     600, "cap_x")
            self.assertEqual(verdict, "INVALID")
            # clean evidence does not invalidate
            summary["measurement_evidence"] = {"window_valid": True,
                                               "parse_errors": 0,
                                               "reader_error": None}
            verdict, m = cs.evaluate(summary, tmp / "latest.json", 100,
                                     600, "cap_x")
            self.assertNotEqual(verdict, "INVALID")
        finally:
            shutil.rmtree(tmp)

    def test_load_generator_requires_independent_evidence(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = self._k6_file(tmp, {"iterations": {"values":
                                                   {"count": 500}}})
            summary = self._summary(completed=500, dropped=10,
                                    status="threshold_failed")
            verdict, m = cs.evaluate(summary, tmp / "latest.json", 100,
                                     600, "metadata_jwks")
            # drops+threshold alone: no independent generator evidence ->
            # plain FAIL, NOT LOAD_GENERATOR_INVALID
            self.assertEqual(verdict, "FAIL")
            self.assertEqual(m.get("load_generator_evidence"), "absent")
            # Analyzer findings are NOT generator-resource evidence: a
            # lagging stream consumer is evidence-pipeline invalidity
            # (checked on capRun stream evidence), a truncated diag is a
            # forensic caveat. Neither feeds load_generator_evidence.
            (tmp / "x.analyzer-stats.json").write_text(
                json.dumps({"lag_over_5s": 3, "diag_overflow": True}))
            verdict2, m2 = cs.evaluate(summary, tmp / "latest.json", 100,
                                       600, "metadata_jwks")
            self.assertEqual(verdict2, "FAIL")
            self.assertEqual(m2.get("load_generator_evidence"), "absent")
        finally:
            shutil.rmtree(tmp)

    def test_invalid_stops_search(self):
        tmp = Path(tempfile.mkdtemp())
        old_root, old_eval, old_run = cs.OUT_ROOT, cs.evaluate, cs.run_isolated
        try:
            cs.OUT_ROOT = tmp
            cs.run_isolated = lambda *a, **k: tmp / "latest.json"
            calls = []
            def fake_eval(*a, **k):
                calls.append(1)
                return "INVALID", {"reason": "missing_or_inconsistent_"
                                           "measurement_contract"}
            cs.evaluate = fake_eval
            cs.load_summary = lambda p: {"status": "passed", "k6": {}}
            res = cs.search("cap_client_credentials", 100)
            self.assertEqual(len(calls), 1)          # stopped after 1 point
            self.assertIsNotNone(res["invalid"])
            self.assertIsNone(res["first_fail_above"])
        finally:
            cs.OUT_ROOT, cs.evaluate, cs.run_isolated = (
                old_root, old_eval, old_run)
            shutil.rmtree(tmp)


class ReportTest(unittest.TestCase):
    def _fixture(self, tmp, truncated_checkpoint=False, missing_bins=None,
                 n_bins=120, hole=(40, 50), ckpt=(50, 70),
                 contract_off=(15, 120), sidecars=None, drop_bins=None,
                 declare_schema=True):
        # series: n_bins bins at 20/s, a hole (5/s) inside `hole`
        bins = {}
        base = FIXTURE_BASE
        missing_bins = missing_bins or set()
        drop_bins = drop_bins or set()
        for s in range(n_bins):
            if s in missing_bins:
                continue
            sec = base + s
            comp = 20 if not (hole[0] <= s < hole[1]) else 5
            bins[str(sec)] = {
                "begins": {"measure": comp}, "begins_pair": {"measure|1": comp},
                "ends": {f"measure|1|success": comp},
                "iterations": comp,
                "dropped": 1 if s in drop_bins else 0,
                "vus": 4, "vus_max": 8,
                "http_reqs": comp * 2, "http_req_failed": 0,
                "data_received": 0, "data_sent": 0,
                "cap_measure_ms": ca.new_hist(),
                "cap_iter_ms": ca.new_hist(),
                "http_req_duration": ca.new_hist(),
            }
            ca.hist_add(bins[str(sec)]["cap_measure_ms"], 5.0)
            ca.hist_add(bins[str(sec)]["http_req_duration"], 3.0)
        series = {"format": "per-second-v1", "bins": bins}
        if declare_schema:
            # mirror the real persisted artifact: stream-v1 generator +
            # explicit bounds
            series.update({"generator": "checkpoint_analyze.stream-v1",
                           "hist_bounds_ms": list(ca.BUCKETS)})
        (tmp / "series.json").write_text(json.dumps(series))
        rows = []
        for s in range(n_bins + 5):
            sec = base + s
            rows.append({"type": "sample", "seq": s, "ts": float(sec),
                         "ts_utc": "x",
                         "pg": {"wal": {"row": {"wal_bytes": s * 1_000_000,
                                                "wal_fpi": s * 10,
                                                "wal_records": s * 500,
                                                "stats_reset": "t0"},
                                        "row_count": 1},
                                "io": {"rows": [
                                    {"backend_type": "checkpointer",
                                     "object": "relation", "context": "normal",
                                     "reads": 0, "writes": s * 5,
                                     "write_bytes": s * 500_000,
                                     "extends": 0, "fsyncs": s,
                                     "fsync_time": s * 10,
                                     "read_bytes": 0, "read_time": 0,
                                     "write_time": s * 20,
                                     "extend_time": 0},
                                    {"backend_type": "checkpointer",
                                     "object": "wal", "context": "normal",
                                     "reads": 0, "writes": s * 2,
                                     "write_bytes": s * 100_000,
                                     "extends": 0, "fsyncs": s * 3,
                                     "fsync_time": s * 2,
                                     "read_bytes": 0, "read_time": 0,
                                     "write_time": s * 5,
                                     "extend_time": 0},
                                ]}},
                         "mem": {"dirty_kb": 1000, "writeback_kb": 10},
                         "cpu": {"user": s, "nice": 0, "system": s,
                                 "idle": s * 8, "iowait": 0, "irq": 0,
                                 "softirq": 0, "steal": 0}})
        (tmp / "obs.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
        start_ts = base + ckpt[0]
        complete_ts = base + ckpt[1]

        def pgts(ts):
            import datetime as _dt
            d = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
            return d.strftime("%Y-%m-%dT%H:%M:%S.000000Z"), d.strftime(
                "%Y-%m-%d %H:%M:%S.000 UTC")

        s1, s2 = pgts(start_ts)
        pg = (f"{s1} {s2} [1] LOG:  checkpoint starting: time\n")
        if ckpt[1] is not None:
            c1, c2 = pgts(complete_ts)
            pg += (f"{c1} {c2} [1] "
                   "LOG:  checkpoint complete: wrote 100 buffers (50.0%); "
                   "0 WAL file(s) added, 0 removed, 1 recycled; "
                   "write=15.000 s, sync=3.000 s, total=20.000 s; "
                   "sync files=5, longest=1.0 s, average=0.5 s; "
                   "distance=1000 kB, estimate=900 kB\n")
        if truncated_checkpoint:
            t1, t2 = pgts(base + n_bins - 2)
            pg += (f"{t1} {t2} [1] "
                   "LOG:  checkpoint starting: time\n")
        (tmp / "pg.log").write_text(pg)
        cfg = {"target_rate": 20, "duration_s": 120, "warmup_s": 15,
               "measurement_contract": {
                   "contract": "cap-scenario-window-v1",
                   "window_start_ms": (base + contract_off[0]) * 1000,
                   "window_end_ms": (base + contract_off[1]) * 1000,
                   "scenario_clock_ok": 1},
               "sidecars": sidecars or []}
        (tmp / "cfg.json").write_text(json.dumps(cfg))
        return base

    def _run_report(self, tmp):
        p = subprocess.run(
            [sys.executable, str(ANALYZER), "report",
             "--series", str(tmp / "series.json"),
             "--observer", str(tmp / "obs.jsonl"),
             "--pglog", str(tmp / "pg.log"),
             "--config", str(tmp / "cfg.json"),
             "--out", str(tmp / "out")],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        return tmp / "out"

    def test_report_pipeline(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(tmp)
            out = self._run_report(tmp)
            rec = json.loads((out / "measurement-reconciliation.json")
                             .read_text())
            self.assertEqual(rec["legacy_vs_unified"]["legacy_rule_ops"],
                             rec["arrival_fidelity"]["started_total"])
            win = json.loads((out / "checkpoint-windows.json").read_text())
            cps = win["checkpoints"]
            self.assertEqual(len(cps), 1)
            self.assertEqual(cps[0]["id"], "ckpt-1")
            self.assertTrue(cps[0]["evidence_sufficient"])
            self.assertEqual(cps[0]["write_s"], 15.0)
            # complete_local tail (+90s) is cut at the common-window end
            self.assertTrue(cps[0]["truncated"])
            # two local windows exist explicitly; the union is their
            # deduped bins — never one continuous start->complete span
            self.assertIn("start_window", cps[0])
            self.assertIn("complete_window", cps[0])
            self.assertIn("local_union", cps[0])
            m = cps[0]["local_union"]
            self.assertGreater(m["hole_area_ops"], 100)
            self.assertEqual(len(m["episodes"]), 1)
            ep = m["episodes"][0]
            self.assertEqual(ep["episode_start_s"], base + 40)
            # min_at_s is an epoch second, never an array index
            self.assertTrue(all(t >= base for t in ep["min_at_s"]))
            self.assertIn(base + 40, ep["min_at_s"])
            self.assertTrue(ep["recovered"])
            wal = json.loads((out / "wal-envelope.json").read_text())
            self.assertEqual(wal["mean_Bps"], 1_000_000)
            # WAL numerator and ops denominator share ONE effective
            # interval: the measurement window's full-second bins
            eff = rec["measurement_window"]["effective"]
            self.assertEqual(wal["interval"], eff)
            self.assertEqual(wal["wal_per_op"]["effective_interval"], eff)
            self.assertEqual(wal["wal_per_op"]["window_seconds"],
                             eff[1] - eff[0])
            self.assertEqual(wal["wal_per_op"]["ops_in_window"],
                             20 * 95 + 5 * 10)  # 105 covered bins w/ hole
            # io breakdown keeps wal vs relation distinct per backend;
            # deltas are per-(backend,object,context) records: 105
            # intervals x 2 rows.
            n_intervals = wal["io"]["deltas"] // 2
            ck = wal["io"]["by_backend"]["checkpointer"]
            self.assertEqual(ck["write_bytes"], 600_000 * n_intervals)
            self.assertEqual(sorted(ck["objects"]), ["relation", "wal"])
            obj = wal["io"]["by_object"]
            self.assertIn("wal", obj)
            self.assertIn("relation", obj)
            self.assertEqual(obj["relation"]["write_bytes"],
                             500_000 * n_intervals)
            self.assertEqual(obj["wal"]["write_bytes"],
                             100_000 * n_intervals)
            # low-cardinality cross dimension is preserved too
            dim = wal["io"]["by_dimension"]
            self.assertIn("checkpointer|relation|normal", dim)
            self.assertIn("checkpointer|wal|normal", dim)
            self.assertEqual(dim["checkpointer|relation|normal"]
                             ["write_bytes"], 500_000 * n_intervals)
            steady = json.loads((out / "steady-state.json").read_text())
            # steady = common-window bins minus checkpoint local union
            self.assertIsNotNone(steady["throughput_ops_per_s"])
            self.assertEqual(
                steady["basis"],
                "common_window_minus_checkpoint_local_windows")
            self.assertGreater(
                steady["excluded_checkpoint_local_bins"], 0)
            self.assertTrue((out / "checkpoint-timeline.csv").exists())
            validity = json.loads((out / "analysis-validity.json")
                                  .read_text())
            self.assertTrue(validity["valid"])
        finally:
            shutil.rmtree(tmp)

    def test_steady_state_excludes_checkpoint_bins(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(tmp)
            out = self._run_report(tmp)
            steady = json.loads((out / "steady-state.json").read_text())
            # checkpoint local windows cover bins base+20 .. base+119
            # (complete_local tail truncated at the common end):
            # steady = common bins base+15..19 = 5 bins
            self.assertEqual(steady["seconds"], 5)
            # all steady bins ran at 20/s — post-exclusion value differs
            # from any window that still contained the 5/s hole
            self.assertEqual(steady["throughput_ops_per_s"], 20.0)
            self.assertEqual(steady["unexpected"], 0)
            # latency categories stay distinct; quantiles are stream-v1
            # bucket intervals (5ms samples -> [5,10) bucket)
            self.assertIn("op_latency_ms", steady)
            self.assertIn("http_latency_ms", steady)
            self.assertEqual(steady["op_latency_ms"]["p95"]
                             ["interval_ms"], [5, 10])
            self.assertEqual(steady["op_latency_ms"]["p95"]
                             ["interval_semantics"], "[lo,hi)")
        finally:
            shutil.rmtree(tmp)

    def test_truncated_checkpoint_flagged_not_trough(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(tmp, truncated_checkpoint=True)
            out = self._run_report(tmp)
            win = json.loads((out / "checkpoint-windows.json").read_text())
            cps = win["checkpoints"]
            self.assertEqual(len(cps), 2)
            tail = cps[1]
            self.assertEqual(tail["missing_boundary"], "checkpoint_complete")
            self.assertTrue(tail["terminal_drain_artifact"])
            self.assertFalse(tail["evidence_sufficient"])
        finally:
            shutil.rmtree(tmp)

    def test_in_flight_boundary_reconciles(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(tmp)
            out = self._run_report(tmp)
            rec = json.loads((out / "measurement-reconciliation.json")
                             .read_text())
            ifb = rec["in_flight_boundary"]
            self.assertIsNotNone(ifb)
            self.assertTrue(ifb["reconciled"])
            self.assertEqual(ifb["in_flight_at_start"], 0)
            self.assertEqual(ifb["in_flight_at_end"], 0)
        finally:
            shutil.rmtree(tmp)

    def test_local_windows_exclude_middle_write_phase(self):
        # Checkpoint start=base+100, complete=base+300 -> the two local
        # windows are [start-30,start+90]=[70,190] and [270,390] clipped
        # to the common window; bins 190..269 are the middle write phase
        # and must NOT be inside local_union.
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(
                tmp, n_bins=400, hole=(230, 240), ckpt=(100, 300),
                contract_off=(20, 390),
                sidecars=[{"name": "s",
                           "window": {"kind": "contract",
                                      "measure_start_s": FIXTURE_BASE + 50,
                                      "measure_end_s": FIXTURE_BASE + 380,
                                      "scenario_clock_ok": 1}}])
            out = self._run_report(tmp)
            win = json.loads((out / "checkpoint-windows.json").read_text())
            cp = win["checkpoints"][0]
            sw, cw = cp["start_window"], cp["complete_window"]
            # common window = [base+50, base+380] (sidecar contract is
            # tighter than main [base+20, base+390])
            self.assertEqual(sw["effective_interval"],
                             [base + 70, base + 190])
            self.assertEqual(cw["effective_interval"],
                             [base + 270, base + 380])
            self.assertTrue(cw["truncated_end"])   # +90 tail cut at 380
            self.assertTrue(cp["clip_basis"].startswith("all-load common"))
            uni = cp["local_union"]
            # union = 120 + 110 covered bins — the 80-bin middle gap is
            # NOT part of checkpoint-local evidence
            self.assertEqual(uni["covered_bins"], 230)
            self.assertEqual(uni["missing_bins"], [])
            self.assertTrue(cp["evidence_sufficient"])
            rec = json.loads((out / "measurement-reconciliation.json")
                             .read_text())
            mid_dips = [d for d in rec["dips_below_99pct"]
                        if base + 230 <= d["s"] < base + 240]
            self.assertEqual(len(mid_dips), 10)
            self.assertTrue(all(not d["in_checkpoint_local"]
                                for d in mid_dips))
        finally:
            shutil.rmtree(tmp)

    def test_steady_uses_common_window_and_keeps_middle_dips(self):
        # Same fixture: common=[base+50,base+380] (330 bins), local union
        # 230 bins -> steady = 100 bins ([50..69] + [190..269]).
        # Drops live only in the pre-common VU-ramp bins 20..49, so a
        # common-window steady state must show drops==0, and the
        # middle-write-phase hole (bins 230..239) stays visible inside
        # steady — it is not checkpoint-local.
        tmp = Path(tempfile.mkdtemp())
        try:
            base = self._fixture(
                tmp, n_bins=400, hole=(230, 240), ckpt=(100, 300),
                contract_off=(20, 390), drop_bins=set(range(20, 50)),
                sidecars=[{"name": "s",
                           "window": {"kind": "contract",
                                      "measure_start_s": FIXTURE_BASE + 50,
                                      "measure_end_s": FIXTURE_BASE + 380,
                                      "scenario_clock_ok": 1}}])
            out = self._run_report(tmp)
            steady = json.loads((out / "steady-state.json").read_text())
            self.assertEqual(steady["common_seconds"], 330)
            self.assertEqual(steady["excluded_checkpoint_local_bins"], 230)
            self.assertEqual(steady["seconds"], 100)
            # pre-common ramp drops must not leak into steady state
            self.assertEqual(steady["drops"], 0)
            # 90 bins at 20/s + 10 hole bins at 5/s
            self.assertAlmostEqual(steady["throughput_ops_per_s"],
                                   (90 * 20 + 10 * 5) / 100, places=3)
            mids = steady["dips_in_steady"]
            self.assertEqual(len(mids), 10)
            self.assertTrue(all(base + 230 <= d["s"] < base + 240
                                for d in mids))
        finally:
            shutil.rmtree(tmp)

    def test_checkpoint_missing_bins_make_evidence_insufficient(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            self._fixture(tmp, missing_bins={40, 41})
            out = self._run_report(tmp)
            win = json.loads((out / "checkpoint-windows.json").read_text())
            cp = win["checkpoints"][0]
            self.assertFalse(cp["evidence_sufficient"])
            self.assertIn(FIXTURE_BASE + 40,
                          cp["start_window"]["missing_bins"])
            validity = json.loads((out / "analysis-validity.json")
                                  .read_text())
            self.assertFalse(validity["valid"])
            self.assertTrue(validity["checkpoint_evidence_gaps"])
        finally:
            shutil.rmtree(tmp)

    def test_unknown_histogram_schema_makes_quantiles_unavailable(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            self._fixture(tmp, declare_schema=False)
            out = self._run_report(tmp)
            steady = json.loads((out / "steady-state.json").read_text())
            self.assertIn("unavailable",
                          steady["op_latency_ms"]["p95"])
        finally:
            shutil.rmtree(tmp)


class ObserverFunctionTest(unittest.TestCase):
    """Tests call the observer's REAL transformation/query-handling
    functions — not hand-written arrays or JSON round-trips."""

    def test_fetch_pg_preserves_io_row_dimensions(self):
        class Desc:
            def __init__(self, name): self.name = name

        class Cur:
            def __init__(self, cols, rows):
                self.description = [Desc(c) for c in cols]
                self._rows = rows
            def fetchall(self):
                return self._rows

        class Conn:
            def execute(self, sql):
                if "pg_stat_io" in sql:
                    return Cur(
                        ["backend_type", "object", "context", "writes"],
                        [("checkpointer", "relation", "normal", 10),
                         ("checkpointer", "wal", "normal", 5)])
                return Cur(["x"], [(1,)])
            def rollback(self):
                pass

        out = obs.fetch_pg(Conn())
        rows = out["io"]["rows"]
        keys = {(r["backend_type"], r["object"], r["context"])
                for r in rows}
        self.assertEqual(len(keys), 2)
        self.assertEqual(out["io"]["key"], "backend_type+object+context")
        self.assertIn("query_ms", out["io"])

    def test_fetch_pg_error_becomes_marker_not_zero(self):
        class Conn:
            def execute(self, sql):
                raise RuntimeError("boom")
            def rollback(self):
                pass
        out = obs.fetch_pg(Conn())
        self.assertIn("error", out["wal"])
        self.assertNotIn("row", out["wal"])

    def test_dec_default_decimal(self):
        import decimal
        self.assertEqual(obs.dec_default(decimal.Decimal("42")), 42)
        self.assertEqual(obs.dec_default(decimal.Decimal("1.5")), 1.5)
        self.assertEqual(obs.dec_default("x"), "x")

    def test_proc_parsers_use_host_proc(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "diskstats").write_text(
                "   8       0 vdb 1 0 2048 10 2 0 4096 20 0 30 40 0 0\n"
                " 259       0 md0 4 0 8192 40 8 0 16384 80 0 100 200 0 0\n")
            (tmp / "stat").write_text(
                "cpu  10 0 20 60 5 0 5 0 0 0\n")
            (tmp / "meminfo").write_text(
                "MemTotal:       1000 kB\nDirty:            12 kB\n"
                "Writeback:         3 kB\nMemAvailable:    900 kB\n"
                "Buffers:           4 kB\nCached:           50 kB\n")
            (tmp / "loadavg").write_text("0.50 0.40 0.30 1/100 42\n")
            old_proc, old_devs = obs.HOST_PROC, obs.DISK_DEVS
            obs.HOST_PROC = str(tmp)
            obs.DISK_DEVS = ["md0", "vdb"]
            try:
                d = obs.read_diskstats()
                self.assertEqual(d["vdb"]["sectors_written"], 4096)
                self.assertEqual(d["md0"]["writes"], 8)
                c = obs.read_cpu()
                self.assertEqual(c["iowait"], 5)
                self.assertEqual(c["steal"], 0)
                m = obs.read_mem()
                self.assertEqual(m["dirty_kb"], 12)
                l = obs.read_load()
                self.assertEqual(l["load1"], 0.5)
            finally:
                obs.HOST_PROC, obs.DISK_DEVS = old_proc, old_devs
        finally:
            shutil.rmtree(tmp)


class HistoricalFixtureTest(unittest.TestCase):
    """Denominator audit on recorded historical counters. These verify the
    arithmetic behind the documented defect — they are NOT a rerun."""

    def test_2000_run_denominators(self):
        ops, completed, dropped = 3541338, 3594332, 5669
        self.assertAlmostEqual(ops / 1785, 1983.942857, places=4)
        self.assertAlmostEqual(ops / 1800, 1967.410, places=3)
        self.assertAlmostEqual(dropped / (completed + dropped), 0.001575,
                               places=6)

    def test_1900_run_denominators(self):
        ops, completed, dropped = 3372095, 3416887, 3119
        self.assertAlmostEqual(ops / 1785, 1889.128851, places=4)
        self.assertAlmostEqual(dropped / (completed + dropped), 0.000912,
                               places=6)


class K6CheckApiTest(unittest.TestCase):
    """k6 `check(val, sets)` takes predicate functions in `sets` — a
    literal `{name: true}` is not a predicate and silently cannot gate.
    Verify the real test file uses the official API and that the
    synthetic verdict actually fails the process."""

    def test_checkpoint_clock_test_uses_predicate_checks(self):
        src = (ROOT / "perf" / "k6" / "checkpoint_clock_test.js").read_text()
        for m in re.finditer(r"check\((.+?),\s*\{([^}]*)\}\)", src, re.S):
            for part in m.group(2).split(","):
                name, sep, val = part.partition(":")
                if not sep:
                    continue
                self.assertIn("=>", val,
                              f"check set {name.strip()} is not a "
                              f"predicate: {val.strip()}")
        # the composite synthetic verdict must exit non-zero, not only
        # appear in the summary
        self.assertIn("throw new Error", src)
        self.assertIn("checks: ['rate==1.0']", src)

    def test_oauth_handleSummary_attaches_contract_only_when_real(self):
        src = (ROOT / "perf" / "k6" / "oauth.js").read_text()
        m = re.search(
            r"export function handleSummary\(data\)\s*\{(.*?)\n\}", src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        # contract attachment is gated on a real cap-window gauge, not
        # emitted unconditionally for every scenario
        self.assertIn("cap_window_measure_start_ms", body)
        self.assertRegex(
            body, r"if \(.*cap_window_measure_start_ms.*\) \{\s*\n"
                  r"\s*data\.measurement_contract")


@unittest.skipUnless(shutil.which("k6"), "k6 binary not on PATH")
class JsWindowMathTest(unittest.TestCase):
    """Drive measurement_clock.js through real k6 to verify edge cases.
    Assertions run through `check` AND a `checks==rate 1.0` threshold —
    a failed predicate makes the k6 exit code non-zero; exit 0 alone is
    never treated as proof."""

    SCRIPT = r'''
import { check, fail } from 'k6';
import {
  bucketCount, bucketIndexAt, cohortAt, measurementWindow,
  parseDurationMs, COHORT_PRE, COHORT_MEASURE, COHORT_POST,
} from './measurement_clock.js';

export const options = {
  scenarios: { t: { executor: 'shared-iterations',
    vus: 1, iterations: 1, exec: 't' } },
  thresholds: { checks: ['rate==1.0'] },
};

export function t() {
  const S = 1_000_000;
  const w = measurementWindow(S, 120000, 15000);
  if (!(w.startMs === S + 15000 && w.endMs === S + 120000)) {
    throw new Error('window bounds wrong');
  }
  // check() sets are predicate functions — never `{name: true}` shells.
  check(w, { win: (x) => x.startMs === S + 15000 && x.endMs === S + 120000 });
  check(cohortAt(S + 14999, w), { pre: (c) => c === COHORT_PRE });
  check(cohortAt(S + 15000, w), { edgeStart: (c) => c === COHORT_MEASURE });
  check(cohortAt(S + 119999, w), { edgeEndMinus1: (c) => c === COHORT_MEASURE });
  check(cohortAt(S + 120000, w), { edgeEnd: (c) => c === COHORT_POST });
  // late VU: scenario clock entry at t=60s is measure regardless of VU age
  check(cohortAt(S + 60000, w), { lateVU: (c) => c === COHORT_MEASURE });
  check(parseDurationMs('1200s'), { durS: (v) => v === 1200000 });
  check(parseDurationMs('20m'), { durM: (v) => v === 1200000 });
  check(parseDurationMs('1h30m'), { durHM: (v) => v === 5400000 });
  check(parseDurationMs('bogus'), { durBad: (v) => Number.isNaN(v) });
  check(parseDurationMs('30x'), { durPartial: (v) => Number.isNaN(v) });
  const n = bucketCount(1200000, 15000, 60000);
  check(n, { buckets: (v) => v === 21 });
  const n30 = bucketCount(1800000, 15000, 60000);
  check(n30, { buckets30: (v) => v === 31 });
  check(bucketIndexAt(S + 14999, w.startMs, 60000, n), { bi: (v) => v === -1 });
  check(bucketIndexAt(S + 15000, w.startMs, 60000, n), { bi0: (v) => v === 0 });
  check(bucketIndexAt(S + 2000000, w.startMs, 60000, n),
        { overflow: (v) => v === n - 1 });
  if (false) fail('unreachable');
}
'''

    def test_js_window_math(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            shutil.copy(CLOCK_JS, tmp / "measurement_clock.js")
            (tmp / "t.js").write_text(self.SCRIPT)
            p = subprocess.run(
                ["k6", "run", "--quiet", str(tmp / "t.js")],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0,
                             f"k6 asserts failed: {p.stdout}\n{p.stderr}")
            self.assertNotIn("checks_failed", p.stderr)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
