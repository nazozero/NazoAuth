#!/usr/bin/env python3
"""Harness-repair gates: stream-authoritative measurement cohort, stream
evidence requirements, workspace binding, ready-marker, sidecar timing,
report-time provenance, and schedule-anomaly diagnostics.

Run: python3 -m unittest perf.tests.test_stream_cohort -v
"""
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "perf" / "tools"
# Harness modules default WORKSPACE to /workspace on the remote host; in
# this worktree we must resolve the ACTIVE checkout (mirrors the §11
# driver-side pinning).
os.environ.setdefault("SIS_WORKSPACE", str(ROOT))
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "perf"))

import capacity_search as cs  # noqa: E402
import checkpoint_analyze as ca  # noqa: E402
import perf_state_ready as psr  # noqa: E402
import single_instance_scaling as sis  # noqa: E402

# Another test module may have imported single_instance_scaling before
# the env pin above — re-derive its workspace-bound globals so the
# provenance checks resolve THIS checkout.
sis.WORKSPACE = str(ROOT)
sis.COMPOSE_FILE = str(ROOT / "docker-compose.perf.yml")
sis.TOOLS = str(ROOT / "perf" / "tools")


def _point(metric, ts, value, tags=None):
    return {"type": "Point", "data": {"metric": metric, "time": ts,
                                      "value": value, "tags": tags or {}},
            "metric": metric}


def _feed(series, points):
    for p in points:
        series.on_point(p, json.dumps(p))


def _window_points(ss_ms=1_000_000, off_ms=15000, dur_ms=1_800_000):
    base = "1970-01-01T00:00:00.000Z"
    return [
        _point("cap_window_scenario_start_ms", base, ss_ms),
        _point("cap_window_measure_start_ms", base, ss_ms + off_ms),
        _point("cap_window_measure_end_ms", base, ss_ms + dur_ms),
        _point("cap_window_duration_ms", base, dur_ms),
        _point("cap_window_measure_offset_ms", base, off_ms),
        _point("cap_window_bucket_ms", base, 60000),
        _point("cap_window_bucket_count", base, 31),
        _point("cap_window_clock_ok", base, 1),
    ]


def _ts(epoch_s):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat()


class StreamCohortDrops(unittest.TestCase):
    """Drop classification against the emitted window contract (A-E)."""

    def _series_with_drops(self, drop_ts_s):
        s = ca.StreamingSeries()
        _feed(s, _window_points(ss_ms=1_000_000, off_ms=0, dur_ms=100_000))
        for i, ts in enumerate(drop_ts_s):
            _feed(s, [_point("dropped_iterations", _ts(ts), 1)])
        s.emit_window()
        return s.window_json["measurement_cohort"]

    def test_drop_before_window_not_counted(self):
        mc = self._series_with_drops([999.0])
        self.assertEqual(mc["measure_dropped_exact"], 0)
        self.assertEqual(mc["drops_pre_window"], 1)

    def test_drop_at_window_start_counts(self):
        mc = self._series_with_drops([1000.0])
        self.assertEqual(mc["measure_dropped_exact"], 1)

    def test_drop_inside_window_counts(self):
        mc = self._series_with_drops([1050.0])
        self.assertEqual(mc["measure_dropped_exact"], 1)

    def test_drop_at_window_end_not_counted(self):
        mc = self._series_with_drops([1100.0])
        self.assertEqual(mc["measure_dropped_exact"], 0)
        self.assertEqual(mc["drops_post_window"], 1)

    def test_three_drops_in_window(self):
        mc = self._series_with_drops([1010.0, 1020.0, 1090.5])
        self.assertEqual(mc["measure_dropped_exact"], 3)
        self.assertTrue(mc["valid"])

    def test_pre_contract_drop_buffered_then_classified(self):
        s = ca.StreamingSeries()
        _feed(s, [_point("dropped_iterations", _ts(999.0), 1)])
        _feed(s, _window_points(ss_ms=1_000_000, off_ms=0,
                                dur_ms=100_000))
        _feed(s, [_point("dropped_iterations", _ts(1050.0), 1)])
        s.emit_window()
        mc = s.window_json["measurement_cohort"]
        self.assertEqual(mc["drops_pre_window"], 1)
        self.assertEqual(mc["measure_dropped_exact"], 1)
        self.assertEqual(mc["drops_pending_unclassified"], 0)

    def test_unresolved_window_marks_unclassified(self):
        s = ca.StreamingSeries()
        _feed(s, [_point("dropped_iterations", _ts(50.0), 1)])
        s.emit_window()
        mc = s.window_json["measurement_cohort"]
        self.assertEqual(mc["drops_pending_unclassified"], 1)
        self.assertFalse(mc["valid"])
        self.assertIn("window_bounds_unresolved", mc["problems"])

    def test_pending_overflow_invalid(self):
        s = ca.StreamingSeries()
        s._pending_drops = [(1.0, 1)] * ca.MAX_PENDING_DROPS
        s._classify_drop(2.0, 1)
        self.assertTrue(s.pending_drops_overflow)


class StreamCohortCounts(unittest.TestCase):
    """Begin/end/outcome exact counting (F, I, J)."""

    def test_scheduled_observed_and_fraction(self):
        s = ca.StreamingSeries()
        _feed(s, _window_points(ss_ms=1_000_000, off_ms=0,
                                dur_ms=100_000))
        pts = []
        for i in range(1000):
            t = _ts(1000.0 + i * 0.001)
            pts.append(_point("cap_iter_begin", t, 1,
                              {"cohort": "measure", "lw": "1"}))
            pts.append(_point("cap_iter_end", t, 1,
                              {"cohort": "measure", "lw": "1",
                               "outcome": "success"}))
        for t in (1010.0, 1020.0, 1030.0):
            pts.append(_point("dropped_iterations", _ts(t), 1))
        _feed(s, pts)
        s.emit_window()
        mc = s.window_json["measurement_cohort"]
        self.assertEqual(mc["measure_started_exact"], 1000)
        self.assertEqual(mc["measure_completed_exact"], 1000)
        self.assertEqual(mc["measure_dropped_exact"], 3)
        self.assertEqual(mc["measure_scheduled_observed"], 1003)
        self.assertAlmostEqual(mc["measure_drop_fraction"], 3 / 1003, 6)
        self.assertTrue(mc["valid"])

    def test_unfinished(self):
        s = ca.StreamingSeries()
        _feed(s, _window_points(ss_ms=1_000_000, off_ms=0,
                                dur_ms=100_000))
        _feed(s, [_point("cap_iter_begin", _ts(1001.0), 1,
                         {"cohort": "measure", "lw": "1"})])
        s.emit_window()
        mc = s.window_json["measurement_cohort"]
        self.assertFalse(mc["valid"])
        self.assertTrue(any(p.startswith("unfinished_measure")
                            for p in mc["problems"]))

    def test_outcome_sum_mismatch(self):
        s = ca.StreamingSeries()
        _feed(s, _window_points(ss_ms=1_000_000, off_ms=0,
                                dur_ms=100_000))
        # manual inconsistency: ends without outcome-tag accounting
        s.measure_begins = 2
        s.measure_ends = 2
        s.measure_outcomes["success"] = 1
        s._window_bounds_s = (1000.0, 1100.0)
        s.emit_window()
        mc = s.window_json["measurement_cohort"]
        self.assertFalse(mc["valid"])
        self.assertTrue(any(p.startswith("outcome_sum_mismatch")
                            for p in mc["problems"]))


# ---------------------------------------------------------------------
# evaluate() on synthetic stream evidence
# ---------------------------------------------------------------------

def _write_point(tmp: Path, *, started, completed, dropped, outcomes,
                 include_stream=True, stats=None, window=None,
                 contract=None):
    ss_ms, ws_ms, we_ms = 1_000_000, 1_015_000, 2_800_000
    contract = contract or {
        "contract": "cap-scenario-window-v1",
        "scenario_start_ms": ss_ms,
        "window_start_ms": ws_ms,
        "window_end_ms": we_ms,
        "window_seconds": 1785.0,
        "duration_ms": 1_800_000,
        "scenario_clock_ok": 1,
        "divergent_vus": False,
        "problems": [],
    }
    def counter(n):
        return {"values": {"count": n}}
    metrics = {
        "cap_measure_ops": counter(outcomes.get("_ops", completed)),
        "cap_measure_success": counter(outcomes.get("success", 0)),
        "cap_measure_expected_rejection":
            counter(outcomes.get("expected_rejection", 0)),
        "cap_measure_local_no_request":
            counter(outcomes.get("local_no_request", 0)),
        "cap_measure_unexpected":
            counter(outcomes.get("unexpected", 0)),
        "cap_iter_begin_measure": counter(started),
        "cap_iter_begin": counter(started),
        "cap_iter_end": counter(completed),
        "cap_iter_begin_late_vu": counter(0),
        "cap_iter_ms": {"values": {"med": 5.0, "p(95)": 25.0,
                                   "p(99)": 43.0}},
        "iterations": counter(started),
        "dropped_iterations": counter(dropped),
        "http_reqs": counter(completed * 2),
        "vus_max": {"values": {"max": 40}},
        "vus": {"values": {"max": 40}},
    }
    for outcome in ("prepare_failed", "prepare_local_failed", "prepare_sut_failed"):
        metrics[f"cap_measure_{outcome}"] = counter(outcomes.get(outcome, 0))
    (tmp / "cap-cap-mixed.k6.json").write_text(json.dumps({
        "metrics": metrics,
        "measurement_contract": contract,
    }))
    summary = {
        "status": "passed", "profile": "cap", "scenario": "cap_mixed",
        "load_model": {"time_unit": "1s"},
        "k6": {"rps": 4337.0, "dropped_iterations": dropped,
               "iterations_completed": started,
               "latency_ms": {"p50": 5, "p95": 25, "p99": 43},
               "error_rate": 0},
    }
    sp = tmp / "cap-cap-mixed.summary.json"
    sp.write_text(json.dumps(summary))
    if include_stream:
        win = window or {
            "contract": "cap-scenario-window-v1",
            "valid": True, "problems": [],
            "measurement_cohort": {
                "window_start_s": ws_ms / 1000.0,
                "window_end_s": we_ms / 1000.0,
                "measure_started_exact": started,
                "measure_completed_exact": completed,
                "measure_dropped_exact": dropped,
                "measure_scheduled_observed": started + dropped,
                "measure_drop_fraction": (
                    dropped / (started + dropped)
                    if started + dropped else None),
                "measure_outcomes": dict(outcomes),
                "measure_outcome_sum": sum(outcomes.values()),
                "drops_pre_window": 0, "drops_post_window": 0,
                "drops_pending_unclassified": 0,
                "pending_drops_overflow": False,
                "valid": True, "problems": [],
            },
        }
        (tmp / "cap-cap-mixed.window.json").write_text(json.dumps(win))
        st = stats or {"points": 100, "parse_errors": 0,
                       "reader_error": None, "diag_overflow": False}
        (tmp / "cap-cap-mixed.analyzer-stats.json").write_text(
            json.dumps(st))
        (tmp / "cap-cap-mixed.series.json").write_text("{}")
        with gzip.open(tmp / "cap-cap-mixed.diag.jsonl.gz", "wt") as fh:
            fh.write("{}\n")
    return sp, summary


class EvaluateStreamPath(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _eval(self, **kw):
        return cs.evaluate(kw.pop("summary"), kw.pop("sp"), 3000, 1800,
                           "cap_mixed", require_stream=True, **kw)

    def test_G_rational_plus5_still_valid(self):
        # rational planned=5,355,000; observed starts=+5, drop=0
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "PASS", json.dumps(m)[:600])
        meas = m["measure"]
        self.assertEqual(meas["rational_planned_arrivals"], 5_355_000)
        self.assertEqual(meas["schedule_delta_vs_rational"], 5)
        self.assertEqual(meas["measure_drop_fraction"], 0)
        self.assertEqual(meas["cohort_source"], "k6_stream_exact")

    def test_mixed_requires_successful_not_completed_rate(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_000, completed=5_355_000, dropped=0,
            outcomes={"success": 5_314_982, "expected_rejection": 885,
                      "local_no_request": 39_133})
        verdict, metrics = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "FAIL")
        self.assertEqual(metrics["measured_ops_s"], 3000)
        self.assertLess(metrics["rate_for_gate"], 2985)
        self.assertEqual(metrics["capacity_gate_contract"], "successful-ops-v1")

    def test_low_rate_prepare_failure_never_passes(self):
        for outcome, expected in (("prepare_failed", "INVALID"),
                                  ("prepare_local_failed", "INVALID"),
                                  ("prepare_sut_failed", "FAIL")):
            with self.subTest(outcome=outcome):
                sp, summary = _write_point(
                    self.tmp, started=5_355_000, completed=5_355_000,
                    dropped=0, outcomes={"success": 5_349_645,
                                         outcome: 5355})
                verdict, metrics = self._eval(sp=sp, summary=summary)
                self.assertEqual(verdict, expected, metrics)
                self.assertEqual(metrics["successful_ops_s"], 2997)

    def test_H_schedule_anomaly(self):
        sp, summary = _write_point(
            self.tmp, started=5_400_000, completed=5_400_000, dropped=0,
            outcomes={"success": 5_400_000})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "INVALID")
        self.assertEqual(m["reason"], "generator_schedule_anomaly")

    def test_I_unfinished(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_010, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "INVALID")
        self.assertEqual(m["reason"], "unfinished_measurement")

    def test_J_outcome_sum_mismatch(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_004})
        # force cohort invalid: outcome_sum != completed
        win = json.loads(
            (self.tmp / "cap-cap-mixed.window.json").read_text())
        win["measurement_cohort"]["measure_outcome_sum"] = 5_355_004
        win["measurement_cohort"]["valid"] = False
        win["measurement_cohort"]["problems"] = ["outcome_sum_mismatch"]
        (self.tmp / "cap-cap-mixed.window.json").write_text(
            json.dumps(win))
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "INVALID")

    def test_K_parse_error_invalid(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005},
            stats={"points": 10, "parse_errors": 2,
                   "reader_error": None, "diag_overflow": False})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "INVALID")
        self.assertEqual(m["reason"], "stream_evidence_invalid")

    def test_L_missing_stream_required(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005}, include_stream=False)
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "INVALID")
        self.assertEqual(m["reason"], "stream_evidence_missing")

    def test_missing_stream_not_required_falls_back(self):
        # Legacy counter path still available when stream not required:
        # started=scheduled+1 inside the legacy boundary allowance.
        sp, summary = _write_point(
            self.tmp, started=5_355_001, completed=5_355_001, dropped=0,
            outcomes={"success": 5_355_001}, include_stream=False)
        verdict, m = cs.evaluate(summary, sp, 3000, 1800, "cap_mixed")
        self.assertEqual(verdict, "PASS", json.dumps(m)[:400])
        self.assertEqual(m["measure"]["cohort_source"], "counter_legacy")

    def test_drop_exact_in_window(self):
        sp, summary = _write_point(
            self.tmp, started=5_354_997, completed=5_354_997, dropped=3,
            outcomes={"success": 5_354_997})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(m["measure"]["measure_dropped_exact"], 3)
        self.assertEqual(m["measure"]["measure_scheduled_observed"],
                         5_355_000)
        self.assertAlmostEqual(m["measure"]["measure_drop_fraction"],
                               3 / 5_355_000, 6)

    def test_drop_over_gate_fails(self):
        # 0.2% exact drops exceeds the 0.1% gate -> real FAIL, not INVALID
        sp, summary = _write_point(
            self.tmp, started=5_344_290, completed=5_344_290,
            dropped=10_710, outcomes={"success": 5_344_290})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "FAIL")


# ---------------------------------------------------------------------
# ready marker / sidecar timing / report time / workspace
# ---------------------------------------------------------------------

class ReadyMarker(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "vectors.json").write_text(json.dumps([{"a": 1}]))
        (self.tmp / "secrets.json").write_text(json.dumps({"k": "v"}))

    def test_write_and_wait(self):
        psr.write_ready(self.tmp, "R2")
        mk = psr.wait_ready(self.tmp, "R2", timeout_s=2)
        self.assertEqual(mk["run_id"], "R2")
        self.assertEqual(mk["vector_count"], 1)

    def test_stale_run_id_ignored(self):
        psr.write_ready(self.tmp, "OLD")
        with self.assertRaises(psr.StateNotReady):
            psr.wait_ready(self.tmp, "R2", timeout_s=0.8, poll_s=0.1)

    def test_hash_mismatch_fails(self):
        mk = psr.write_ready(self.tmp, "R2")
        (self.tmp / "vectors.json").write_text(json.dumps([{"a": 2}]))
        with self.assertRaises(psr.StateNotReady):
            psr._verify(mk, self.tmp)

    def test_missing_files_fail(self):
        mk = psr.write_ready(self.tmp, "R2")
        (self.tmp / "secrets.json").unlink()
        with self.assertRaises(psr.StateNotReady):
            psr._verify(mk, self.tmp)

    def test_timeout_without_marker(self):
        with self.assertRaises(psr.StateNotReady):
            psr.wait_ready(self.tmp, "R2", timeout_s=0.4, poll_s=0.1)


class SidecarTiming(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _gate(self, ts_map, window_start_ms=2_000_000):
        sys.path.insert(0, str(TOOLS))
        import pool_size_ab as psa
        for name, ts in ts_map.items():
            d = self.tmp / name
            d.mkdir(exist_ok=True)
            if ts is not None:
                (d / "k6-started.json").write_text(json.dumps({"ts": ts}))
        scs = [{"name": n} for n in ts_map]
        return psa._sidecar_timing_gate(self.tmp, scs, window_start_ms)

    def test_all_before_deadline_ok(self):
        # window_start=2000.0s -> deadline 1995.0s; both started earlier
        g = self._gate({"a": 1990.0, "b": 1994.9})
        self.assertTrue(g["ok"])

    def test_late_sidecar_fails(self):
        g = self._gate({"a": 1990.0, "b": 1996.0})
        self.assertFalse(g["ok"])
        self.assertTrue(g["detail"]["a"]["ok"])
        self.assertFalse(g["detail"]["b"]["ok"])

    def test_missing_k6_start_fails(self):
        g = self._gate({"a": 1990.0, "b": None})
        self.assertFalse(g["ok"])
        self.assertFalse(g["detail"]["b"]["ok"])

    def test_no_window_fails(self):
        g = self._gate({"a": 1990.0}, window_start_ms=None)
        self.assertFalse(g["ok"])


class ReportTime(unittest.TestCase):
    def test_ok(self):
        import pool_size_ab as psa
        self.assertTrue(psa._report_time_ok(100.0, 100.0 + 3600))

    def test_generated_before_run_end(self):
        import pool_size_ab as psa
        self.assertFalse(psa._report_time_ok(100.0, 99.0))

    def test_beyond_6h(self):
        import pool_size_ab as psa
        self.assertFalse(psa._report_time_ok(100.0, 100.0 + 6 * 3600 + 1))

    def test_missing_run_end(self):
        import pool_size_ab as psa
        self.assertFalse(psa._report_time_ok(None, 100.0))


class WorkspaceBinding(unittest.TestCase):
    def test_provenance_ok_on_this_checkout(self):
        prov = sis.workspace_provenance()
        self.assertTrue(prov["ok"], prov["missing"])
        self.assertEqual(prov["workspace_realpath"],
                         str(Path(sis.WORKSPACE).resolve()))
        self.assertTrue(prov["file_sha256"]["docker-compose.perf.yml"]
                        ["sha256"])

    def test_mount_sources_ok(self):
        mounts = sis.verify_mount_sources()
        self.assertTrue(all(mounts.values()),
                        [k for k, v in mounts.items() if not v])

    def test_workspace_mismatch_exits(self):
        env = dict(os.environ)
        env["SIS_WORKSPACE"] = tempfile.gettempdir()
        p = subprocess.run(
            [sys.executable, str(TOOLS / "pool_size_ab.py"), "--help"],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertIn("HARNESS_WORKSPACE_MISMATCH",
                      p.stderr + p.stdout)

    def test_workspace_autopin(self):
        env = dict(os.environ)
        env.pop("SIS_WORKSPACE", None)
        p = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0, sys.argv[1]);"
             "import pool_size_ab;import os;"
             "print(os.environ['SIS_WORKSPACE'])",
             str(TOOLS)],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertIn(str(ROOT), p.stdout.strip(),
                      p.stdout + p.stderr)


class MetaSha(unittest.TestCase):
    def test_meta_sha_ok_missing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.assertIsNone(
            sis._meta_sha_ok(tmp / "x.jsonl", __file__))

    def test_meta_sha_ok_mismatch(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        f = tmp / "x.jsonl"
        f.write_text(json.dumps({"kind": "meta",
                                 "script_sha256": "deadbeef"}) + "\n")
        self.assertFalse(sis._meta_sha_ok(f, __file__))

    def test_meta_sha_ok_match(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        import hashlib
        src = tmp / "sampler.py"
        src.write_text("print('x')\n")
        f = tmp / "x.jsonl"
        f.write_text(json.dumps({
            "kind": "meta",
            "script_sha256": hashlib.sha256(
                src.read_bytes()).hexdigest()}) + "\n")
        self.assertTrue(sis._meta_sha_ok(f, str(src)))


if __name__ == "__main__":
    unittest.main()
