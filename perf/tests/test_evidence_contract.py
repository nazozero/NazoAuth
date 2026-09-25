#!/usr/bin/env python3
"""Evidence-contract repair: forensic diag artifact is NOT authoritative.

Proves the three-tier evidence split:
  A. AUTHORITATIVE — series.json / window.json / k6 summary.
  B. SYSTEM HEALTH — residency/soak/proc/audit/sidecar evidence.
  C. FORENSIC    — diag.jsonl.gz; a bounded sampled debug log whose
                   completeness NEVER feeds a formal gate.

And that consumer-lag on the FIFO-drained point stream is evidence-
pipeline invalidity, not a generator-resource fault.

Run: python3 -m unittest perf.tests.test_evidence_contract -v
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "perf" / "tools"
os.environ.setdefault("SIS_WORKSPACE", str(ROOT))
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "perf"))

import capacity_search as cs  # noqa: E402
import checkpoint_analyze as ca  # noqa: E402
import single_instance_scaling as sis  # noqa: E402

sis.WORKSPACE = str(ROOT)
sis.COMPOSE_FILE = str(ROOT / "docker-compose.perf.yml")
sis.TOOLS = str(ROOT / "perf" / "tools")

try:  # tests run as top-level modules under `discover -s tests`
    from test_stream_cohort import (_point, _window_points, _ts, _feed,
                                    _write_point)  # noqa: E402
except ImportError:  # pragma: no cover - package-style invocation
    from tests.test_stream_cohort import (_point, _window_points, _ts,
                                          _feed, _write_point)


def _mixed_stream(n_begin=200, drops_in=2, drops_pre=1, drops_post=1,
                  extra_metrics=6):
    """A representative point stream: window contract, warmup+measure
    begins/ends with outcomes, drops on both sides of the bounds, and a
    few high-volume metric families."""
    pts = _window_points(ss_ms=1_000_000, off_ms=15_000, dur_ms=1_800_000)
    # warmup cohort begin/end (cohort != measure -> not gated)
    for i in range(20):
        t = _ts(1000.0 + i * 0.05)
        pts.append(_point("cap_iter_begin", t, 1,
                          {"cohort": "warmup", "lw": "1"}))
        pts.append(_point("cap_iter_end", t, 1,
                          {"cohort": "warmup", "lw": "1",
                           "outcome": "success"}))
    pts.append(_point("dropped_iterations", _ts(1010.0), drops_pre))
    # measure cohort (window is [1015, 2800) in seconds: 1015..2800)
    t0 = 1015.0
    for i in range(n_begin):
        t = _ts(t0 + i * 0.1)
        pts.append(_point("cap_iter_begin", t, 1,
                          {"cohort": "measure", "lw": "1"}))
        pts.append(_point("cap_iter_end", t, 1,
                          {"cohort": "measure", "lw": "1",
                           "outcome": "success"}))
        for m in range(extra_metrics):
            pts.append(_point(f"vol_metric_{m}", t, 3.5))
    pts.append(_point("dropped_iterations", _ts(1016.0), drops_in))
    pts.append(_point("dropped_iterations", _ts(2805.0), drops_post))
    return pts


def _run_series():
    s = ca.StreamingSeries()
    s.diag_fh = io.StringIO()
    return s


class DiagOverflowInvariance(unittest.TestCase):
    """§10: the SAME point stream consumed with an overflowing forensic
    artifact must produce IDENTICAL authoritative outputs. Only the diag
    fields may differ."""

    def test_series_window_cohort_identical(self):
        pts = _mixed_stream()
        a = _run_series()
        _feed(a, pts)
        a.emit_window()
        bins_a = a.finalize_bins()
        win_a = a.window_json

        # Force overflow almost immediately by shrinking the logical-byte
        # budget to nearly zero.
        old_cap = ca.MAX_DIAG_BYTES
        try:
            ca.MAX_DIAG_BYTES = 200
            b = _run_series()
            _feed(b, pts)
            b.emit_window()
            bins_b = b.finalize_bins()
            win_b = b.window_json
        finally:
            ca.MAX_DIAG_BYTES = old_cap

        self.assertFalse(a.diag_overflow)
        self.assertTrue(b.diag_overflow)
        # Overflow-side rejects are counted separately from per-second
        # keep-budget rejects.
        self.assertGreater(b.diag_overflow_dropped, 0)
        # AUTHORITATIVE outputs — byte-for-byte identical.
        self.assertEqual(bins_a, bins_b)
        self.assertEqual(win_a, win_b)
        self.assertEqual(a.measure_begins, b.measure_begins)
        self.assertEqual(a.measure_ends, b.measure_ends)
        self.assertEqual(dict(a.measure_outcomes),
                         dict(b.measure_outcomes))
        self.assertEqual(a.drop_in_window, b.drop_in_window)
        self.assertEqual(a.drop_pre_window, b.drop_pre_window)
        self.assertEqual(a.drop_post_window, b.drop_post_window)
        # cohort identity
        self.assertEqual(
            win_a["measurement_cohort"], win_b["measurement_cohort"])


class ForensicDiagContract(unittest.TestCase):
    """§5/§8: stream_evidence projects diag status but never gates on it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _eval(self, **kw):
        return cs.evaluate(kw.pop("summary"), kw.pop("sp"), 3000, 1800,
                           "cap_mixed", require_stream=True, **kw)

    def test_truncated_diag_still_passes_formal(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005},
            stats={"points": 165104262, "parse_errors": 0,
                   "reader_error": None, "lag_over_5s": 0,
                   "diag_overflow": True,
                   "diag_budget_exceeded": 8587268,
                   "max_diag_bytes": 536870912})
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "PASS", json.dumps(m)[:500])
        fd = m["forensic_diag"]
        self.assertEqual(fd["status"], "TRUNCATED")
        self.assertTrue(fd["truncated"])
        self.assertEqual(fd["budget_exceeded_points"], 8587268)
        self.assertEqual(fd["logical_bytes_cap"], 536870912)

    def test_missing_diag_is_absent_not_invalid(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005})
        (self.tmp / "cap-cap-mixed.diag.jsonl.gz").unlink()
        verdict, m = self._eval(sp=sp, summary=summary)
        self.assertEqual(verdict, "PASS", json.dumps(m)[:500])
        self.assertEqual(m["forensic_diag"]["status"], "ABSENT")
        sev = cs.stream_evidence(sp)
        self.assertTrue(sev["valid"], sev["problems"])

    def test_complete_diag_status(self):
        sp, _ = _write_point(
            self.tmp, started=10, completed=10, dropped=0,
            outcomes={"success": 10})
        sev = cs.stream_evidence(sp)
        self.assertEqual(sev["forensic_diag"]["status"], "COMPLETE")


class EvidencePipelineLag(unittest.TestCase):
    """§6: lag_over_5s > 0 is evidence-pipeline invalidity — the analyzer
    drains a FIFO whose writer is k6; a lagging consumer mechanically
    backpressures the output write path. It is NOT a generator-resource
    fault and NOT a forensic caveat."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_lag_invalidates_stream_evidence(self):
        sp, summary = _write_point(
            self.tmp, started=5_355_005, completed=5_355_005, dropped=0,
            outcomes={"success": 5_355_005},
            stats={"points": 100, "parse_errors": 0,
                   "reader_error": None, "lag_over_5s": 12,
                   "diag_overflow": False})
        sev = cs.stream_evidence(sp)
        self.assertFalse(sev["valid"])
        self.assertTrue(sev["evidence_pipeline_invalid"])
        self.assertTrue(any(p.startswith("evidence_pipeline_lag_over_5s")
                            for p in sev["problems"]))
        verdict, m = cs.evaluate(summary, sp, 3000, 1800, "cap_mixed",
                                 require_stream=True)
        self.assertEqual(verdict, "INVALID")
        self.assertEqual(m["reason"], "evidence_pipeline_invalid")

    def test_lag_measured_live(self):
        # A point stamped 10s in the past arrives lagged at consumption.
        s = ca.StreamingSeries()
        _feed(s, [_point("vus", _ts(1000.0), 1)])
        self.assertGreaterEqual(s.lag_over_5s, 1)
        self.assertGreater(s.lag_max_s, 5.0)
        # A fresh (recent) point is not lagged.
        s2 = ca.StreamingSeries()
        import time as _t
        _feed(s2, [_point("vus",
                          _ts(_t.time()), 1)])
        self.assertEqual(s2.lag_over_5s, 0)

    def test_classify_maps_pipeline_class(self):
        import pool_size_ab as psa
        v, fc = psa.classify_stability(
            "EVIDENCE_PIPELINE_INVALID", stab={}, failed=[])
        self.assertEqual((v, fc), ("INVALID", "EVIDENCE_PIPELINE_INVALID"))


class GeneratorResourceScope(unittest.TestCase):
    """§7: generator_resource_evidence only counts real generator
    resource/process faults — analyzer artifacts are excluded."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "cap-cap-mixed.summary.json").write_text("{}")

    def test_analyzer_stats_not_generator_evidence(self):
        (self.tmp / "x.analyzer-stats.json").write_text(json.dumps(
            {"lag_over_5s": 9, "diag_overflow": True}))
        ev = cs.generator_resource_evidence(
            self.tmp / "cap-cap-mixed.summary.json", {}, {})
        self.assertEqual(ev, [])

    def test_real_generator_signatures_still_count(self):
        (self.tmp / "run.log").write_text("too many open files\n")
        ev = cs.generator_resource_evidence(
            self.tmp / "cap-cap-mixed.summary.json", {},
            {"oom_killed": False})
        self.assertEqual(len(ev), 1)
        self.assertIn("too many open files", ev[0])
        ev2 = cs.generator_resource_evidence(
            self.tmp / "cap-cap-mixed.summary.json", {},
            {"oom_killed": True})
        self.assertIn("generator container OOMKilled", ev2)


class FailClosedStillHolds(unittest.TestCase):
    """§11: removing the forensic gate must not relax true integrity
    checks — every one of these stays INVALID."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, **kw):
        kw.setdefault("started", 5_355_005)
        kw.setdefault("completed", 5_355_005)
        kw.setdefault("dropped", 0)
        kw.setdefault("outcomes", {"success": kw["started"]})
        return _write_point(self.tmp, **kw)

    def _eval(self, sp, summary):
        return cs.evaluate(summary, sp, 3000, 1800, "cap_mixed",
                           require_stream=True)

    def test_parse_errors_invalid(self):
        sp, summary = self._write(stats={
            "points": 10, "parse_errors": 1, "reader_error": None})
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertIn("parse_errors", json.dumps(m))

    def test_reader_error_invalid(self):
        sp, summary = self._write(stats={
            "points": 10, "parse_errors": 0,
            "reader_error": "ValueError: boom"})
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertIn("reader_error", json.dumps(m))

    def test_window_invalid_divergent(self):
        win = {"valid": False, "problems": ["divergent_fields"],
               "measurement_cohort": {"valid": True, "problems": [],
                                      "window_start_s": 1015.0,
                                      "window_end_s": 2800.0,
                                      "measure_started_exact": 5_355_005,
                                      "measure_completed_exact": 5_355_005,
                                      "measure_dropped_exact": 0,
                                      "measure_scheduled_observed":
                                          5_355_005,
                                      "measure_drop_fraction": 0.0,
                                      "measure_outcomes":
                                          {"success": 5_355_005},
                                      "measure_outcome_sum": 5_355_005,
                                      "drops_pre_window": 0,
                                      "drops_post_window": 0,
                                      "drops_pending_unclassified": 0,
                                      "pending_drops_overflow": False}}
        sp, summary = self._write(window=win)
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertIn("window_invalid", json.dumps(m))

    def test_cohort_pending_overflow_invalid(self):
        sp, summary = self._write()
        win = json.loads(
            (self.tmp / "cap-cap-mixed.window.json").read_text())
        win["measurement_cohort"]["pending_drops_overflow"] = True
        win["measurement_cohort"]["valid"] = False
        win["measurement_cohort"]["problems"] = ["pending_drops_overflow"]
        (self.tmp / "cap-cap-mixed.window.json").write_text(
            json.dumps(win))
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertIn("pending_drops_overflow", json.dumps(m))

    def test_started_completed_mismatch_invalid(self):
        sp, summary = self._write(started=5_355_006,
                                  completed=5_355_005)
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")

    def test_missing_series_invalid(self):
        sp, summary = self._write()
        (self.tmp / "cap-cap-mixed.series.json").unlink()
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertEqual(m["reason"], "stream_evidence_missing")

    def test_missing_stats_invalid(self):
        sp, summary = self._write()
        (self.tmp / "cap-cap-mixed.analyzer-stats.json").unlink()
        v, m = self._eval(sp, summary)
        self.assertEqual(v, "INVALID")
        self.assertEqual(m["reason"], "stream_evidence_missing")


class StabilityWithoutDiag(unittest.TestCase):
    """§12: stability_analyze never reads diag.jsonl.gz — its result must
    be identical whether the forensic file exists or not."""

    def test_analyze_ignores_diag(self):
        import stability_analyze as sa
        # Static proof: the analyzer never references the forensic file.
        src = Path(sa.__file__).read_text()
        self.assertNotIn("diag.jsonl", src)
        self.assertNotIn("diag_out", src)
        self.assertNotIn("diag_fh", src)
        # Behavioural proof on the committed R2 evidence dir: result is
        # identical with and without a diag artifact present.
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "load").mkdir()
        res1 = sa.analyze(tmp, 1000.0, 60.0)
        (tmp / "cap-cap-mixed.diag.jsonl.gz").write_bytes(b"")
        res2 = sa.analyze(tmp, 1000.0, 60.0)
        self.assertEqual(res1, res2)


class ReevalSmoke(unittest.TestCase):
    """--reeval replays _post_run_verdict over a saved evidence dir."""

    def test_empty_dir_yields_invalid_not_crash(self):
        import pool_size_ab as psa
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        pt = tmp / "phase" / "PT1"
        pt.mkdir(parents=True)
        rec = {"ok": True,
               "point": {"name": "PT1", "phase": "phase",
                          "duration": "60s", "max_vus": 8,
                          "app_env_overrides": {}},
               "run_id": "PT1",
               "load": {"started_ts": 1000.0, "ended_ts": 1060.0,
                        "sidecars": [], "load_status": "completed",
                        "main_exit_code": 0, "main_oom_killed": False},
               "metrics": {}}
        (pt / "point.json").write_text(json.dumps(rec))
        (pt / "load").mkdir()
        rc = psa._reeval(pt)
        self.assertEqual(rc, 0)
        # verdict lands under rebound RESULTS root (parent of phase dir)
        out = json.loads(
            (tmp / "PT1.reeval-verdict.json").read_text())
        self.assertIn(out["verdict"], ("FAIL", "INVALID"))
        self.assertEqual(out["reeval"]["new_real_load_time_s"], 0)


if __name__ == "__main__":
    unittest.main()
