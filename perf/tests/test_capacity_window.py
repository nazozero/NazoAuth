#!/usr/bin/env python3
"""Measurement-window accounting: schedule helper + capRun gate
population. All gate assertions call the real capacity_search.evaluate
— no duplicated math."""
import json
import re
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import capacity_search as cs  # noqa: E402
import measure_schedule as ms  # noqa: E402

SS = 1_000_000  # scenario_start_ms
WS, WE = SS + 15_000, SS + 120_000  # 15s -> 120s window
DUR = 120_000


class ScheduleTest(unittest.TestCase):
    def test_3000s_15_to_120(self):
        self.assertEqual(
            ms.scheduled_arrivals_in_window(SS, WS, WE, 3000,
                                            Fraction(1000), DUR),
            315000)

    def test_fractional_window(self):
        # 100/s, 1s unit -> period 10ms. Window [1505ms, 1605ms):
        # arrivals at 1510..1600 -> 10.
        self.assertEqual(
            ms.scheduled_arrivals_in_window(0, 1505, 1605, 100,
                                            Fraction(1000), 5000),
            10)

    def test_timeunit_500ms(self):
        # rate=10 per 500ms -> period 50ms. Window [100ms, 300ms):
        # arrivals at 100,150,200,250 -> 4 (300 excluded).
        self.assertEqual(
            ms.scheduled_arrivals_in_window(0, 100, 300, 10,
                                            Fraction(500), 1000),
            4)

    def test_boundary_start_inclusive_end_exclusive(self):
        # 1/s, window [1000, 2000): arrival at 1000 counts, 2000 doesn't.
        self.assertEqual(
            ms.scheduled_arrivals_in_window(0, 1000, 2000, 1,
                                            Fraction(1000), 5000),
            1)

    def test_inverted_window_invalid(self):
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            0, 2000, 1000, 3000, Fraction(1000), 5000))
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            0, 2000, 2000, 3000, Fraction(1000), 5000))

    def test_zero_rate_invalid(self):
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            SS, WS, WE, 0, Fraction(1000), DUR))

    def test_missing_fields_invalid(self):
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            None, WS, WE, 3000, Fraction(1000), DUR))
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            SS, WS, WE, None, Fraction(1000), DUR))
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            SS, WS, None, 3000, Fraction(1000), DUR))

    def test_window_before_scenario_invalid(self):
        self.assertIsNone(ms.scheduled_arrivals_in_window(
            SS, SS - 5000, WE, 3000, Fraction(1000), DUR))

    def test_time_unit_parse(self):
        self.assertEqual(ms.parse_time_unit_ms("1s"), Fraction(1000))
        self.assertEqual(ms.parse_time_unit_ms("500ms"), Fraction(500))
        self.assertIsNone(ms.parse_time_unit_ms("bogus"))
        self.assertIsNone(ms.parse_time_unit_ms(None))


def _k6_metrics(ops, began_measure, outcomes, iter_p95=50.0,
                iter_p99=150.0, begins_total=None, ends_total=None,
                dropped_whole=0, vus_max=None):
    metrics = {
        "cap_measure_ops": {"count": ops},
        "cap_iter_begin_measure": {"count": began_measure},
        "cap_iter_begin": {"count": begins_total
                           if begins_total is not None
                           else began_measure + 45000},
        "cap_iter_end": {"count": ends_total
                         if ends_total is not None
                         else (begins_total or began_measure + 45000)},
        "cap_iter_ms": {"values": {"med": 10.0, "p(95)": iter_p95,
                                   "p(99)": iter_p99}},
        "cap_measure_ms": {"values": {"med": 10.0, "p(95)": iter_p95,
                                      "p(99)": iter_p99}},
        "iterations": {"count": begins_total
                       if begins_total is not None
                       else began_measure + 45000},
        "dropped_iterations": {"count": dropped_whole},
        "vus_max": {"values": {"max": vus_max or 0}},
    }
    for name, count in outcomes.items():
        metrics[f"cap_measure_{name}"] = {"count": count}
    return metrics


def _contract():
    return {"contract": "cap-scenario-window-v1",
            "scenario_start_ms": SS, "window_start_ms": WS,
            "window_end_ms": WE, "duration_ms": DUR,
            "window_seconds": 105.0, "scenario_clock_ok": 1,
            "divergent_vus": False}


def _summary(dropped_whole=0, iters=360000, p95=50.0, p99=150.0,
             status="passed", error_rate=0.0):
    return {"status": status,
            "k6": {"dropped_iterations": dropped_whole,
                   "iterations_completed": iters,
                   "drop_fraction": dropped_whole / (iters + dropped_whole),
                   "rps": 3000.0, "error_rate": error_rate,
                   "latency_ms": {"p50": 10.0, "p95": p95, "p99": p99}},
            "load_model": {"executor": "constant-arrival-rate",
                           "target_rate": 3000, "time_unit": "1s",
                           "duration": "120s"}}


class GateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    _UNSET = object()

    def _write(self, metrics, contract=_UNSET):
        (self.dir / "cap-x.k6.json").write_text(json.dumps({
            "metrics": metrics,
            "measurement_contract":
            _contract() if contract is self._UNSET else contract}))
        return self.dir / "cap-x.summary.json"

    def _eval(self, summary, metrics, contract=_UNSET, target=3000):
        path = self._write(metrics, contract)
        (path).write_text(json.dumps(summary))
        return cs.evaluate(summary, path, target, 120, "cap_mixed")

    def _passing_metrics(self, ops=314925, **kw):
        outcomes = {"success": ops - 100, "expected_rejection": 50,
                    "local_no_request": 50, "unexpected": 0,
                    "prepare_failed": 0}
        return _k6_metrics(ops, ops, outcomes, **kw)

    def test_measure_clean_whole_run_drops_pass(self):
        # Whole-run shows 1000 warmup drops; measurement cohort is clean.
        m = self._passing_metrics(dropped_whole=1000)
        s = _summary(dropped_whole=1000)
        v, met = self._eval(s, m)
        self.assertEqual(v, "PASS", met)
        self.assertEqual(met["measure"]["drop_fraction"], 0.000238)

    def test_measure_drop_fails_despite_clean_whole_run(self):
        # 400 measure drops (0.127%) with zero whole-run reported drops.
        m = self._passing_metrics(ops=314600, dropped_whole=0)
        s = _summary(dropped_whole=0)
        v, met = self._eval(s, m)
        self.assertEqual(v, "FAIL", met)
        self.assertAlmostEqual(met["measure"]["drop_fraction"],
                               400 / 315000, places=6)

    def test_whole_run_p99_high_measure_ok(self):
        m = self._passing_metrics(iter_p95=60.0, iter_p99=200.0)
        s = _summary(p95=4000.0, p99=4800.0)  # warmup spike, whole-run
        v, met = self._eval(s, m)
        self.assertEqual(v, "PASS", met)
        self.assertEqual(met["gate_p99"], 200.0)

    def test_measure_unexpected_fails(self):
        m = self._passing_metrics()
        m["cap_measure_unexpected"] = {"count": 3}
        m["cap_measure_success"] = {"count": 314925 - 100 - 3}
        # completed now 314925 still (sum shifts), unexpected=3 -> FAIL
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "FAIL", met)
        self.assertEqual(met["unexpected_errors"], 3)

    def test_boundary_overshoot_within_allowance_passes(self):
        # k6's wall-clock ticker can legitimately land ~1ms of the
        # arrival stream inside a half-open window edge. At 3000/s the
        # allowance is 3 arrivals; +1 must not invalidate the point and
        # the gate uses the worst-case drop bound (|Δ|/scheduled).
        m = self._passing_metrics(ops=315001)
        verdict, met = self._eval(_summary(), m)
        self.assertEqual("PASS", verdict)
        meas = met["measure"]
        self.assertEqual(1, meas["boundary_overshoot"])
        self.assertEqual(round(1 / 315000, 6),
                         meas["drop_fraction_upper"])
        # drops are never negative: +1 start yields lower bound 0
        self.assertEqual(0, meas["dropped"])
        self.assertEqual(0, meas["drop_lower_bound"])
        self.assertEqual(1, meas["drop_upper_bound"])
        self.assertEqual(1, meas["schedule_delta"])

    def test_drop_bounds_never_negative(self):
        # scheduled=1000, started=1001 -> delta +1 inside the allowance:
        # dropped must be 0 (never negative), upper bound 1.
        contract = {"contract": "cap-scenario-window-v1",
                    "scenario_start_ms": 0, "window_start_ms": 0,
                    "window_end_ms": 1000, "duration_ms": 1000,
                    "window_seconds": 1.0}
        metrics = {"cap_iter_begin_measure": {"count": 1001},
                   "cap_measure_ops": {"count": 1001},
                   "cap_measure_success": {"count": 1001},
                   "cap_measure_expected_rejection": {"count": 0},
                   "cap_measure_local_no_request": {"count": 0},
                   "cap_measure_unexpected": {"count": 0},
                   "cap_measure_prepare_failed": {"count": 0},
                   "cap_iter_begin": {"count": 1001},
                   "cap_iter_end": {"count": 1001}}
        acct = ms.cohort_accounting(metrics, contract, 1000, 1000)
        self.assertTrue(acct["valid"], acct["problems"])
        self.assertEqual(0, acct["dropped"])
        self.assertEqual(0, acct["drop_lower_bound"])
        self.assertEqual(1, acct["drop_upper_bound"])
        self.assertEqual(1, acct["schedule_delta"])
        self.assertEqual(1, acct["boundary_overshoot"])

    def test_drop_bounds_real_drop(self):
        # scheduled=1000, started=999 -> a real drop of exactly 1.
        contract = {"contract": "cap-scenario-window-v1",
                    "scenario_start_ms": 0, "window_start_ms": 0,
                    "window_end_ms": 1000, "duration_ms": 1000,
                    "window_seconds": 1.0}
        metrics = {"cap_iter_begin_measure": {"count": 999},
                   "cap_measure_ops": {"count": 999},
                   "cap_measure_success": {"count": 999},
                   "cap_measure_expected_rejection": {"count": 0},
                   "cap_measure_local_no_request": {"count": 0},
                   "cap_measure_unexpected": {"count": 0},
                   "cap_measure_prepare_failed": {"count": 0},
                   "cap_iter_begin": {"count": 999},
                   "cap_iter_end": {"count": 999}}
        acct = ms.cohort_accounting(metrics, contract, 1000, 1000)
        self.assertTrue(acct["valid"], acct["problems"])
        self.assertEqual(1, acct["dropped"])
        self.assertEqual(1, acct["drop_lower_bound"])
        self.assertEqual(1, acct["drop_upper_bound"])
        self.assertEqual(-1, acct["schedule_delta"])
        self.assertEqual(0, acct["boundary_overshoot"])

    def test_f3000r2_shape_still_passes(self):
        # Regression lock for the observed F3000R2 evidence:
        # 585s window at 3000/s -> scheduled 1,755,000; observed
        # started=completed=1,755,001 (delta +1) must remain PASS.
        contract = {"contract": "cap-scenario-window-v1",
                    "scenario_start_ms": 0, "window_start_ms": 15000,
                    "window_end_ms": 600000, "duration_ms": 600000,
                    "window_seconds": 585.0}
        n = 1_755_001
        metrics = {"cap_iter_begin_measure": {"count": n},
                   "cap_measure_ops": {"count": n},
                   "cap_measure_success": {"count": n},
                   "cap_measure_expected_rejection": {"count": 0},
                   "cap_measure_local_no_request": {"count": 0},
                   "cap_measure_unexpected": {"count": 0},
                   "cap_measure_prepare_failed": {"count": 0},
                   "cap_iter_begin": {"count": n + 46000},
                   "cap_iter_end": {"count": n + 46000},
                   "cap_iter_ms": {"values": {"med": 5.0, "p(95)": 34.0,
                                              "p(99)": 93.0}}}
        acct = ms.cohort_accounting(metrics, contract, 3000, 1000)
        self.assertTrue(acct["valid"], acct["problems"])
        self.assertEqual(0, acct["dropped"])
        self.assertEqual(1, acct["drop_upper_bound"])

    def test_boundary_overshoot_beyond_allowance_invalid(self):
        # +4 observed starts at 3000/s exceeds the 1ms ticker-jitter
        # allowance (max(2, ceil(3000*0.001)) = 3): counter stream or
        # contract is lying -> INVALID, never clamped.
        m = self._passing_metrics(ops=315004)
        verdict, met = self._eval(_summary(), m)
        self.assertEqual("INVALID", verdict)
        self.assertTrue(any("scheduled_less_than_started" in p
                            for p in met["cohort_problems"]))

    def test_scheduled_less_than_started_invalid(self):
        m = self._passing_metrics()
        m["cap_iter_begin_measure"] = {"count": 316000}  # > 315000
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "INVALID")
        self.assertTrue(any("scheduled_less_than_started" in p
                            for p in met["cohort_problems"]))

    def test_started_ne_completed_invalid(self):
        # began 314925 but only 314800 outcomes recorded -> unfinished.
        m = self._passing_metrics(ops=314800)
        m["cap_iter_begin_measure"] = {"count": 314925}
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "INVALID")
        self.assertTrue(any(p.startswith("unfinished_measure")
                            for p in met["cohort_problems"]))

    def test_missing_contract_invalid(self):
        m = self._passing_metrics()
        s = _summary()
        v, met = self._eval(s, m, contract={})
        self.assertEqual(v, "INVALID")

    def test_non_caprun_uses_whole_run(self):
        # No cap markers at all -> full-scenario accounting.
        metrics = {"iterations": {"count": 6000},
                   "dropped_iterations": {"count": 0},
                   "http_reqs": {"count": 6000}}
        s = _summary(dropped_whole=0, iters=6000, p95=50.0, p99=100.0)
        s["k6"]["rps"] = 3000.0
        path = self._write(metrics)
        path.write_text(json.dumps(s))
        v, met = cs.evaluate(s, path, 3000, 2, "cap_other")
        self.assertIn(v, ("PASS", "FAIL"))  # not INVALID
        self.assertEqual(met.get("rate_basis"), "full_scenario")

    def test_vu_cap_alone_is_diagnostic_not_invalid(self):
        # vus_max at the configured cap is a diagnostic flag, NOT
        # generator-resource evidence: arrival drops at the cap can mean
        # the SUT held VUs longer. With drops but no independent evidence
        # the point is a SUT FAIL, flagged injector_vu_cap_reached.
        m = self._passing_metrics(ops=314000, vus_max=1024)
        s = _summary()
        import os
        old = os.environ.get("CAP_MAX_VUS")
        os.environ["CAP_MAX_VUS"] = "1024"
        try:
            v, met = self._eval(s, m)
        finally:
            if old is None:
                os.environ.pop("CAP_MAX_VUS")
            else:
                os.environ["CAP_MAX_VUS"] = old
        self.assertEqual(v, "FAIL", met)
        self.assertIs(met["injector_vu_cap_reached"], True)
        self.assertEqual(met["load_generator_evidence"], "absent")

    def test_vu_cap_plus_latency_fail_still_fails(self):
        # VU ceiling must not hide a latency-gate breach.
        m = self._passing_metrics(ops=314000, vus_max=1024,
                                  iter_p95=300.0, iter_p99=900.0)
        s = _summary()
        import os
        old = os.environ.get("CAP_MAX_VUS")
        os.environ["CAP_MAX_VUS"] = "1024"
        try:
            v, met = self._eval(s, m)
        finally:
            if old is None:
                os.environ.pop("CAP_MAX_VUS")
            else:
                os.environ["CAP_MAX_VUS"] = old
        self.assertEqual(v, "FAIL", met)
        self.assertIs(met["injector_vu_cap_reached"], True)

    def test_independent_generator_oom_is_resource_invalid(self):
        m = self._passing_metrics(ops=314000)
        s = _summary()
        v, met = self._eval(s, m)
        # same point without facts -> SUT FAIL
        self.assertEqual(v, "FAIL", met)
        # generator OOMKilled is independent evidence -> RESOURCE_INVALID
        path = self._write(m)
        v2, met2 = cs.evaluate(s, path, 3000, 120, "cap_mixed",
                               generator_facts={"oom_killed": True})
        self.assertEqual(v2, "LOAD_GENERATOR_RESOURCE_INVALID", met2)
        # k6 threshold exit code 99 is a RESULT, not generator evidence
        v3, met3 = cs.evaluate(s, path, 3000, 120, "cap_mixed",
                               generator_facts={"load_status": "completed",
                                                "exit_code": "99"})
        self.assertEqual(v3, "FAIL", met3)
        # abnormal exit (not 0/99) on a completed run is evidence
        v4, met4 = cs.evaluate(s, path, 3000, 120, "cap_mixed",
                               generator_facts={"load_status": "completed",
                                                "exit_code": "1"})
        self.assertEqual(v4, "LOAD_GENERATOR_RESOURCE_INVALID", met4)

    def test_run_log_generator_signature_is_resource_invalid(self):
        m = self._passing_metrics(ops=314000)
        s = _summary()
        (self.dir / "run.log").write_text(
            "k6 run ... dial tcp: socket: too many open files\n")
        v, met = self._eval(s, m)
        self.assertEqual(v, "LOAD_GENERATOR_RESOURCE_INVALID", met)

    def test_late_vu_over_0_1pct_is_load_model_invalid(self):
        # 0.4% of measure begins are late-VU bootstraps -> load model.
        m = self._passing_metrics()
        m["cap_iter_begin_late_vu"] = {"count": 1260}  # 0.4% of 314925
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "LOAD_MODEL_INVALID", met)
        self.assertEqual(met["reason"], "late_vu_fraction_over_0.1pct")

    def test_late_vu_under_0_1pct_passes(self):
        m = self._passing_metrics()
        m["cap_iter_begin_late_vu"] = {"count": 100}  # 0.032%
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "PASS", met)
        self.assertAlmostEqual(met["measure"]["late_vu_fraction"],
                               100 / 314925, places=6)

    def test_drop_without_generator_evidence_is_sut_fail(self):
        m = self._passing_metrics(ops=314000)  # 1000 measure drops, no ev
        s = _summary()
        v, met = self._eval(s, m)
        self.assertEqual(v, "FAIL", met)

    def test_threshold_failed_does_not_override_clean_measure(self):
        # Whole-run threshold breach (warmup p99 spike) but clean cohort.
        m = self._passing_metrics()
        s = _summary(status="threshold_failed")
        v, met = self._eval(s, m)
        self.assertEqual(v, "PASS", met)
        self.assertEqual(met["threshold_status_diagnostic"],
                         "threshold_failed")

    def test_offline_b1_b2_shape(self):
        # The real B1 numbers: began=ops=314570, scheduled=315000.
        m = _k6_metrics(314570, 314570,
                        {"success": 310052, "expected_rejection": 54,
                         "local_no_request": 4464, "unexpected": 0,
                         "prepare_failed": 0},
                        iter_p95=57.0, iter_p99=144.0,
                        begins_total=358880, ends_total=358880,
                        dropped_whole=1121)
        s = _summary(dropped_whole=1121, iters=358880)
        v, met = self._eval(s, m)
        self.assertEqual(v, "FAIL")  # 430/315000 = 0.1365% > 0.1%
        self.assertEqual(met["measure"]["scheduled"], 315000)
        self.assertEqual(met["measure"]["started"], 314570)
        self.assertEqual(met["measure"]["dropped"], 430)
        self.assertAlmostEqual(met["measure"]["drop_fraction"],
                               430 / 315000, places=6)
        # B2: 75 drops -> PASS
        m2 = _k6_metrics(314925, 314925,
                         {"success": 310400, "expected_rejection": 60,
                          "local_no_request": 4465, "unexpected": 0,
                          "prepare_failed": 0},
                         iter_p95=46.0, iter_p99=101.0,
                         begins_total=359287, ends_total=359287,
                         dropped_whole=714)
        s2 = _summary(dropped_whole=714, iters=359287)
        v2, met2 = self._eval(s2, m2)
        self.assertEqual(v2, "PASS", met2)
        self.assertEqual(met2["measure"]["dropped"], 75)


class SubjectLifecycleWiringTest(unittest.TestCase):
    """Structural checks that oauth.js actually wires the subject-token
    lifecycle (a real k6 run exercises subject_state_test.js; these lock
    the integration points in the load script itself)."""

    ROOT = Path(__file__).resolve().parents[2]

    def setUp(self):
        self.oauth = (self.ROOT / "perf" / "k6" / "oauth.js").read_text()
        self.subj = (self.ROOT / "perf" / "k6" /
                     "subject_state.js").read_text()

    def test_subject_counters_declared(self):
        for name in ("cap_subject_initial_mint",
                     "cap_subject_refresh_update",
                     "cap_subject_expired_reauth"):
            self.assertIn(f"'{name}'", self.subj)
        # oauth.js consumes them via the imported subjectCounters map
        self.assertIn("subjectCounters", self.oauth)
        self.assertIn("capSubjectEvent(", self.oauth)

    def test_refresh_adopts_access_token_gated_on_200(self):
        m = re.search(r"async function capRefreshOp\(\).*?\n\}", self.oauth,
                      re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        # adoption only on HTTP 200 and only when access_token exists —
        # a failed refresh must never retimestamp subjectAt
        self.assertRegex(body, r"response\.status === 200 && "
                               r"adoptSubjectAccessToken\(")
        self.assertIn("capSubjectEvent('refresh_update')", body)
        # refresh_token rotation semantics preserved
        self.assertIn("response.json('refresh_token')", body)

    def test_mint_classifies_and_counts(self):
        m = re.search(r"async function capMintSubjectTokens\(.*?\n\}",
                      self.oauth, re.S)
        self.assertIsNotNone(m)
        body = m.group(0)
        self.assertIn("classifyMint(", body)
        self.assertIn("capSubjectEvent(", body)

    def test_per_bucket_counters_wired(self):
        self.assertIn("_iter_begin", self.oauth)
        self.assertIn("cap_m${i + 1}_subject_${kind}", self.oauth)
        self.assertIn("capBucketSubject[kind]", self.oauth)

    def test_no_high_cardinality_subject_tags(self):
        # subject lifecycle counters must be plain names — never VU,
        # user or client ids as tags.
        self.assertNotRegex(
            self.subj + self.oauth,
            r"cap_subject_\w+[`'\"]\s*,")


if __name__ == "__main__":
    unittest.main()
