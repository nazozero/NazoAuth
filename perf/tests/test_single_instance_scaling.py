#!/usr/bin/env python3
"""Offline unit tests for the single-instance scaling harness.

Run: python3 -m unittest perf.tests.test_single_instance_scaling -v

Covered (pure logic only — no docker, no host assumptions):
  * cpu-list parse/format round-trip, including single ids and ranges;
  * SMT sibling grouping incl. partial groups (sibling outside the
    allowed cpuset);
  * nested X4/X8/X16 plan: distinct physical cores for X4/X8, X16 adds the
    sibling threads, infra is the exact complement;
  * pinset argv construction;
  * runner summary -> normalized point metrics extraction;
  * phase-2 retention gates: A stability, +5% B gain on both points,
    combined p99 threshold, clean outcomes, WAL/success, runtime health,
    audit drain;
  * phase-3 gates: B >= A*0.98, drop-fraction +0.1pp bound, combined p99
    bound, no local_no_request/expected-rejection inflation, refresh
    invariants, sidecar terminal completeness;
  * pinset C source static checks (--pid mode, exec mode, no shortcuts).
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import single_instance_scaling as sis  # noqa: E402


def metric_record(**overrides) -> dict:
    rec = {
        "window_valid": True,
        "successful_ops_per_s": 1000.0,
        "ops_per_s": 1000.0,
        "measure_ops": 105000,
        "http_reqs": 105000,
        "http_rps": 1000.0,
        "iterations_completed": 105000,
        "dropped_iterations": 0,
        "drop_fraction": 0.0,
        "op_p50_ms": 3.0,
        "op_p95_ms": 8.0,
        "op_p99_ms": 12.0,
        "outcome_success": 105000,
        "outcome_expected_rejection": 0,
        "outcome_local_no_request": 0,
        "outcome_unexpected": 0,
        "outcome_prepare_failed": 0,
        "wal_delta_bytes": 5_000_000.0,
        "wal_per_success_bytes": 47.619,
        "oom_killed": False,
        "restart_count": 0,
        "audit_drained": True,
        "audit_db_drained": True,
        "audit_delivery_reconciled": True,
        "audit_log_scan": {
            "collected": True, "queue_full": 0, "dropped_required": 0},
    }
    rec.update(overrides)
    return rec


class CpuListTest(unittest.TestCase):
    def test_parse_ranges_and_singles(self):
        self.assertEqual(sis.parse_cpu_list("88-91,96"), frozenset({88, 89, 90, 91, 96}))
        self.assertEqual(sis.parse_cpu_list("5"), frozenset({5}))

    def test_parse_rejects_empty_and_inverted(self):
        with self.assertRaises(ValueError):
            sis.parse_cpu_list("")
        with self.assertRaises(ValueError):
            sis.parse_cpu_list("91-88")

    def test_format_roundtrip(self):
        for spec in ("88-91,96", "0-63", "7", "1,3,5-7,9"):
            self.assertEqual(
                sis.format_cpu_list(sis.parse_cpu_list(spec)),
                spec if spec != "1,3,5-7,9" else "1,3,5-7,9",
            )


class CpuSetPlanTest(unittest.TestCase):
    """The remote benchmark host allows cpus 87-150: 31 complete SMT pairs
    (88-89 .. 148-149) plus two half cores (87, 150)."""

    def setUp(self):
        self.allowed = set(range(87, 151))
        self.groups = [frozenset({87})]
        for base in range(88, 150, 2):
            self.groups.append(frozenset({base, base + 1}))
        self.groups.append(frozenset({150}))
        self.groups.sort(key=min)

    def test_plan_uses_whole_cores_for_x4_x8(self):
        plan = sis.plan_cpu_sets(self.allowed, self.groups)
        self.assertEqual(plan["X4"], [88, 90, 92, 94])
        self.assertEqual(plan["X8"], [88, 90, 92, 94, 96, 98, 100, 102])
        self.assertEqual(plan["X16"], list(range(88, 104)))
        # Partial cores are never assigned to the app reservation.
        self.assertNotIn(87, plan["APP_RESERVED"])
        self.assertNotIn(150, plan["APP_RESERVED"])
        # Infra is the exact complement and covers the stragglers.
        self.assertEqual(set(plan["INFRA"]) | set(plan["APP_RESERVED"]),
                         self.allowed)
        self.assertTrue(set(plan["INFRA"]).isdisjoint(plan["APP_RESERVED"]))
        self.assertIn(87, plan["INFRA"])
        self.assertIn(150, plan["INFRA"])
        self.assertEqual(len(plan["INFRA"]), 48)

    def test_nested_sets(self):
        plan = sis.plan_cpu_sets(self.allowed, self.groups)
        self.assertTrue(set(plan["X4"]) < set(plan["X8"]))
        self.assertTrue(set(plan["X8"]) < set(plan["X16"]))

    def test_too_small_allowed_set_rejected(self):
        with self.assertRaises(ValueError):
            sis.plan_cpu_sets(set(range(8)), [frozenset({0, 1}), frozenset({2, 3})])


class PinsetArgvTest(unittest.TestCase):
    def test_pin_command(self):
        self.assertEqual(
            sis.pin_argv("/opt/sis/pinset", "88-91", ["nazoauth", "server"]),
            ["/opt/sis/pinset", "88-91", "nazoauth", "server"])

    def test_pinset_source_has_pid_and_exec_modes(self):
        src = sis.PINSET_C
        self.assertIn("sched_setaffinity", src)
        self.assertIn('"--pid"', src)
        self.assertIn("execvp", src)
        # Failure paths must exit nonzero, never fall through to exec.
        self.assertIn("perror(\"sched_setaffinity\")", src)


class ExtractMetricsTest(unittest.TestCase):
    def test_extracts_measure_contract_fields(self):
        combined = {
            "status": "passed",
            "k6_exit_code": 0,
            "k6": {
                "http_reqs": 105000,
                "rps": 1000.0,
                "iterations_completed": 105000,
                "dropped_iterations": 0,
                "drop_fraction": 0.0,
                "measure": {
                    "ops": 105000,
                    "ops_per_s": 1000.0,
                    "successful_ops_per_s": 999.5,
                    "outcomes": {"success": 104948, "expected_rejection": 0,
                                 "local_no_request": 0, "unexpected": 0,
                                 "prepare_failed": 52},
                    "latency_ms": {"p50": 3.0, "p95": 8.0, "p99": 12.0},
                    "measurement_contract": {"window_seconds": 105},
                    "window_valid": True,
                },
            },
            "db_pool": {"acquire_count": 105000, "wait_ms_total": 12.5},
        }
        rec = sis.extract_point_metrics(combined)
        self.assertEqual(rec["successful_ops_per_s"], 999.5)
        self.assertEqual(rec["window_seconds"], 105)
        self.assertEqual(rec["outcome_success"], 104948)
        self.assertEqual(rec["outcome_prepare_failed"], 52)
        self.assertTrue(rec["window_valid"])

    def test_missing_measure_yields_nulls(self):
        rec = sis.extract_point_metrics({"k6": {}})
        self.assertIsNone(rec["successful_ops_per_s"])
        self.assertFalse(rec["window_valid"])


class WalPerSuccessTest(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(sis.wal_per_success(1000.0, 100), 10.0)

    def test_no_success_or_no_wal(self):
        self.assertIsNone(sis.wal_per_success(None, 100))
        self.assertIsNone(sis.wal_per_success(10.0, 0))


class Phase2GateTest(unittest.TestCase):
    def make_records(self, a1=1000.0, a2=1000.0, b1=1100.0, b2=1100.0,
                     **common):
        return {
            "A1": metric_record(successful_ops_per_s=a1, **common),
            "A2": metric_record(successful_ops_per_s=a2, **common),
            "B1": metric_record(successful_ops_per_s=b1, **common),
            "B2": metric_record(successful_ops_per_s=b2, **common),
        }

    def test_pass(self):
        verdict = sis.evaluate_phase2_gates(self.make_records())
        self.assertTrue(verdict["retain"])
        self.assertEqual(verdict["verdict"], "PASS")

    def test_unstable_a_is_inconclusive(self):
        verdict = sis.evaluate_phase2_gates(self.make_records(a2=900.0, b1=1200.0, b2=1200.0))
        self.assertEqual(verdict["verdict"], "INCONCLUSIVE")
        self.assertFalse(verdict["retain"])

    def test_b_must_exceed_amax_by_5_percent_on_both(self):
        # B2 only +4% over max(A) -> fail.
        verdict = sis.evaluate_phase2_gates(self.make_records(b2=1040.0))
        self.assertFalse(verdict["retain"])
        self.assertFalse(verdict["gates"]["b_gain"]["pass"])

    def test_p99_combined_threshold(self):
        # +11% and +3ms -> violation; +11% but only +1ms -> allowed.
        records = self.make_records()
        records["B1"]["op_p99_ms"] = 13.32  # 12 * 1.11, +1.32ms
        records["B2"]["op_p99_ms"] = 15.5   # +29%, +3.5ms -> violation
        verdict = sis.evaluate_phase2_gates(records)
        rows = {r["point"]: r for r in verdict["gates"]["p99_regression"]["rows"]}
        self.assertFalse(rows["B1"]["violation"])
        self.assertTrue(rows["B2"]["violation"])
        self.assertFalse(verdict["retain"])

    def test_local_no_request_fails(self):
        records = self.make_records()
        records["B1"]["outcome_local_no_request"] = 5
        verdict = sis.evaluate_phase2_gates(records)
        self.assertFalse(verdict["gates"]["clean_outcomes"]["pass"])

    def test_wal_increase_fails(self):
        records = self.make_records()
        records["B1"]["wal_per_success_bytes"] = 60.0  # +26% vs A mean 47.619
        verdict = sis.evaluate_phase2_gates(records)
        self.assertFalse(verdict["gates"]["wal_per_success"]["pass"])

    def test_oom_fails(self):
        records = self.make_records()
        records["B2"]["oom_killed"] = True
        verdict = sis.evaluate_phase2_gates(records)
        self.assertFalse(verdict["gates"]["runtime_health"]["pass"])

    def test_audit_db_drain_fails(self):
        records = self.make_records()
        records["A2"]["audit_db_drained"] = False
        verdict = sis.evaluate_phase2_gates(records)
        self.assertFalse(verdict["gates"]["audit_db_drained"]["pass"])

    def test_audit_delivery_fails(self):
        records = self.make_records()
        records["B1"]["audit_delivery_reconciled"] = False
        verdict = sis.evaluate_phase2_gates(records)
        self.assertFalse(
            verdict["gates"]["audit_delivery_reconciled"]["pass"])

    def test_invalid_window_is_invalid(self):
        records = self.make_records()
        records["B1"]["window_valid"] = False
        verdict = sis.evaluate_phase2_gates(records)
        self.assertEqual(verdict["verdict"], "INVALID")


class Phase3GateTest(unittest.TestCase):
    def make(self, a_over=None, b_over=None):
        a = metric_record()
        b = metric_record(successful_ops_per_s=1100.0)
        b["audit_log_scan"] = {
            "collected": True, "queue_full": 0, "dropped_required": 0}
        b["sidecar_terminal_complete"] = True
        b["refresh_invariants"] = {
            "max_active_per_scope": 3,
            "spent_max_per_family": 12,
            "spent_expired_backlog": 0,
        }
        a["audit_log_scan"] = {
            "collected": True, "queue_full": 0, "dropped_required": 0}
        if a_over:
            a.update(a_over)
        if b_over:
            b.update(b_over)
        return a, b

    def test_pass(self):
        a, b = self.make()
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertTrue(verdict["retain"])

    def test_b_below_98_percent_of_a_fails(self):
        a, b = self.make(b_over={"successful_ops_per_s": 970.0})
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["gates"]["throughput"]["pass"])

    def test_drop_fraction_bound(self):
        a, b = self.make(a_over={"drop_fraction": 0.010},
                         b_over={"drop_fraction": 0.0112})
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["gates"]["drop_fraction"]["pass"])
        a, b = self.make(a_over={"drop_fraction": 0.010},
                         b_over={"drop_fraction": 0.0109})
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertTrue(verdict["gates"]["drop_fraction"]["pass"])

    def test_expected_rejection_inflation_fails(self):
        a, b = self.make(b_over={"outcome_expected_rejection": 50})
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["gates"]["clean_outcomes"]["pass"])

    def test_refresh_invariant_breach_fails(self):
        a, b = self.make()
        b["refresh_invariants"]["spent_max_per_family"] = 65
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["gates"]["refresh_invariants"]["pass"])

    def test_queue_full_fails(self):
        a, b = self.make()
        b["audit_log_scan"]["queue_full"] = 2
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["gates"]["runtime_health"]["pass"])

    def test_missing_sidecar_summary_fails(self):
        a, b = self.make()
        b["sidecar_terminal_complete"] = False
        verdict = sis.evaluate_phase3_gates(a, b)
        self.assertFalse(verdict["retain"])


class DurationParseTest(unittest.TestCase):
    def test_units(self):
        self.assertEqual(sis._duration_seconds("120s"), 120)
        self.assertEqual(sis._duration_seconds("2m"), 120)
        self.assertEqual(sis._duration_seconds("360"), 360)

    def test_bad(self):
        with self.assertRaises(ValueError):
            sis._duration_seconds("10x")


def fake_proc(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr)


class DockerHarnessPatch:
    """Patch sis.dc with a recording fake plus the exclusive project."""

    def __init__(self, test, labels=None):
        self.test = test
        self.calls = []
        self.labels = labels or {}

    def __enter__(self):
        self._saved = {k: getattr(sis, k)
                       for k in ("PROJECT", "dc")}
        sis.PROJECT = "sis-selftest"
        def fake_dc(*args, check=True, timeout=None):
            self.calls.append(list(args))
            if args[:1] == ("inspect",):
                return fake_proc(
                    stdout=self.labels.get(args[1], "") + "\n")
            return fake_proc()
        sis.dc = fake_dc
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(sis, k, v)


class CleanupOwnershipTest(unittest.TestCase):
    """stack_down must touch only the exclusive compose project plus
    recorded, label-matching extras — never name-prefix sweeps."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._ec = sis.EXTRA_CONTAINERS
        sis.EXTRA_CONTAINERS = Path(self.tmp.name) / "extra.jsonl"
        self.addCleanup(setattr, sis, "EXTRA_CONTAINERS", self._ec)

    def test_no_extras_only_compose_down(self):
        with DockerHarnessPatch(self) as h:
            sis.stack_down()
        self.assertEqual(len(h.calls), 1)
        cmd = h.calls[0]
        self.assertEqual(cmd[0], "compose")
        self.assertEqual(cmd[cmd.index("-p") + 1], "sis-selftest")
        self.assertIn("down", cmd)
        # No global enumeration, no prune, no container rm/stop at all.
        for banned in ("ps", "prune", "rm", "stop", "kill"):
            self.assertNotIn(banned, cmd)

    def test_foreign_resources_never_enumerated(self):
        """sis-test-pg, other sis tasks, old soak tasks and the shared
        nazoauth-perf project must not even be listed, let alone sent
        stop/rm/down commands."""
        with DockerHarnessPatch(self) as h:
            sis.stack_down()
        for c in h.calls:
            self.assertNotEqual(c[:1], ["ps"],
                                f"global enumeration issued: {c}")

    def test_recorded_extras_label_gate(self):
        extras = [
            {"id": "id-own", "name": "sis-sampler-X4", "service": "sampler"},
            {"id": "id-foreign", "name": "sis-sampler-X4", "service": "s"},
            {"id": "id-gone", "name": "sis-gone", "service": "sampler"},
        ]
        sis.EXTRA_CONTAINERS.write_text(
            "\n".join(json.dumps(e) for e in extras))
        with DockerHarnessPatch(
                self, labels={"id-own": "sis-selftest",
                              "id-foreign": "sis-other"}) as h:
            # Same name as ours but a foreign owner label must not be rm'd.
            orig = sis.dc
            def fake_dc(*args, check=True, timeout=None):
                h.calls.append(list(args))
                if args[:1] == ("inspect",):
                    if args[1] == "id-gone":
                        return fake_proc(rc=1)
                    return fake_proc(
                        stdout=h.labels.get(args[1], "") + "\n")
                return fake_proc()
            sis.dc = fake_dc
            sis.stack_down()
            sis.dc = orig
        rms = [c for c in h.calls if c[:1] == ["rm"]]
        self.assertEqual(rms, [["rm", "-f", "id-own"]])
        for c in h.calls:
            if c and c[0] in ("rm", "stop", "kill"):
                self.assertEqual(c[-1], "id-own")

    def test_same_name_foreign_not_removed(self):
        with DockerHarnessPatch(
                self, labels={"foreign-id": "sis-other"}) as h:
            orig = sis.dc
            def fake_dc(*args, check=True, timeout=None):
                h.calls.append(list(args))
                if args[:1] == ("inspect",):
                    if "{{.Id}}" in args:
                        return fake_proc(stdout="foreign-id\n")
                    return fake_proc(stdout="sis-other\n")
                return fake_proc()
            sis.dc = fake_dc
            removed = sis._remove_owned_by_name("sis-sampler-X4")
            sis.dc = orig
        self.assertFalse(removed)
        self.assertFalse(any(c[:1] == ["rm"] for c in h.calls))


class WaitHealthyExactTest(unittest.TestCase):
    """'unhealthy' contains 'healthy' — only exact equality may pass."""

    def setUp(self):
        self._dc, self._proj = sis.dc, sis.PROJECT
        self._sleep = sis.time.sleep
        sis.PROJECT = "sis-selftest"
        sis.time.sleep = lambda *_: None
        self.status = "unhealthy"
        def fake_dc(*args, check=True, timeout=None):
            if "Health" in args[-1]:
                return fake_proc(stdout=f'"{self.status}"\n')
            return fake_proc(stdout="true\n")
        sis.dc = fake_dc
        self.addCleanup(self._restore)

    def _restore(self):
        sis.dc, sis.PROJECT, sis.time.sleep = (
            self._dc, self._proj, self._sleep)

    def test_unhealthy_is_not_healthy(self):
        self.assertFalse(sis.wait_healthy("pg", timeout_s=0.05))

    def test_starting_is_not_healthy(self):
        self.status = "starting"
        self.assertFalse(sis.wait_healthy("pg", timeout_s=0.05))

    def test_exact_healthy_passes(self):
        self.status = "healthy"
        self.assertTrue(sis.wait_healthy("pg", timeout_s=5))


class PgssIdentityResetTest(unittest.TestCase):
    def row(self, **kw):
        base = {"dbid": 1, "userid": 10, "toplevel": True, "queryid": 7,
                "calls": 100, "total_exec_time": 500.0, "rows": 10,
                "q": "SELECT", "rolname": "nazoauth_perf_runtime"}
        base.update(kw)
        return base

    def test_delta_uses_full_identity_not_queryid(self):
        pre = {"stats_reset": 1.0,
               "statements": [self.row()]}
        post = {"stats_reset": 1.0,
                "statements": [
                    self.row(calls=150, total_exec_time=700.0),
                    # Same queryid, different userid — a distinct identity.
                    self.row(userid=11, rolname="observer",
                             calls=5, total_exec_time=9.0)]}
        d = sis.pgss_delta(pre, post, 100)
        self.assertTrue(d["valid"])
        self.assertEqual(d["total_calls_delta"], 55)

    def test_cross_reset_refused(self):
        pre = {"stats_reset": 1790180347.988551, "statements": []}
        post = {"stats_reset": 1790180369.652601, "statements": []}
        d = sis.pgss_delta(pre, post, 100)
        self.assertFalse(d["valid"])
        self.assertIn("reset", d["reason"])

    def test_missing_identity_refused(self):
        pre = {"stats_reset": 1.0, "statements": []}
        post = {"stats_reset": 1.0,
                "statements": [{"queryid": 7, "calls": 3, "q": "SELECT"}]}
        d = sis.pgss_delta(pre, post, 100)
        self.assertFalse(d["valid"])
        self.assertIn("identity", d["reason"])

    def test_missing_reset_refused(self):
        d = sis.pgss_delta({"statements": []}, {"statements": []}, 100)
        self.assertFalse(d["valid"])


class WindowConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def soak(self, events):
        p = Path(self.tmp.name) / "soak-metrics.jsonl"
        p.write_text("\n".join(json.dumps(e) for e in events))
        return p

    def test_windowed_delta_interpolates(self):
        p = self.soak([{"ts": t, "wal_bytes": t * 10}
                       for t in range(100, 201, 10)])
        d = sis.windowed_series_delta(p, "wal_bytes", 120000, 180000)
        self.assertEqual(d["delta"], 600)

    def test_windowed_delta_missing_window(self):
        p = self.soak([{"ts": t, "wal_bytes": t} for t in (100, 200)])
        d = sis.windowed_series_delta(p, "wal_bytes", None, None)
        self.assertIsNone(d["delta"])
        self.assertIn("window", d["reason"])

    def test_windowed_delta_edges_outside(self):
        p = self.soak([{"ts": t, "wal_bytes": t} for t in (100, 200)])
        d = sis.windowed_series_delta(p, "wal_bytes", 50000, 180000)
        self.assertIsNone(d["delta"])

    def test_x8_full_window_normalization(self):
        # acquire_count is app-lifetime: honest denominator is full-run
        # HTTP, NOT the post-warmup cohort (2172564/475667 ≈ 4.567 is a
        # mixed-window result that must never be produced).
        out = sis.acquire_per_http(2172564, 542120)
        self.assertAlmostEqual(out["per_request"], 4.008, places=3)
        self.assertIn("background", out["window"])

    def test_wal_per_success_missing_is_none(self):
        self.assertIsNone(sis.wal_per_success(None, 100))
        self.assertIsNone(sis.wal_per_success(100.0, None))
        self.assertIsNone(sis.wal_per_success(0.0, 100))


class MissingMetricGateTest(unittest.TestCase):
    """Absent evidence is not passing evidence."""

    def make_records(self, **b1_over):
        recs = {"A1": metric_record(), "A2": metric_record(),
                "B1": metric_record(successful_ops_per_s=1100.0),
                "B2": metric_record(successful_ops_per_s=1100.0)}
        recs["B1"].update(b1_over)
        return recs

    def missing_fields(self, verdict):
        return {(m["point"], m["field"])
                for m in verdict["gates"]["required_evidence"]["missing"]}

    def test_missing_outcome_fails(self):
        recs = self.make_records()
        del recs["B1"]["outcome_unexpected"]
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertIn(("B1", "outcome_unexpected"),
                      self.missing_fields(v))

    def test_missing_wal_fails(self):
        v = sis.evaluate_phase2_gates(
            self.make_records(wal_per_success_bytes=None))
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertIn(("B1", "wal_per_success_bytes"),
                      self.missing_fields(v))

    def test_missing_health_fails(self):
        v = sis.evaluate_phase2_gates(
            self.make_records(oom_killed=None, restart_count=None))
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertIn(("B1", "oom_killed"), self.missing_fields(v))

    def test_missing_audit_fails(self):
        v = sis.evaluate_phase2_gates(
            self.make_records(audit_db_drained=None))
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])


class RequiredEvidenceGateTest(unittest.TestCase):
    """§1: A1/A2/B1/B2 must all exist with their required fields — no
    filtering a missing baseline down to a one-sided comparison."""

    def make_records(self):
        return {"A1": metric_record(), "A2": metric_record(),
                "B1": metric_record(successful_ops_per_s=1100.0),
                "B2": metric_record(successful_ops_per_s=1100.0)}

    def missing(self, verdict):
        return {(m["point"], m["field"])
                for m in verdict["gates"]["required_evidence"]["missing"]}

    def test_a1_throughput_missing_invalid(self):
        recs = self.make_records()
        recs["A1"]["successful_ops_per_s"] = None
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertIn(("A1", "successful_ops_per_s"), self.missing(v))

    def test_a2_throughput_missing_invalid(self):
        recs = self.make_records()
        recs["A2"]["successful_ops_per_s"] = None
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])

    def test_a1_wal_missing_invalid(self):
        recs = self.make_records()
        recs["A1"]["wal_per_success_bytes"] = None
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertIn(("A1", "wal_per_success_bytes"), self.missing(v))

    def test_a2_wal_missing_invalid(self):
        recs = self.make_records()
        recs["A2"]["wal_per_success_bytes"] = None
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])

    def test_missing_point_record_invalid(self):
        recs = self.make_records()
        del recs["B2"]
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertIn(("B2", "<point record>"), self.missing(v))

    def test_legal_zero_throughput_no_crash_no_approval(self):
        recs = self.make_records()
        for r in recs.values():
            r["successful_ops_per_s"] = 0.0
        v = sis.evaluate_phase2_gates(recs)
        # Not INVALID — the evidence exists, it is just zero. Stability
        # cannot be certified and the candidate is not approved.
        self.assertNotEqual(v["verdict"], "INVALID")
        self.assertFalse(v["gates"]["a_stability"]["pass"])
        self.assertFalse(v["gates"]["b_gain"]["pass"])
        self.assertFalse(v["retain"])

    def test_delivery_missing_blocks_approval(self):
        # audit_drained=True (old field) + DB drain ok but no receiver
        # evidence: end-to-end reconciliation must not be claimed.
        recs = self.make_records()
        recs["B1"]["audit_delivery_reconciled"] = None
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])
        self.assertNotIn("audit_delivery_reconciled",
                         [g for g in v["gates"] if g != "required_evidence"])

    def test_log_collection_failure_is_not_clean(self):
        recs = self.make_records()
        recs["B1"]["audit_log_scan"] = {
            "collected": False, "queue_full": 0, "dropped_required": 0}
        v = sis.evaluate_phase2_gates(recs)
        self.assertFalse(v["gates"]["runtime_health"]["pass"])

    def test_complete_valid_evidence_still_passes(self):
        # Gate-combination logic only: the fixture hand-sets
        # audit_delivery_reconciled=True, which NO current collector can
        # produce — audit_delivery_reconciled_of never returns True
        # without real receiver reconciliation facts. This test verifies
        # the evaluator approves a *hypothetically complete* record; it
        # does not claim the harness has ever collected such evidence.
        v = sis.evaluate_phase2_gates(self.make_records())
        self.assertTrue(v["gates"]["required_evidence"]["pass"])
        self.assertEqual(v["verdict"], "PASS")
        self.assertTrue(v["retain"])


class AuditEvidenceScopeTest(unittest.TestCase):
    """DB drain vs end-to-end delivery reconciliation are separate."""

    def drain(self, **kw):
        d = {"pending": 0, "last_sequence": 512556,
             "anchor_sequence": 512556}
        d.update(kw)
        return d

    def test_pending_zero_anchor_mismatch_not_drained(self):
        self.assertFalse(sis.audit_db_drained_of(
            self.drain(anchor_sequence=512555)))

    def test_missing_anchor_not_drained(self):
        self.assertFalse(sis.audit_db_drained_of(
            self.drain(anchor_sequence=None)))

    def test_pending_nonzero_not_drained(self):
        self.assertFalse(sis.audit_db_drained_of(self.drain(pending=3)))

    def test_db_drained_happy(self):
        self.assertTrue(sis.audit_db_drained_of(self.drain()))

    def test_delivery_unknown_without_receiver(self):
        self.assertIsNone(sis.audit_delivery_reconciled_of(
            self.drain(), {"collected": False}))

    def test_delivery_unknown_with_log_health_only(self):
        # A collected, clean log is receiver *health*, not
        # reconciliation facts (sequence/hash/deployment) — UNKNOWN.
        self.assertIsNone(sis.audit_delivery_reconciled_of(
            self.drain(), {"collected": True, "error_markers": 0}))

    def test_delivery_unknown_empty_log(self):
        self.assertIsNone(sis.audit_delivery_reconciled_of(
            self.drain(), {"collected": True, "lines": 0,
                           "error_markers": 0, "ack_markers": 0}))

    def test_delivery_unknown_any_ack_markers(self):
        # Keyword counts must never upgrade UNKNOWN into reconciled.
        self.assertIsNone(sis.audit_delivery_reconciled_of(
            self.drain(), {"collected": True, "error_markers": 0,
                           "ack_markers": 512556}))

    def test_delivery_false_on_receiver_errors(self):
        self.assertFalse(sis.audit_delivery_reconciled_of(
            self.drain(), {"collected": True, "error_markers": 2}))

    def test_delivery_false_when_db_not_drained(self):
        self.assertFalse(sis.audit_delivery_reconciled_of(
            self.drain(pending=1), {"collected": False}))

    def test_real_helper_into_evaluator_blocks_retain(self):
        # DB drained + clean log but no receiver reconciliation state:
        # feeding the real helper output into the real evaluator must
        # not approve the candidate.
        recs = {"A1": metric_record(), "A2": metric_record(),
                "B1": metric_record(successful_ops_per_s=1100.0),
                "B2": metric_record(successful_ops_per_s=1100.0)}
        drain = self.drain()
        rcv = {"collected": True, "lines": 42,
               "error_markers": 0, "ack_markers": 17}
        for r in recs.values():
            r["audit_db_drained"] = sis.audit_db_drained_of(drain)
            r["audit_delivery_reconciled"] = (
                sis.audit_delivery_reconciled_of(drain, rcv))
        v = sis.evaluate_phase2_gates(recs)
        self.assertEqual(v["verdict"], "INVALID")
        self.assertFalse(v["retain"])


class LogScanTest(unittest.TestCase):
    def setUp(self):
        self._dc, self._proj = sis.dc, sis.PROJECT
        sis.PROJECT = "sis-selftest"
        self.proc = fake_proc()
        sis.dc = lambda *a, **k: self.proc
        self.addCleanup(self._restore)

    def _restore(self):
        sis.dc, sis.PROJECT = self._dc, self._proj

    def test_stderr_anomalies_counted(self):
        self.proc = fake_proc(
            stdout="all fine\n",
            stderr="queue_full\ndropped_required\nboom\n")
        s = sis.app_log_scan(1000)
        self.assertTrue(s["collected"])
        self.assertEqual(s["queue_full"], 1)
        self.assertEqual(s["dropped_required"], 1)

    def test_failed_collection_is_not_silent(self):
        self.proc = fake_proc(rc=1, stderr="daemon error")
        s = sis.app_log_scan(1000)
        self.assertFalse(s["collected"])

    def test_empty_log_distinct_from_failure(self):
        self.proc = fake_proc(stdout="", stderr="")
        s = sis.app_log_scan(1000)
        self.assertTrue(s["collected"])
        self.assertEqual(s["lines"], 1)  # the "\n" join separator


class BudgetAccountingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._ll = sis.LOAD_LOG
        sis.LOAD_LOG = Path(self.tmp.name) / "budget.json"
        self.addCleanup(setattr, sis, "LOAD_LOG", self._ll)

    def state(self):
        return json.loads(sis.LOAD_LOG.read_text())

    def test_completed_records_seconds(self):
        sis.budget_spend("X4", 5.5)
        e = self.state()["points"][0]
        self.assertEqual(e["status"], "completed")
        self.assertEqual(e["load_seconds"], 5.5)
        self.assertEqual(self.state()["load_seconds_used"], 5.5)

    def test_unmeasurable_is_unknown_not_zero(self):
        # run_load raised after the container may have started: the
        # finally-path must still record the attempt, marked unknown.
        rec = {}
        try:
            rec["load"] = {"load_seconds": None}
            raise RuntimeError("orchestration blew up")
        except RuntimeError:
            pass
        finally:
            sis._spend_load_budget("A1", rec)
        e = self.state()["points"][0]
        self.assertEqual(e["status"], "unknown")
        self.assertIsNone(e["load_seconds"])
        self.assertEqual(self.state()["load_seconds_used"], 0.0)

    def test_missing_load_key_is_unknown(self):
        sis._spend_load_budget("B2", {})
        e = self.state()["points"][0]
        self.assertEqual(e["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
