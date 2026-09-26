#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import pool_size_ab as psa  # noqa: E402
import single_instance_scaling as sis  # noqa: E402


def _rec(run_id="A1", pool=24, ops=2800.0, p99=1100.0, drop=0.05,
         commits=300000, fsyncs=60000, wait_ms=60.0,
         attempted=2850.0, p95=500.0):
    return {
        "ok": True, "run_id": run_id,
        "point": {"name": run_id, "phase": "pool24v32/mixed",
                  "app_env_overrides":
                  {"DATABASE_MAX_CONNECTIONS": str(pool)}},
        "stack": {"app_binary_sha256": "deadbeef"},
        "metrics": {
            "outcome_success": 300000, "successful_ops_per_s": ops,
            "ops_per_s": attempted,
            "op_p50_ms": 200.0, "op_p95_ms": p95, "op_p99_ms": p99,
            "drop_fraction": drop,
            # measurement-cohort fields (authoritative gate population)
            "cohort_valid": True,
            "measure_scheduled": 315000,
            "measure_started": 314925,
            "measure_completed": 314925,
            "measure_dropped": 75,
            "measure_drop_fraction": 0.000238,
            "iter_p95_ms": 46.0, "iter_p99_ms": 101.0,
            "outcome_unexpected": 0, "outcome_local_no_request": 50,
            "outcome_expected_rejection": 10,
            "outcome_prepare_failed": 0,
            "oom_killed": False, "restart_count": 0,
            "audit_db_drained": True,
            "audit_log_scan": {"queue_full": 0, "dropped_required": 0},
            "acquire_per_op_windowed": 6.4,
            "wait_per_acq_ms": wait_ms,
            "wal_bytes_per_s": 2e7, "wal_writes_per_s": 1000,
            "wal_fsyncs_per_s": 800,
            "window_start_ms": 10000, "window_end_ms": 130000,
            "refresh_invariants": {"max_active_per_scope": 3,
                                   "spent_max_per_family": 5,
                                   "spent_expired_backlog": 0},
            "sidecar_terminal_complete": True,
        },
        "load": {"load_status": "completed"},
        "wal_delta": {"fsyncs_total": fsyncs,
                      "fsyncs_client_backend": fsyncs,
                      "db_xact_commit": commits + 100},
        "pgss_delta": {"valid": True,
                       "path_classes": {"commit_txn": commits}},
        "audit_state_check": {
            "verdict": "PASS",
            "journal": {"duplicate_sequences": 0, "sequence_gaps": 0,
                        "range_contiguous": True}},
        "audit_queue_post_drain": {
            "enqueued": 100, "persisted": 100, "dropped": 0,
            "pending_in_process": 0},
    }


def _write_residency(tmp: Path, run_id: str, pool: int,
                     wal_share: float, waiting: int,
                     n_samples: int = 4):
    d = tmp / "pool24v32" / "mixed" / run_id
    d.mkdir(parents=True, exist_ok=True)
    n_wal = int(round(wal_share * 10))
    backends = ([{"pid": i, "state": "active", "wet": "IO",
                  "we": "WalSync"} for i in range(n_wal)] +
                [{"pid": i, "state": "active", "wet": "Client",
                  "we": "ClientRead"} for i in range(n_wal, 10)] +
                [{"pid": i, "state": "idle", "wet": None, "we": None}
                 for i in range(10, pool)])
    with open(d / "residency.jsonl", "w") as fh:
        for ts in (30.0, 60.0, 90.0, 120.0):
            fh.write(json.dumps({
                "kind": "sample", "ts": ts,
                "pool": {"con": pool, "idle": pool - len(backends)
                         if len(backends) < pool else 0,
                         "waiting": waiting, "acq": 1000},
                "backends": backends}) + "\n")


class EvaluatorTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = sis.RESULTS
        tmp = Path(self._tmp.name)
        sis.RESULTS = tmp
        psa.sis.RESULTS = tmp
        self._tmp_path = tmp

    def tearDown(self):
        sis.RESULTS = self._old
        psa.sis.RESULTS = self._old
        self._tmp.cleanup()

    def _records(self, a_ops=(2800.0, 2790.0), b_ops=(2950.0, 2960.0),
                 a_wait=1200, b_wait=600, a_wpa=60.0, b_wpa=40.0,
                 a_share=0.5, b_share=0.5, a_p99=1100.0, b_p99=1050.0,
                 a_drop=0.05, b_drop=0.05, pool_match=True):
        specs = {"A1": (24, a_ops[0], a_p99, a_drop, a_wait, a_wpa,
                        a_share),
                 "B1": (32, b_ops[0], b_p99, b_drop, b_wait, b_wpa,
                        b_share),
                 "B2": (32, b_ops[1], b_p99, b_drop, b_wait, b_wpa,
                        b_share),
                 "A2": (24, a_ops[1], a_p99, a_drop, a_wait, a_wpa,
                        a_share)}
        recs = {}
        for name, (pool, ops, p99, drop, wait, wpa, share) in \
                specs.items():
            r = _rec(run_id=name, pool=pool, ops=ops, p99=p99,
                     drop=drop, wait_ms=wpa)
            _write_residency(self._tmp_path, name,
                             pool if pool_match or name.startswith("A")
                             else pool - 1,
                             share, wait)
            recs[name] = r
        return recs

    def test_pass(self):
        v = psa.evaluate(self._records())
        self.assertEqual(v["verdict"], "PASS", v.get("reason"))

    def test_inconclusive_spread(self):
        v = psa.evaluate(self._records(a_ops=(2800.0, 3000.0)))
        self.assertEqual(v["verdict"], "INCONCLUSIVE")

    def test_fail_no_improvement(self):
        v = psa.evaluate(self._records(b_ops=(2810.0, 2800.0)))
        self.assertEqual(v["verdict"], "FAIL")

    def test_fail_marginal_each(self):
        # B mean +4.4% but B2 only +1.8% vs a_max -> each-3% gate fails.
        v = psa.evaluate(self._records(a_ops=(2800.0, 2700.0),
                                       b_ops=(2980.0, 2830.0)))
        self.assertEqual(v["verdict"], "FAIL")
        self.assertFalse(v["gates"]["throughput_improvement_ge_3pct_each"]
                         ["pass"])

    def test_fail_p99(self):
        v = psa.evaluate(self._records(b_p99=1400.0))
        self.assertEqual(v["verdict"], "FAIL")

    def test_fail_drop(self):
        v = psa.evaluate(self._records(b_drop=0.08))
        self.assertEqual(v["verdict"], "FAIL")

    def test_fail_structural(self):
        v = psa.evaluate(self._records(b_wait=1150, b_wpa=55.0))
        self.assertEqual(v["verdict"], "FAIL")
        self.assertFalse(v["gates"]["structural_pool"]["pass"])

    def test_fail_wal_guardrail(self):
        v = psa.evaluate(self._records(b_share=0.75))
        self.assertEqual(v["verdict"], "FAIL")
        self.assertFalse(v["gates"]["wal_guardrail_le_10pp"]["pass"])

    def test_fail_pool_identity(self):
        v = psa.evaluate(self._records(pool_match=False))
        self.assertEqual(v["verdict"], "FAIL")
        self.assertIn("B1", v["reason"])

    def test_strict_gate(self):
        recs = self._records()
        for p in recs.values():
            e = psa.point_evidence(p)
            self.assertFalse(e["strict_3000_gate"]["pass"])  # 2850<2985
        recs["B1"]["metrics"]["ops_per_s"] = 2990.0
        e = psa.point_evidence(recs["B1"])
        self.assertFalse(e["strict_3000_gate"]["pass"])
        self.assertEqual(e["attainment"], round(2950 / 3000, 4))
        recs["B1"]["metrics"]["successful_ops_per_s"] = 2985.0
        # gate reads the measurement cohort, not whole-run drop/latency
        recs["B1"]["metrics"]["drop_fraction"] = 0.4  # whole-run, ignored
        e = psa.point_evidence(recs["B1"])
        self.assertTrue(e["strict_3000_gate"]["pass"])
        # measurement-cohort drop >0.1% flips it back to FAIL
        recs["B1"]["metrics"]["measure_drop_fraction"] = 0.002
        e = psa.point_evidence(recs["B1"])
        self.assertFalse(e["strict_3000_gate"]["pass"])

    def test_strict_gate_rejects_any_preparation_failure(self):
        m = _rec(ops=3000)["metrics"]
        for outcome in ("prepare_failed", "prepare_local_failed", "prepare_sut_failed"):
            with self.subTest(outcome=outcome):
                changed = dict(m, **{f"outcome_{outcome}": 1})
                self.assertFalse(psa._strict_gate(changed, 3000)["pass"])

    def test_ab_preparation_failure_preserves_attribution(self):
        for outcome, expected in (("prepare_failed", "INVALID"),
                                  ("prepare_local_failed", "INVALID"),
                                  ("prepare_sut_failed", "FAIL")):
            with self.subTest(outcome=outcome):
                records = self._records()
                records['B1']['metrics'][f'outcome_{outcome}'] = 1
                result = psa.evaluate(records)
                self.assertEqual(result['verdict'], expected)
                self.assertEqual(result['points']['B1']['verdict'], expected)


class ClassifyStabilityTest(unittest.TestCase):
    """Pre-registered stability verdict space: PASS/FAIL/INVALID plus
    the seven permitted fail_class values."""

    def test_clean_pass(self):
        stab = {"reauth_herd": {"herd": False},
                "sustained_cliff": {"sustained_cliff": False}}
        self.assertEqual(("PASS", None),
                         psa.classify_stability("PASS", stab, []))

    def test_missing_analysis_is_invalid(self):
        self.assertEqual(("INVALID", "UNRESOLVED"),
                         psa.classify_stability("PASS", None, []))
        self.assertEqual(
            ("INVALID", "UNRESOLVED"),
            psa.classify_stability("PASS", {"error": "x"}, []))

    def test_herd_is_load_model_invalid(self):
        stab = {"reauth_herd": {"herd": True, "max_per_minute": 600},
                "sustained_cliff": {"sustained_cliff": False}}
        self.assertEqual(("INVALID", "LOAD_MODEL_INVALID"),
                         psa.classify_stability("PASS", stab, []))

    def test_isolated_spike_still_passes(self):
        stab = {"reauth_herd": {"herd": False},
                "sustained_cliff": {"sustained_cliff": False},
                "anomaly_buckets": [{"bucket": 7,
                                     "in_checkpoint_write_window": True}]}
        self.assertEqual(("PASS", None),
                         psa.classify_stability("PASS", stab, []))

    def test_sustained_cliff_fail_checkpoint_correlated(self):
        stab = {"reauth_herd": {"herd": False},
                "sustained_cliff": {"sustained_cliff": True},
                "anomaly_buckets": [
                    {"bucket": 7, "in_checkpoint_write_window": True},
                    {"bucket": 13, "in_checkpoint_write_window": True}],
                "buckets": []}
        self.assertEqual(("FAIL", "CHECKPOINT_CORRELATED_CLIFF"),
                         psa.classify_stability("PASS", stab, []))

    def test_sustained_cliff_wal_dominated(self):
        stab = {"reauth_herd": {"herd": False},
                "sustained_cliff": {"sustained_cliff": True},
                "anomaly_buckets": [],
                "buckets": [{"wal": {"wal_wait_share": 0.6}},
                            {"wal": {"wal_wait_share": 0.55}}]}
        self.assertEqual(("FAIL", "SUSTAINED_DB_WAL_CLIFF"),
                         psa.classify_stability("PASS", stab, []))

    def test_sustained_cliff_correlation_only(self):
        stab = {"reauth_herd": {"herd": False},
                "sustained_cliff": {"sustained_cliff": True},
                "anomaly_buckets": [
                    {"bucket": 7, "in_checkpoint_write_window": True}],
                "buckets": [{"wal": {"wal_wait_share": 0.3}}]}
        self.assertEqual(("FAIL", "UNRESOLVED"),
                         psa.classify_stability("PASS", stab, []))

    def test_audit_health_failure(self):
        self.assertEqual(
            ("FAIL", "AUDIT_HEALTH_FAILURE"),
            psa.classify_stability("FAIL", None,
                                   ["enqueued_eq_persisted"]))

    def test_refresh_state_failure(self):
        self.assertEqual(
            ("FAIL", "REFRESH_STATE_FAILURE"),
            psa.classify_stability("FAIL", None,
                                   ["expired_backlog_zero"]))

    def test_other_fail_unresolved(self):
        self.assertEqual(("FAIL", "UNRESOLVED"),
                         psa.classify_stability("FAIL", None,
                                                ["oom_none"]))

    def test_generator_invalid(self):
        self.assertEqual(
            ("INVALID", "GENERATOR_RESOURCE_INVALID"),
            psa.classify_stability("GENERATOR_RESOURCE_INVALID", None,
                                   []))

    def test_load_model_and_injector_cap_invalid(self):
        for f in ("LOAD_MODEL_INVALID", "INVALID",
                  "INJECTOR_CAP_UNEXPECTED"):
            self.assertEqual(("INVALID", "LOAD_MODEL_INVALID"),
                             psa.classify_stability(f, None, []))


if __name__ == "__main__":
    unittest.main()
