"""Small regression checks for the bounded short-suite controller."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import short_baseline as short
import proc_detail_sampler as sampler


class ShortBaselineTests(unittest.TestCase):
    def test_sparse_affinity_is_partitioned_without_inventing_cpu_ids(self):
        allowed = [7, 11, 20, 31, 42, 50, 101, 177]
        cpus = short.allocate(allowed)
        groups = [set(cpus[k]) for k in ("multi", "postgres", "valkey", "generator")]
        self.assertEqual(set.union(*groups), set(allowed))
        self.assertEqual(sum(map(len, groups)), len(allowed))
        self.assertEqual(cpus["single"], [7])

    def test_small_deployment_shares_infra_and_has_no_fake_multicore(self):
        cpus = short.allocate([19])
        self.assertEqual(cpus["multi"], [19])
        self.assertEqual(cpus["isolation"], "SHARED_INFRA")
        self.assertEqual(len(short.cases(False)), 5)
        self.assertTrue(all(mode == "single" for mode, _, _ in short.cases(False)))

    def test_known_budget_limits_only_the_visible_runtime_seed(self):
        self.assertEqual(short.allocate([5, 6, 9, 11], 2)["allowed"], [5, 6])
        for bad in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                short.allocate([5], bad)

    def test_required_worst_case_fits_one_hour_with_preparation_and_delivery(self):
        budget = sum(short.point_budget(w, s == "cap_mixed") for _, s, w in short.cases())
        self.assertEqual(budget + 15 * 60 + short.FINAL_RESERVE, 3600)
        self.assertGreaterEqual(short.CONFIRM_WINDOW - 360, 180)
        self.assertEqual(short.started_epoch("2026-09-29T14:00:00+08:00"),
                         short.started_epoch("2026-09-29T06:00:00Z"))
        with self.assertRaises(ValueError):
            short.started_epoch("2026-09-29T06:00:00")

    def test_missing_state_is_invalid_not_a_zero_or_a_service_failure(self):
        state = dict(collected=True, fresh_rows=0, legacy_rows=0, issuance_rows=0)
        self.assertEqual(short.token_state_verdict(state, "cap_client_credentials"), "INVALID")
        state["issuance_inserts"] = 0
        self.assertEqual(short.token_state_verdict(state, "cap_client_credentials"), "PASS")
        state["issuance_inserts"] = 50
        self.assertEqual(short.token_state_verdict(state, "cap_client_credentials"), "FAIL")
        self.assertEqual(short.token_state_verdict(state, "cap_authorization_code"), "PASS")
        state["fresh_rows"] = 1
        self.assertEqual(short.token_state_verdict(state, "cap_refresh_token"), "FAIL")

    def test_invalid_results_cannot_complete_the_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [dict(mode=m, scenario=s, rate=1, window_seconds=w,
                         verdict="INVALID", confirmation=w == short.CONFIRM_WINDOW)
                    for m, s, w in short.cases()]
            value = short.report(Path(directory), {}, rows, time.time())
            self.assertEqual(value["status"], "INCOMPLETE")
            self.assertEqual(len(value["missing_valid_cases"]), 9)
            self.assertFalse(value["confirmation_passed"])

    def test_failed_offered_load_is_evidence_but_not_a_passing_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [dict(mode=m, scenario=s, rate=1, window_seconds=w,
                         verdict="FAIL", confirmation=w == short.CONFIRM_WINDOW)
                    for m, s, w in short.cases()]
            value = short.report(Path(directory), {}, rows, time.time())
            self.assertEqual(value["status"], "COMPLETE")
            self.assertFalse(value["confirmation_passed"])
            self.assertEqual(value["acceptance_status"], "FAIL")

    def test_hung_worker_is_terminated_and_returns_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            rc = short.bounded_child([sys.executable, "-c", "import time; time.sleep(60)"],
                                     None, Path(directory) / "worker.log", 0.05)
            self.assertEqual(rc, 124)

    def test_cleanup_never_sweeps_by_prefix_or_removes_volumes(self):
        calls = []
        def fake(args, **kwargs):
            calls.append(args)
            return "abc123" if "ps" in args else ""
        with patch.object(short, "command", side_effect=fake):
            short.own_cleanup("short-test")
        self.assertTrue(all(any("label=" + label in arg for arg in call)
                            for call, label in ((calls[0], "sis.owner=short-test"),
                                                (calls[2], "com.docker.compose.project=short-test"))))
        self.assertFalse(any("volume" in call or "prune" in call for call in calls))

    def test_component_discovery_is_project_scoped(self):
        with patch.object(sampler.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, f"{sampler.PROJECT}-nazoauth-1\n")) as run:
            self.assertEqual(sampler.container_name(f"{sampler.PROJECT}-nazoauth-1"),
                             f"{sampler.PROJECT}-nazoauth-1")
            self.assertIn(f"label=com.docker.compose.project={sampler.PROJECT}", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
