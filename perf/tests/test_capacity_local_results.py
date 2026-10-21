"""Capacity checkpoints retain results without publishing them to Git."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("local_capacity", ROOT / "perf/capacity.py")
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


class LocalResultsTests(unittest.TestCase):
    def test_offline_report_preserves_source_and_starts_no_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.json"
            report = Path(tmp) / "report.md"
            source.write_text(json.dumps([{"instances": 2, "scenario": "legacy",
                "target_rate": 10, "duration": "17s", "result": {"k6": {
                    "rps": 100, "error_rate": 0,
                    "latency_ms": {"p50": 1, "p95": 2, "p99": 3}}}}]))
            before = source.read_bytes()
            with patch.object(sys, "argv", ["capacity", "--input", str(source), "--report-path", str(report)]), \
                 patch("subprocess.run", side_effect=AssertionError("offline report started a process")):
                capacity.main()
            self.assertEqual(source.read_bytes(), before)
            self.assertIn("17s", report.read_text())
            self.assertIn("measurement_unavailable", report.read_text())

    def test_legacy_provenance_is_not_reconstructed_from_the_current_machine(self):
        from perf.finalize_capacity_reports import evidence_block
        with patch("subprocess.run", side_effect=AssertionError("current host is not evidence")):
            report = evidence_block(suffix="old", data=[{"duration": "17s", "instances": 2,
                "scenario": "saved", "target_rate": 7}])
        self.assertIn("17s", report)
        self.assertNotIn("30m", report)
        self.assertIn("UNAVAILABLE", report)
        self.assertIn("UNVERIFIED", report)

    def test_endpoint_matrix_does_not_promote_static_plans_to_load_evidence(self):
        from perf.tools.build_matrix import build_matrix
        rows = [{"path": "/token", "status": 200}, {"path": "/fapi/resource", "status": 401}]
        matrix = build_matrix(rows)
        self.assertTrue(all(row["load_status"] == "UNVERIFIED" for row in matrix))
        self.assertEqual(matrix[1]["status"], 401)
        self.assertIn("own DPoP-bound request", matrix[1]["scenario_plan"])
        self.assertNotIn("load_status", rows[0])

    def test_http_requests_do_not_establish_business_capacity(self):
        point = {"target_rate": 10, "result": {"k6": {"rps": 1000}}}
        self.assertIsNone(capacity.target_ratio(point["result"], 10))
        self.assertEqual(capacity.normalized_status(point), "measurement_unavailable")
        point["result"]["k6"]["measure"] = {
            "window_valid": True, "cohort_valid": True, "successful_ops_per_s": 0, "drop_fraction": 0}
        self.assertEqual(capacity.target_ratio(point["result"], 10), 0)
        self.assertEqual(capacity.normalized_status(point), "target_miss")
        point["result"]["k6"]["measure"]["successful_ops_per_s"] = 5
        point["result"]["k6"]["target_ops_per_s"] = 5
        self.assertEqual(capacity.normalized_status(point), "passed")
        point["result"]["k6"]["measure"]["window_valid"] = False
        self.assertEqual(capacity.normalized_status(point), "measurement_unavailable")


if __name__ == "__main__":
    unittest.main()
