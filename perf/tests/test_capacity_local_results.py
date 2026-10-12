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
    def test_checkpoint_and_resume_never_publish_even_with_old_opt_in(self):
        for status in ("passed", "threshold_failed"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                report = directory / "report.md"
                results = directory / "results.json"
                point = capacity.skipped_after_threshold_failure_point(
                    scenario="token_only_client_credentials", rate=1,
                    duration="1s", instances=1,
                )
                point["result"]["status"] = status
                point["result"]["k6"].update(rps=1, iterations_completed=1)
                argv = ["capacity", "--instances", "1", "--rates", "1,2",
                        "--scenarios", "token_only_client_credentials",
                        "--report-path", str(report), "--results-path", str(results)]
                with patch.object(sys, "argv", argv), \
                     patch.dict(os.environ, {"CAPACITY_CHECKPOINT_COMMIT": "1"}), \
                     patch.object(capacity, "RESULTS_DIR", directory), \
                     patch.object(capacity, "CHECKPOINT_LOCK", directory / "lock"), \
                     patch.object(capacity.subprocess, "run", side_effect=AssertionError("unexpected subprocess")), \
                     patch.object(capacity, "run_point", return_value=point) as run:
                    # Use only one fresh point for passing; failure also exercises skip persistence.
                    if status == "passed":
                        argv[4] = "1"
                    capacity.main()
                    self.assertEqual(run.call_count, 1)
                    saved = json.loads(results.read_text())
                    self.assertEqual(saved[0]["result"]["status"], status)
                    if status == "threshold_failed":
                        self.assertEqual(saved[1]["result"]["status"], "skipped_after_threshold_failure")
                    self.assertTrue(report.is_file())
                    run.reset_mock()
                    capacity.main()
                    run.assert_not_called()
                    self.assertEqual(json.loads(results.read_text()), saved)


if __name__ == "__main__":
    unittest.main()
