"""Exercise preview logs, workload resolution and audit/collector evidence contracts."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "perf/tools"))
sys.path.insert(0, str(ROOT / "perf"))
import capacity_preview as preview
import current_capacity as capacity
import ledger_check
import point_runner


class ToolContractTests(unittest.TestCase):
    def test_preview_reads_persisted_ansi_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.log"
            path.write_text("\x1b[31mERROR failed\x1b[0m\rnext\n")
            self.assertEqual(preview.sanitize_log(preview.read_tail(path, 10)), "ERROR failed\nnext")
            self.assertIn("ERROR failed", preview.interesting_lines(path))

    def test_explicit_population_reaches_runner_unchanged(self):
        tree = ast.parse((ROOT / "perf/runner.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "ensure_user_capacity")
        scope = {"os": os}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "runner", "exec"), scope)
        recipe = capacity.resource_profile({"multi": list(range(16)), "postgres": list(range(16))}, "multi")
        with patch.dict(os.environ, {"PERF_USER_COUNT": str(recipe["users"]), "PERF_MAX_VUS": str(recipe["vus"])}, clear=True):
            scope["ensure_user_capacity"]()
            self.assertEqual(int(os.environ["PERF_USER_COUNT"]), recipe["users"])
        with patch.dict(os.environ, {"PERF_MAX_VUS": "512"}, clear=True):
            scope["ensure_user_capacity"]()
            self.assertEqual(os.environ["PERF_USER_COUNT"], "512")

    def test_warmup_failure_cannot_be_hidden_by_clean_measurement(self):
        load = {"load_status": "completed"}
        metrics = {"full_run_iterations_completed": 100, "full_run_success": 99,
                   "outcome_unexpected": 0, "outcome_success": 90}
        self.assertIsNone(point_runner.expected_issuances("cap_client_credentials", load, metrics))
        metrics["full_run_success"] = 100
        self.assertEqual(point_runner.expected_issuances("cap_client_credentials", load, metrics), 100)
        del metrics["full_run_success"]
        self.assertIsNone(point_runner.expected_issuances("cap_client_credentials", load, metrics))

    def test_blackbox_sampler_requires_its_observable_dimensions(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / "sampler.jsonl"
            meta = {"kind": "meta", "run_id": "test", "script_sha256": "a",
                    "collection_contract": "blackbox-db-v1"}
            sample = {"pg": {}, "pg_db": {}, "vk": {}}
            def check():
                path.write_text(json.dumps(meta) + "\n" + json.dumps(sample) + "\n")
                return ledger_check.check_sampler(path, "test")
            self.assertEqual(check(), 0)
            del sample["pg_db"]
            self.assertEqual(check(), 2)
            sample["pg_db"] = {}
            meta.pop("collection_contract")
            self.assertEqual(check(), 2)
            sample["pool"] = {}
            self.assertEqual(check(), 0)
