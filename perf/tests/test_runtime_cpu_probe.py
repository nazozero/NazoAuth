"""CPU plans depend only on the tested runtime, never host metadata."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "runtime_cpu_probe", Path(__file__).parents[1] / "tools/runtime_cpu_probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RuntimeCpuProbeTests(unittest.TestCase):
    def test_host_fields_in_old_snapshot_do_not_influence_plan(self):
        source = {"runnable": [24, 25, 161, 162], "online_reported": "0-63",
                  "visible_quota_cores": 1, "topology": {"24": [0, 0]}}
        result = probe.make_plan(source)
        self.assertEqual(result["allowed"], [24, 25, 161, 162])
        self.assertEqual(result["multi"], [24, 25])
        self.assertEqual(result["topology_status"], "OUT_OF_SCOPE")
        self.assertFalse(set(result["multi"]) & set(result["infra"]))

    def test_explicit_runtime_quota_is_only_a_planning_hint(self):
        result = probe.make_plan({"runnable": [2, 3, 6, 7]}, 2)
        self.assertEqual(result["multi"], [2])
        self.assertEqual(result["cpu_budget"], 2)
        self.assertEqual(result["isolation"], "LOGICAL_CPU_SETS_SEPARATED")

    def test_single_cpu_is_reported_shared_instead_of_blocking(self):
        result = probe.make_plan({"runnable": [7]})
        self.assertEqual(result["single"], result["infra"])
        self.assertEqual(result["isolation"], "SHARED_INFRA")

    def test_probe_restores_affinity_and_does_not_read_host_files(self):
        state = {"mask": {24, 161}}

        def pin(pid, mask):
            if mask == {161}:
                raise OSError("denied")
            state["mask"] = set(mask)

        with patch.object(probe.os, "sched_getaffinity", side_effect=lambda pid: state["mask"], create=True), \
             patch.object(probe.os, "sched_setaffinity", side_effect=pin, create=True), \
             patch.object(probe.ctypes, "CDLL", return_value=object()), \
             patch.object(Path, "read_text", side_effect=AssertionError("no file inspection")):
            result = probe.probe()
        self.assertEqual(result["runnable"], [24])
        self.assertIn("161", result["rejected"])
        self.assertEqual(state["mask"], {24, 161})

    def test_no_successful_binding_requires_explicit_unpinned_fallback(self):
        with self.assertRaisesRegex(ValueError, "NO_TESTED_PINNABLE_CPU"):
            probe.make_plan({"runnable": []})

    def test_prepared_cli_accepts_old_host_flag_without_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / "runner.json"
            runner.write_text(json.dumps({"runnable": [4, 5]}))
            missing_host = Path(directory) / "must-not-be-read.json"
            args = ["probe", "plan", "--runner", str(runner), "--host", str(missing_host)]
            output = io.StringIO()
            with patch.object(sys, "argv", args), contextlib.redirect_stdout(output):
                probe.main()
            self.assertEqual(json.loads(output.getvalue())["single"], [4])


if __name__ == "__main__":
    unittest.main()
