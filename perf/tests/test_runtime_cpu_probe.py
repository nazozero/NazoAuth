"""CNB's visible topology must not veto CPUs accepted by the scheduler."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "runtime_cpu_probe", Path(__file__).parents[1] / "tools/runtime_cpu_probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def snapshot(cpus, online="0-63", quota=None, topology=None):
    return {"runnable": cpus, "online_reported": online,
            "visible_quota_cores": quota, "topology": topology or {}}


class RuntimeCpuProbeTests(unittest.TestCase):
    def test_hidden_parent_and_conflicting_online_still_allow_logical_plan(self):
        host = snapshot([24, 25, 161, 162], quota=64)
        result = probe.make_plan(host, host)
        self.assertEqual(result["allowed"], [24, 25, 161, 162])
        self.assertEqual(result["topology_status"], "UNVERIFIED")
        self.assertEqual(result["effective_parent_capacity"], "UNKNOWN")
        self.assertFalse(set(result["multi"]) & set(result["infra"]))

    def test_runner_can_use_cpus_outside_ssh_affinity(self):
        result = probe.make_plan(snapshot([0]), snapshot([4, 5]))
        self.assertEqual(result["allowed"], [4, 5])

    def test_consistent_smt_siblings_stay_out_of_infra(self):
        topology = {"2": [0, 0], "3": [0, 1], "6": [0, 0], "7": [0, 1]}
        source = snapshot([2, 3, 6, 7], online="0-7", topology=topology)
        result = probe.make_plan(source, source)
        self.assertEqual(result["single"], [2])
        self.assertEqual(result["infra"], [3, 7])
        self.assertEqual(result["isolation"], "VISIBLE_SMT_GROUPS_SEPARATED")

    def test_single_cpu_is_reported_shared_instead_of_blocking(self):
        result = probe.make_plan(snapshot([7]), snapshot([7]))
        self.assertEqual(result["single"], result["infra"])
        self.assertEqual(result["isolation"], "SHARED_INFRA")

    def test_probe_restores_affinity_after_one_cpu_is_rejected(self):
        state = {"mask": {24, 161}}

        def pin(pid, mask):
            if mask == {161}:
                raise OSError("denied")
            state["mask"] = set(mask)

        with patch.object(probe.os, "sched_getaffinity", side_effect=lambda pid: state["mask"]), \
             patch.object(probe.os, "sched_setaffinity", side_effect=pin), \
             patch.object(probe.ctypes, "CDLL", return_value=object()), \
             patch.object(probe, "read", return_value=None):
            result = probe.probe()
        self.assertEqual(result["runnable"], [24])
        self.assertIn("161", result["rejected"])
        self.assertEqual(state["mask"], {24, 161})

    def test_no_successful_binding_requires_explicit_unpinned_fallback(self):
        with self.assertRaisesRegex(ValueError, "NO_TESTED_PINNABLE_CPU"):
            probe.make_plan(snapshot([1]), snapshot([]))


if __name__ == "__main__":
    unittest.main()
