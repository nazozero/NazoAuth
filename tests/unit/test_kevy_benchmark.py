import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kevy_benchmark", ROOT / "scripts/bench-kevy-valkey.py"
)
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def observation(second, components):
    return {
        "time_ns": second * BENCH.NS,
        "components": {
            role: {
                "root_start_ticks": 1,
                "cpu_ticks": ticks,
                "pss_kib": pss_mib * 1024,
                "rss_kib": pss_mib * 1024,
                "affinity_mismatches": 0,
            }
            for role, (ticks, pss_mib) in components.items()
        },
        "pressure_us": {"cpu_some": None},
        "host_cpu_ticks": [second, 0, 0, second, 0, 0, 0, 0],
        "loadavg": [0, 0, 0],
        "host_tasks": {"procs_running": 1, "procs_blocked": 0},
    }


class KevyBenchmarkResources(unittest.TestCase):
    def test_reaped_child_counter_drop_and_recovery_do_not_double_count_cpu(self):
        samples = [
            observation(0, {"app": (100 * BENCH.HZ, 1)}),
            observation(1, {"app": (0, 1)}),
            observation(2, {"app": (101 * BENCH.HZ, 1)}),
        ]
        resources, total, _, _ = BENCH.resource_summary(samples, ["app"], 0, 2 * BENCH.NS)

        self.assertAlmostEqual(resources["app"]["cpu_seconds"], 1.0)
        self.assertEqual(resources["app"]["cpu_sample_seconds"], 2.0)
        self.assertEqual(resources["app"]["cpu_counter_regressions"], 1)
        self.assertAlmostEqual(resources["app"]["mean_cpu_cores"], 0.5)
        self.assertAlmostEqual(total["cpu_seconds"], 1.0)
        self.assertAlmostEqual(total["mean_cpu_cores"], 0.5)

    def test_server_pss_sums_simultaneous_components_before_selecting_peak(self):
        samples = [
            observation(0, {"app": (0, 4), "postgres": (0, 1), "generator": (0, 20)}),
            observation(1, {"app": (1, 1), "postgres": (1, 4), "generator": (1, 24)}),
            observation(2, {"app": (2, 20), "postgres": (2, 20), "generator": (2, 200)}),
        ]
        resources, total, _, _ = BENCH.resource_summary(
            samples, ["app", "postgres", "generator"], 0, 2 * BENCH.NS
        )

        self.assertEqual(resources["app"]["peak_pss_mib"], 4)
        self.assertEqual(resources["postgres"]["peak_pss_mib"], 4)
        self.assertEqual(resources["generator"]["peak_pss_mib"], 24)
        self.assertEqual(total["peak_pss_mib"], 5)
        self.assertEqual(total["memory_samples"], 2)


if __name__ == "__main__":
    unittest.main()
