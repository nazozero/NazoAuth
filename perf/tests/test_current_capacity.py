"""Valid observations outrank invalid observer attempts when bounding load."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from current_capacity import SCENARIOS, bounds, point_name


def record(rate, verdict, seconds):
    return {"rate": rate, "verdict": verdict, "metrics": {"window_seconds": seconds}}


class CapacityBoundsTests(unittest.TestCase):
    def bound(self, *records):
        return bounds({"scene": list(records)}, "scene")

    def test_invalid_long_recheck_does_not_erase_valid_short_observation(self):
        self.assertEqual(self.bound(record(100, "PASS", 90), record(100, "INVALID", 180)), (100, None))

    def test_valid_short_failure_replaces_invalid_long_observer_attempt(self):
        self.assertEqual(self.bound(record(100, "PASS", 180), record(200, "INVALID", 90),
                                    record(200, "FAIL", 60)), (100, 200))

    def test_valid_long_failure_supersedes_short_candidate_pass(self):
        self.assertEqual(self.bound(record(50, "PASS", 180), record(100, "PASS", 90),
                                    record(100, "FAIL", 180)), (50, 100))

    def test_valid_long_pass_is_retained(self):
        self.assertEqual(self.bound(record(100, "PASS", 180), record(100, "FAIL", 60)), (100, None))

    def test_invalid_only_never_establishes_an_upper_or_lower_bound(self):
        self.assertEqual(self.bound(record(100, "INVALID", None), record(100, "INVALID", 90)), (0, None))

    def test_first_failure_is_above_highest_passing_load(self):
        self.assertEqual(self.bound(record(100, "FAIL", 60), record(200, "PASS", 180),
                                    record(400, "FAIL", 60), record(300, "FAIL", 60)), (200, 300))

    def test_receiver_names_fit_dns_labels_at_all_search_rates_and_windows(self):
        for scenario, initial in SCENARIOS.items():
            for mode, cores in (("single", 1), ("multi", 16)):
                for window in (60, 180, 660):
                    with self.subTest(scenario=scenario, mode=mode, window=window):
                        name = "sis-rcv-" + point_name(
                            mode, scenario, initial * cores * 2**8, window, 1790543188)
                        self.assertLessEqual(len(name.encode("idna")), 63)

    def test_point_names_distinguish_every_scene_and_cpu_mode(self):
        names = {point_name(mode, scenario, 20, 180, 1790543188)
                 for mode in ("single", "multi") for scenario in SCENARIOS}
        self.assertEqual(len(names), 2 * len(SCENARIOS))
