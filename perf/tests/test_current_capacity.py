"""Valid observations outrank invalid observer attempts when bounding load."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from current_capacity import bounds


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
