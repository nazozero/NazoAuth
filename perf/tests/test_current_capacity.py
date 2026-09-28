"""Valid observations outrank invalid observer attempts when bounding load."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from current_capacity import SCENARIOS, bounds, point_name
import current_capacity as cc
from perf.tests.test_pool_size_ab import _rec


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


class PointVerdictTests(unittest.TestCase):
    def setUp(self):
        self.rec = _rec()
        self.rec['metrics']['audit_log_scan']['collected'] = True
        self.rec['metrics']['common_window_s'] = {'seconds': 180}
        self.rec['audit_state_check']['checks'] = {'collected': True}
        self.rec['journal_stats'] = {'collected': True}
        self.rec['audit_queue_post_drain']['collected'] = True
        self.point = {'scenario': 'cap_mixed', 'rate': 100,
                      'duration': '240s', 'warmup_ms': 60000,
                      'sidecars': cc.sidecars(16, 240)}

    def evaluate(self, main='PASS', sides=None, confirmation=False,
                 maintenance='PASS'):
        sides = sides or {}

        def business(summary, path, target, duration, label, **kwargs):
            self.assertTrue(kwargs['require_stream'])
            return (main if path.parent.name == 'load'
                    else sides.get(path.parent.name, 'PASS')), {}

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cc.gate, 'evaluate', side_effect=business) as evaluator, \
                patch.object(cc.sis, 'issuance_maintenance_evidence',
                             return_value={'status': maintenance}):
            result = cc.evaluate_point(self.point, self.rec, Path(tmp),
                                       confirmation=confirmation)
            return result, evaluator.call_args_list

    def test_clean_point_evaluates_each_sidecar_with_its_own_recipe(self):
        (verdict, metrics, _, _), calls = self.evaluate()
        self.assertEqual(verdict, 'PASS')
        self.assertEqual(len(calls), 5)
        for call, recipe in zip(calls[1:], self.point['sidecars']):
            self.assertEqual(call.args[2:5],
                             (recipe['rate'], 270, recipe['scenario']))
        self.assertEqual(len(metrics['sidecar_gates']), 4)

    def test_finished_sidecar_business_failure_rejects_mixed(self):
        for name in ('argon2', 'meta', 'fapi', 'refresh'):
            with self.subTest(sidecar=name):
                (verdict, metrics, health, _), _ = self.evaluate(sides={name: 'FAIL'})
                self.assertTrue(health['sidecars_complete'])
                self.assertEqual(verdict, 'FAIL')
                self.assertEqual(metrics['sidecar_gates'][name]['verdict'], 'FAIL')

    def test_invalid_sidecar_does_not_establish_service_upper_bound(self):
        (verdict, _, _, _), _ = self.evaluate(main='FAIL', sides={'fapi': 'INVALID'})
        self.assertEqual(verdict, 'INVALID')

    def test_missing_mixed_recipe_is_invalid(self):
        self.point['sidecars'].pop()
        (verdict, metrics, _, _), _ = self.evaluate()
        self.assertEqual(verdict, 'INVALID')
        self.assertIn('sidecar_recipe_error', metrics)

    def test_local_preparation_failure_stays_invalid_with_collected_health(self):
        for failure in ('prepare_failed', 'prepare_local_failed'):
            with self.subTest(failure=failure):
                self.rec['metrics'][f'outcome_{failure}'] = 1
                (verdict, metrics, _, _), _ = self.evaluate(main='INVALID')
                self.assertTrue(metrics['health_evidence_collected'])
                self.assertEqual(verdict, 'INVALID')
                self.rec['metrics'][f'outcome_{failure}'] = 0

    def test_invalid_generator_not_overwritten_by_health_failure(self):
        self.rec['metrics']['audit_log_scan']['queue_full'] = 1
        (verdict, metrics, _, _), _ = self.evaluate(main='LOAD_GENERATOR_RESOURCE_INVALID')
        self.assertEqual(verdict, 'LOAD_GENERATOR_RESOURCE_INVALID')
        self.assertEqual(metrics['health_verdict'], 'FAIL')

    def test_measured_sut_preparation_failure_remains_failure(self):
        self.rec['metrics']['outcome_prepare_sut_failed'] = 1
        (verdict, _, _, _), _ = self.evaluate(main='FAIL')
        self.assertEqual(verdict, 'FAIL')

    def test_missing_health_evidence_cannot_be_a_service_failure(self):
        self.rec['ok'] = False
        (verdict, _, _, _), _ = self.evaluate(main='FAIL')
        self.assertEqual(verdict, 'INVALID')

    def test_maintenance_failure_cannot_overwrite_invalid_measurement(self):
        (verdict, _, _, maintenance), _ = self.evaluate(
            main='INVALID', confirmation=True, maintenance='FAIL')
        self.assertEqual(verdict, 'INVALID')
        self.assertEqual(maintenance['status'], 'FAIL')

    def test_missing_summary_is_invalid_in_authoritative_evaluator(self):
        self.assertEqual(cc.gate.evaluate(None, Path('missing.json'), 100, 60,
                                         'cap_mixed')[0], 'INVALID')
