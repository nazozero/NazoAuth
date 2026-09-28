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


class CapacityAllocationTests(unittest.TestCase):
    def test_override_redistributes_only_visible_cpus_without_overlap(self):
        visible = set(range(17, 49)) | set(range(130, 162))
        with patch.object(cc.os, 'sched_getaffinity', return_value=visible, create=True):
            default = cc.allocations()
            tuned = cc.allocations(4)
        self.assertEqual(len(default['multi']), 16)
        self.assertEqual(len(tuned['multi']), 4)
        self.assertEqual(len(tuned['postgres']), 16)
        self.assertEqual(len(tuned['generator']), 43)
        groups = [set(tuned[key]) for key in ('multi', 'postgres', 'valkey', 'generator')]
        self.assertEqual(set.union(*groups), visible)
        self.assertEqual(sum(map(len, groups)), len(visible))
        self.assertEqual(tuned['single'], tuned['multi'][:1])

    def test_override_preserves_at_least_one_generator_cpu(self):
        with patch.object(cc.os, 'sched_getaffinity', return_value={7, 9, 11, 13}, create=True):
            self.assertEqual(cc.allocations(1)['generator'], [13])
            for count in (0, 2, 5):
                with self.assertRaises(ValueError):
                    cc.allocations(count)

    def test_shared_small_deployment_cannot_claim_isolated_override(self):
        with patch.object(cc.os, 'sched_getaffinity', return_value={7, 9, 11}, create=True):
            self.assertEqual(cc.allocations()['multi'], [7, 9, 11])
            with self.assertRaises(ValueError):
                cc.allocations(1)


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

    def test_sidecar_quantiles_keep_operation_and_request_populations_separate(self):
        operation = {'med': 41, 'p(95)': 131, 'p(99)': 211}
        request = {'med': 2, 'p(95)': 3, 'p(99)': 4}

        def native(path):
            raw = {'http_req_duration': {'values': request}}
            if path.parent.name != 'meta':
                raw['cap_iter_ms'] = {'values': operation}
            return raw, {}

        with patch.object(cc.gate, 'k6_metrics', side_effect=native):
            (verdict, metrics, _, _), _ = self.evaluate()
        self.assertEqual(verdict, 'PASS')
        self.assertEqual(metrics['sidecar_gates']['fapi']['metrics'][
            'complete_operation_latency_ms'], {'p50': 41, 'p95': 131, 'p99': 211})
        self.assertIsNone(metrics['sidecar_gates']['meta']['metrics'][
            'complete_operation_latency_ms'])

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


class IncrementalExecutionTests(unittest.TestCase):
    def setUp(self):
        self.cpus = {'allowed': list(range(64)), 'single': [0],
                     'multi': list(range(16)), 'postgres': list(range(16, 32)),
                     'valkey': [32], 'generator': list(range(33, 64))}

    def test_resources_scale_and_vu_change_preserves_user_population(self):
        small = cc.resource_profile(self.cpus, 'single')
        large = cc.resource_profile(self.cpus, 'multi')
        self.assertGreater(large['vus'], small['vus'])
        increased = cc.resource_profile(self.cpus, 'multi', vus=2048)
        self.assertEqual(increased['users'], large['users'])
        self.assertEqual(increased['pool_connections'], large['pool_connections'])
        exact = cc.resource_profile(self.cpus, 'multi', vus=512, users=256, pool=48)
        self.assertEqual(exact, {'vus': 512, 'users': 256, 'pool_connections': 48})

    def test_sidecar_vu_override_preserves_offered_workload(self):
        before = cc.sidecars(16, 240)
        after = cc.sidecars(16, 240, [16, 32, 64, 256])
        for old, new in zip(before, after):
            self.assertEqual(old['rate'], new['rate'])
            self.assertEqual(old['user_count'], new['user_count'])
            self.assertGreater(new['pre_vus'], old['pre_vus'])
            self.assertEqual(new['pre_vus'], new['max_vus'])

    def test_small_deployment_reports_shared_infra_without_blocking(self):
        with patch.object(cc.os, 'sched_getaffinity', return_value={7}, create=True):
            cpus = cc.allocations()
        self.assertEqual(cpus['single'], [7])
        self.assertEqual(cpus['postgres'], [7])
        self.assertEqual(cpus['generator'], [7])

    def test_targeted_resume_reuses_same_recipe_and_separates_changed_pool(self):
        import contextlib
        import io
        import json
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(cc.sis, 'RESULTS', Path(tmp)), \
                patch.object(cc, 'allocations', return_value=self.cpus), \
                patch.object(cc.points, 'image_binary_sha', return_value='binary'), \
                patch.object(cc.sis, 'dc', return_value=SimpleNamespace(stdout='image')), \
                patch.object(cc.sis, 'sh', return_value=SimpleNamespace(stdout='controller')), \
                patch.dict(cc.os.environ, {'SIS_APP_SHA': 'application'}), \
                patch.object(cc.points, 'run_ab_point', return_value={}) as run, \
                patch.object(cc, 'evaluate_point', side_effect=lambda *a, **kw:
                             ('PASS', {'window_seconds': 180}, {}, None)), \
                contextlib.redirect_stdout(io.StringIO()):
            legacy = b'{"pool_connections": 32, "harness_sha": "original"}\n'
            (Path(tmp) / 'registered-config.json').write_bytes(legacy)
            args = ['current_capacity.py', '--stop-at', '2099-01-01T00:00:00+00:00',
                    '--mode', 'multi', '--scenarios', 'cap_mixed', '--rates', '2400', '3000',
                    '--vus', '512', '--users', '256', '--pool-connections', '32']
            with patch.object(sys, 'argv', args):
                cc.main()
            archived = next(Path(tmp).glob('registered-config-legacy-*.json'))
            self.assertEqual(archived.read_bytes(), legacy)
            self.assertEqual([c.args[0]['rate'] for c in run.call_args_list], [2400, 3000])
            self.assertTrue(all(c.args[0]['scenario'] == 'cap_mixed'
                                and c.args[0]['pre_vus'] == 512
                                and c.args[0]['user_count'] == 256
                                for c in run.call_args_list))
            original = next(Path(tmp).glob('search-state-*.json'))
            original_bytes = original.read_bytes()
            run.reset_mock()
            # A later stop time or controller-only checkpoint must not repeat load.
            args[2] = '2099-02-01T00:00:00+00:00'
            with patch.object(sys, 'argv', args):
                cc.main()
            run.assert_not_called()
            args[-1] = '48'
            with patch.object(sys, 'argv', args):
                cc.main()
            self.assertEqual(run.call_count, 2)
            self.assertEqual(len(list(Path(tmp).glob('search-state-*.json'))), 2)
            self.assertEqual(original.read_bytes(), original_bytes)
            self.assertEqual(len(json.loads(original.read_text())['multi/cap_mixed']), 2)
            run.reset_mock()
            with patch.object(sys, 'argv', args + ['--stream-workers', '4']):
                cc.main()
            self.assertEqual(run.call_count, 2)
            self.assertEqual(len(list(Path(tmp).glob('search-state-*.json'))), 3)
            self.assertTrue(all(call.args[0]['stream_workers'] == 4
                                for call in run.call_args_list))
            self.assertEqual(original.read_bytes(), original_bytes)

    def test_offline_cli_needs_no_container_and_preserves_source(self):
        import contextlib
        import io
        import json

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'point.json'
            source.write_text(json.dumps({'point': {'capture_audit_journal': True}}))
            before = source.read_bytes()
            output = Path(tmp) / 'reassessed.json'
            with patch.object(sys, 'argv', ['current_capacity.py', '--reevaluate',
                                           str(source), '--output', str(output)]), \
                    patch.object(cc, 'evaluate_point', return_value=('PASS', {}, {}, {})) as evaluate, \
                    patch.object(cc.sis, 'dc') as docker, \
                    patch.object(cc.points, 'run_ab_point') as load, \
                    contextlib.redirect_stdout(io.StringIO()):
                cc.main()
            docker.assert_not_called()
            load.assert_not_called()
            self.assertTrue(evaluate.call_args.kwargs['confirmation'])
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(json.loads(output.read_text())[0]['verdict'], 'PASS')
            with self.assertRaises(ValueError):
                cc.reevaluate([source], source)
