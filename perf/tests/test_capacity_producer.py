"""Execute the real JS producer and consume its labels with the Python gate.

Node supplies only k6 I/O/metric shims. The measurement clock, capRun and
bootstrap failure handling execute from the production load-script sources.
"""
import ast
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

try:
    from .test_stream_cohort import ROOT, _feed, _write_point, ca, cs
except ImportError:  # unittest discover -s perf/tests
    from test_stream_cohort import ROOT, _feed, _write_point, ca, cs


NODE_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const root = process.argv[2];
const clock = fs.readFileSync(root + '/perf/k6/measurement_clock.js', 'utf8')
  .replace(/^import .*;\n/gm, '').replace(/\bexport /g, '');
const oauth = fs.readFileSync(root + '/perf/k6/oauth.js', 'utf8');
const run = oauth.slice(oauth.indexOf('function capOutcomeOf('),
  oauth.indexOf('// Vectors are only consumed'));
const mint = oauth.slice(oauth.indexOf('const CAP_SUBJECT_AT_MAX_AGE_MS'),
  oauth.indexOf('function capUserinfoOp('));
const results = {};
(async () => {
  for (const mode of ['success', 'unexpected', 'local', 'sut', 'unknown', 'mixed_sut']) {
    const points = [];
    let now = 1015000;
    class Metric {
      constructor(name) { this.name = name; }
      add(value, tags = {}) {
        points.push({type: 'Point', metric: this.name,
          data: {metric: this.name, time: new Date(now).toISOString(), value, tags}});
      }
    }
    const context = vm.createContext({
      Counter: Metric, Gauge: Metric, Trend: Metric,
      exec: {scenario: {startTime: 1000000}}, Date: {now: () => now},
      capPhase: () => 'measure', sleep: () => {},
      capBucketBegins: [new Metric('bucket_begin')],
      capBucketLatency: [new Metric('bucket_latency')],
      capBucketOps: [new Metric('bucket_ops')], capBucketErrs: [new Metric('bucket_errs')],
      capOps: new Metric('cap_measure_ops'), capErrs: new Metric('cap_measure_errors'),
      capLatency: new Metric('cap_measure_ms'), CAP_BUCKET_MS: 60000, CAP_BUCKETS: 31,
      __VU_STATE: {}, classifyMint: () => 'initial_mint',
      selectedUser: () => ({email: 'fixture', password: 'fixture'}),
      capVector: () => ({oidc_state: 'state', oidc_nonce: 'nonce', oidc_code_challenge: 'challenge'}),
      requestObject: async () => {
        now += 10;
        if (mode === 'local') throw new Error('invalid local signing fixture');
        return 'jar';
      },
      secrets: {clients: {oidc: 'client'}, client_secret: 'fixture'}, BASE_URL: 'http://sut',
      form: x => x, formHeaders: x => x, requestTags: x => x,
      http: {post: () => {
        now += 5;
        if (mode === 'unknown') throw new Error('unclassified runtime exception');
        return {status: 503, body: 'unavailable'};
      }},
      advance: n => { now += n; }, mode,
    });
    vm.runInContext(clock + run + mint + `
      const capClock = createMeasurementClock({durationMs: 1800000,
        measureOffsetMs: 15000, bucketMs: 60000, vuInitMs: 1000000});
    `, context);
    await vm.runInContext(`
      mode === 'success' || mode === 'unexpected'
        ? capRun(async () => advance(10), async () => { advance(5); return mode === 'success'; })
        : mode === 'mixed_sut'
          ? capRun(async () => {}, async () => capMintSubjectTokens(false))
          : capRun(async () => capMintSubjectTokens(false), async () => true)
    `, context);
    results[mode] = points;
  }
  process.stdout.write(JSON.stringify(results));
})().catch(e => { console.error(e); process.exit(1); });
"""


@unittest.skipUnless(shutil.which('node'), 'Node is required to execute the real JS producer')
class ProducerConsumerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            ['node', '-', str(ROOT)], input=NODE_HARNESS,
            text=True, capture_output=True, check=True)
        cls.produced = json.loads(result.stdout)

    def test_real_labels_named_counters_and_stream_agree(self):
        for mode, expected in (
                ('success', 'success'), ('unexpected', 'unexpected'),
                ('local', 'prepare_local_failed'), ('sut', 'prepare_sut_failed'),
                ('unknown', 'prepare_failed'), ('mixed_sut', 'prepare_sut_failed')):
            with self.subTest(mode=mode):
                points = self.produced[mode]
                series = ca.StreamingSeries()
                _feed(series, points)
                series.emit_window()
                self.assertEqual(series.window_json['measurement_cohort']['measure_outcomes'],
                                 {expected: 1})
                named = [p for p in points if p['metric'] == f'cap_measure_{expected}']
                self.assertEqual(sum(p['data']['value'] for p in named), 1)
                bins = series.finalize_bins()
                flattened = [ca.bin_record(b) for b in bins.values()]
                self.assertEqual(sum(b[expected] for b in flattened), 1)

    def test_preparation_failures_and_success_include_entry_to_end_latency(self):
        for mode, expected_ms in (('success', 15), ('local', 10), ('sut', 15),
                                  ('unknown', 15), ('mixed_sut', 15)):
            with self.subTest(mode=mode):
                latency = [p['data']['value'] for p in self.produced[mode]
                           if p['metric'] == 'cap_iter_ms']
                self.assertEqual(latency, [expected_ms])

    def test_real_unexpected_is_sut_fail_not_counter_mismatch(self):
        end = next(p for p in self.produced['unexpected'] if p['metric'] == 'cap_iter_end')
        outcome = end['data']['tags']['outcome']
        with tempfile.TemporaryDirectory() as td:
            path, summary = _write_point(
                Path(td), started=5_355_000, completed=5_355_000, dropped=0,
                outcomes={'success': 5_354_999, outcome: 1})
            verdict, metrics = cs.evaluate(summary, path, 3000, 1800,
                                           'cap_mixed', require_stream=True)
        self.assertEqual(verdict, 'FAIL', metrics)
        self.assertEqual(metrics['unexpected_errors'], 1)

    def test_runner_keeps_all_prepare_failed_cohort_without_operation_trend(self):
        # Execute the runner's pure summary functions without importing its
        # Docker/database orchestration dependencies into this offline test.
        names = {'k6_brief', 'k6_error_rate', 'k6_metric_ratio', 'k6_metric_values',
                 'metric_ratio', 'metric_values', 'contract_problems'}
        tree = ast.parse((ROOT / 'perf/runner.py').read_text())
        body = [node for node in tree.body
                if (isinstance(node, ast.FunctionDef) and node.name in names)
                or (isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'CONTRACT_REQUIRED_FIELDS'
                            for t in node.targets))]
        scope = {'Any': Any, 'os': os, 'OUTCOME_NAMES': cs.OUTCOME_NAMES,
                 'cohort_accounting': cs.cohort_accounting,
                 'parse_time_unit_ms': cs.parse_time_unit_ms}
        exec(compile(ast.Module(body=body, type_ignores=[]), 'runner-summary', 'exec'), scope)
        for mode, outcome in (('local', 'prepare_local_failed'),
                              ('sut', 'prepare_sut_failed'), ('unknown', 'prepare_failed')):
            with self.subTest(mode=mode):
                metrics = {}
                for point in self.produced[mode]:
                    name, value = point['metric'], point['data']['value']
                    if name.startswith('cap_window_'):
                        continue
                    if name == 'cap_iter_ms':
                        metrics[name] = {'values': {'med': value, 'p(95)': value, 'p(99)': value}}
                    else:
                        metrics.setdefault(name, {'count': 0})['count'] += value
                self.assertNotIn('cap_measure_ms', metrics)
                summary = {'metrics': metrics, 'measurement_contract': {
                    'contract': 'cap-scenario-window-v1', 'scenario_start_ms': 1015000,
                    'window_start_ms': 1015000, 'window_end_ms': 1016000,
                    'window_seconds': 1, 'duration_ms': 1000,
                    'scenario_clock_ok': 1, 'divergent_vus': False}}
                with patch.dict(os.environ, {'PERF_RATE': '1', 'PERF_TIME_UNIT': '1s'}):
                    measure = scope['k6_brief'](summary)['measure']
                self.assertEqual(measure['outcomes'][outcome], 1)
                self.assertEqual(measure['completed'], 1)
                self.assertTrue(measure['cohort_valid'])
                self.assertEqual(measure['successful_ops_per_s'], 0)


if __name__ == '__main__':
    unittest.main()
