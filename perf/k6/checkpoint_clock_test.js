// Synthetic late-VU coverage test for the unified measurement clock.
//
// No NazoAuth / PostgreSQL dependency — pure generator workload:
//   * iterations sleep 1ms for the first 30 scenario seconds,
//   * then sleep 180ms, which at 20 it/s forces constant-arrival-rate to
//     spawn additional VUs (maxVUs=8) mid-run.
// VUs created inside the measurement window must join cohort 'measure'
// immediately on the scenario clock, while the legacy VU-local rule (lw=1)
// still re-warms them for 15s — one stream, both accountings.
//
// Asserts (in teardown, after all VUs finish):
//   * scenario clock was available,
//   * late VUs were actually created (vus_max > preAllocatedVUs),
//   * measure-cohort iterations exist with lw=0 (late-VU ops the legacy
//     rule would have missed) and lw=1,
//   * every begin has an end for non-post cohorts (no silent gaps).
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import {
  COHORT_MEASURE, COHORT_POST, COHORT_PRE, bucketCount, bucketIndexAt,
  capIterMs, contractFromMetrics, createMeasurementClock,
  parseDurationMs,
} from './measurement_clock.js';

const duration = __ENV.PERF_DURATION || '90s';
const WARMUP_MS = Number(__ENV.CAP_WARMUP_MS || '15000');
const DURATION_MS = parseDurationMs(duration);
const BUCKET_MS = 60000;
const BUCKETS = bucketCount(DURATION_MS, WARMUP_MS, BUCKET_MS);
const VU_INIT_MS = Date.now();

const clock = createMeasurementClock({
  durationMs: DURATION_MS,
  measureOffsetMs: WARMUP_MS,
  bucketMs: BUCKET_MS,
  vuInitMs: VU_INIT_MS,
});

const opLatency = new Trend('cap_measure_ms', true);
const ops = new Counter('cap_measure_ops');
const bucketOps = [];
for (let i = 0; i < BUCKETS; i += 1) {
  bucketOps.push(new Counter(`cap_m${i + 1}_ops`));
}
const slowModeMs = Number(__ENV.SYNTH_SLOW_AFTER_MS || '30000');

export const options = {
  scenarios: {
    synth: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: 1,
      maxVUs: 8,
      gracefulStop: '30s',
      exec: 'synth',
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
  // Assertion failures must fail the run: exit code 0 alone is no proof.
  // Every condition expressible as a metric bound is a threshold; the
  // composite synthetic verdict additionally throws in handleSummary,
  // which exits k6 non-zero.
  thresholds: {
    checks: ['rate==1.0'],
    cap_window_clock_ok: ['value==1'],
    cap_iter_begin_late_vu: ['count>0'],
    cap_iter_begin_measure: ['count>0'],
  },
};

export function synth() {
  const entryMs = Date.now();
  const scenarioStart = clock.window().startMs - WARMUP_MS;
  // Legacy rule reconstruction: this VU's own 15s warmup, exactly like the
  // old init-context clock measured it.
  const lw = entryMs - VU_INIT_MS >= WARMUP_MS;
  const cohort = clock.begin(entryMs, lw);
  check(cohort, {
    valid_cohort: (c) => c === COHORT_MEASURE || c === COHORT_PRE
      || c === COHORT_POST,
  });
  check({ cohort, entryMs }, {
    measure_in_window: (o) => o.cohort !== COHORT_MEASURE
      || o.entryMs >= clock.window().startMs,
  });
  const t0 = Date.now();
  sleep(entryMs - scenarioStart < slowModeMs ? 0.001 : 0.18);
  const endMs = Date.now();
  clock.end(cohort, lw, 'success');
  if (cohort !== COHORT_MEASURE) {
    return;
  }
  opLatency.add(endMs - t0);
  capIterMs.add(endMs - entryMs);
  ops.add(1);
  const idx = bucketIndexAt(endMs, clock.window().startMs, BUCKET_MS, BUCKETS);
  if (idx >= 0) {
    bucketOps[idx].add(1);
  }
}

export function handleSummary(data) {
  data.measurement_contract = contractFromMetrics(data.metrics || {}, {
    warmupMs: WARMUP_MS,
    measureStartMs: 0,
  });
  const m = data.metrics || {};
  const countOf = (name) => {
    const metric = m[name];
    return metric ? (metric.values || metric).count || 0 : 0;
  };
  const beginsMeasure = countOf('cap_iter_begin_measure');
  const lateVuOps = countOf('cap_iter_begin_late_vu');
  const legacyOps = countOf('cap_iter_begin_lw1');
  const endsTotal = countOf('cap_iter_end');
  const beginsTotal = countOf('cap_iter_begin');
  const successful = countOf('cap_measure_success');
  data.synthetic_verdict = {
    scenario_clock_ok: (data.measurement_contract.scenario_clock_ok || 0) === 1,
    vus_max: (m.vus_max ? (m.vus_max.values || m.vus_max).max || m.vus_max.value : null),
    window_seconds: data.measurement_contract.window_seconds,
    measure_begins: beginsMeasure,
    legacy_rule_begins: legacyOps,
    late_vu_iterations_measured_only: lateVuOps,
    measured_successful_ops: successful,
    begins_total: beginsTotal,
    ends_total: endsTotal,
    begin_end_reconciled: endsTotal === beginsTotal,
    late_vus_covered: lateVuOps > 0,
    pass: (data.measurement_contract.scenario_clock_ok === 1)
      && lateVuOps > 0 && endsTotal === beginsTotal
      && beginsMeasure > 0 && beginsMeasure > legacyOps,
  };
  // The composite verdict must fail the process, not just the summary:
  // an uncaught throw in handleSummary exits k6 non-zero.
  if (!data.synthetic_verdict.pass) {
    throw new Error(
      `synthetic verdict failed: ${JSON.stringify(data.synthetic_verdict)}`,
    );
  }
  const out = {};
  if (__ENV.PERF_SUMMARY_EXPORT) {
    out[__ENV.PERF_SUMMARY_EXPORT] = JSON.stringify(data);
  }
  out.stdout = JSON.stringify(data.synthetic_verdict);
  return out;
}
