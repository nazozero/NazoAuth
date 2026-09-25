// Unified measurement clock for capacity scenarios.
//
// All cap_* cohort decisions anchor to exec.scenario.startTime — one epoch
// shared by every VU, including VUs that constant-arrival-rate spawns
// mid-run. The per-VU init clock remains in charge of workload lifecycle
// (gap idling, bootstrap re-minting); this module owns only the measurement
// window, the emitted diagnostic-metric contract, and the summary contract.
//
// Metric contract:
//   cap_iter_begin{cohort,lw}           tagged point per iteration entry
//   cap_iter_end{cohort,lw,outcome}     tagged point per observed exit
//     (tags live in the JSON stream; the exported summary keeps totals)
//   cap_iter_begin_measure              measure-cohort entries (named)
//   cap_iter_begin_lw1                  entries the legacy VU-local rule
//                                       would have measured (named)
//   cap_iter_begin_late_vu              measure-cohort entries the legacy
//                                       rule missed — late-created VUs
//   cap_iter_ms                         Trend, entry->end incl. prepare
//                                       (measure cohort only)
//   cap_measure_{success,expected_rejection,local_no_request,unexpected,
//                prepare_failed}        named outcome counters, measure cohort
//   cap_window_*                        Gauges emitted once per VU carrying
//                                       the window contract (plain names —
//                                       k6 summaries fold tag submetrics):
//     scenario_start_ms, measure_start_ms, measure_end_ms (-1 = open),
//     duration_ms (-1 = unknown), measure_offset_ms, bucket_ms,
//     bucket_count, clock_ok (1 = exec.scenario.startTime usable)
//
// cohort: 'pre' | 'measure' | 'post' — by iteration ENTRY time against
//         [measure_start_ms, measure_end_ms) on the scenario clock.
// lw:     '1' iff the legacy per-VU rule (phase === 'measure' on the VU-local
//         clock) would have counted this iteration — lets one execution
//         stream reconstruct both accountings.
// outcome: success | expected_rejection | local_no_request | unexpected |
//          prepare_failed | gap_idle
import exec from 'k6/execution';
import { Counter, Gauge, Trend } from 'k6/metrics';

export const COHORT_PRE = 'pre';
export const COHORT_MEASURE = 'measure';
export const COHORT_POST = 'post';

export const capIterBegin = new Counter('cap_iter_begin');
export const capIterEnd = new Counter('cap_iter_end');
export const capIterBeginMeasure = new Counter('cap_iter_begin_measure');
export const capIterBeginLegacy = new Counter('cap_iter_begin_lw1');
export const capIterBeginLateVu = new Counter('cap_iter_begin_late_vu');
export const capIterMs = new Trend('cap_iter_ms', true);
export const capOutcomeCounters = {
  success: new Counter('cap_measure_success'),
  expected_rejection: new Counter('cap_measure_expected_rejection'),
  local_no_request: new Counter('cap_measure_local_no_request'),
  unexpected: new Counter('cap_measure_unexpected'),
  prepare_failed: new Counter('cap_measure_prepare_failed'),
};
const windowGauges = {
  scenario_start_ms: new Gauge('cap_window_scenario_start_ms'),
  measure_start_ms: new Gauge('cap_window_measure_start_ms'),
  measure_end_ms: new Gauge('cap_window_measure_end_ms'),
  duration_ms: new Gauge('cap_window_duration_ms'),
  measure_offset_ms: new Gauge('cap_window_measure_offset_ms'),
  bucket_ms: new Gauge('cap_window_bucket_ms'),
  bucket_count: new Gauge('cap_window_bucket_count'),
  clock_ok: new Gauge('cap_window_clock_ok'),
};

export function parseDurationMs(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return NaN;
  }
  const factors = { ms: 1, s: 1000, m: 60000, h: 3600000 };
  const pattern = /(\d+(?:\.\d+)?)(ms|s|m|h)/g;
  let total = 0;
  let matched = 0;
  let part;
  while ((part = pattern.exec(value)) !== null) {
    total += Number(part[1]) * factors[part[2]];
    matched += part[0].length;
  }
  // Reject partial parses ('30x' must not silently become 30s).
  if (matched === 0 || matched !== value.trim().length) {
    return NaN;
  }
  return total;
}

// Half-open measurement window [startMs, endMs) on the scenario clock.
// measureOffsetMs is the offset from scenario start at which measuring begins
// (warmup for standard runs, CAP_MEASURE_START_MS when a gap phase is set).
export function measurementWindow(scenarioStartMs, durationMs, measureOffsetMs) {
  return {
    startMs: scenarioStartMs + measureOffsetMs,
    endMs: Number.isFinite(durationMs) ? scenarioStartMs + durationMs : Infinity,
  };
}

export function cohortAt(entryMs, window) {
  if (entryMs < window.startMs) {
    return COHORT_PRE;
  }
  if (entryMs < window.endMs) {
    return COHORT_MEASURE;
  }
  return COHORT_POST;
}

// Minute buckets derive their count from the configured duration so late
// minutes are never folded into a fixed-size last bucket. One extra bucket
// sits past the regular span: completions that land after the configured
// window end (graceful-stop stragglers) stay visible instead of being merged.
export function bucketCount(durationMs, measureOffsetMs, bucketMs) {
  if (!Number.isFinite(durationMs) || bucketMs <= 0) {
    return 2;
  }
  const spanMs = Math.max(0, durationMs - measureOffsetMs);
  return Math.max(1, Math.ceil(spanMs / bucketMs)) + 1;
}

export function bucketIndexAt(ms, windowStartMs, bucketMs, count) {
  const idx = Math.floor((ms - windowStartMs) / bucketMs);
  if (idx < 0) {
    return -1;
  }
  return Math.min(idx, count - 1);
}

// exec.scenario.startTime throws in init context, so the scenario clock is
// read lazily inside VU runtime and cached. When it is unavailable the VU
// falls back to its own init timestamp — emitted contracts then diverge
// between VUs and the analyzer marks the run INVALID (never silently fixed).
let cachedScenarioStartMs = null;
let cachedClockOk = false;

export function scenarioStartMs(fallbackMs) {
  if (cachedScenarioStartMs === null) {
    let start = 0;
    try {
      start = exec.scenario.startTime;
    } catch (e) {
      start = 0;
    }
    cachedClockOk = typeof start === 'number' && start > 0;
    cachedScenarioStartMs = cachedClockOk ? start : fallbackMs;
  }
  return cachedScenarioStartMs;
}

export function scenarioClockOk() {
  return cachedClockOk;
}

function emitWindowContract(window, durationMs, measureOffsetMs, bucketMs, count) {
  windowGauges.scenario_start_ms.add(scenarioStartMs(0));
  windowGauges.measure_start_ms.add(window.startMs);
  windowGauges.measure_end_ms.add(Number.isFinite(window.endMs) ? window.endMs : -1);
  windowGauges.duration_ms.add(Number.isFinite(durationMs) ? durationMs : -1);
  windowGauges.measure_offset_ms.add(measureOffsetMs);
  windowGauges.bucket_ms.add(bucketMs);
  windowGauges.bucket_count.add(count);
  windowGauges.clock_ok.add(scenarioClockOk() ? 1 : 0);
}

// Per-VU measurement clock instance. Module state is per-VU in k6, so the
// cached window stays stable for the VU's whole lifetime.
export function createMeasurementClock(config) {
  let window = null;
  let emitted = false;
  const count = bucketCount(config.durationMs, config.measureOffsetMs, config.bucketMs);

  function currentWindow() {
    if (window === null) {
      window = measurementWindow(
        scenarioStartMs(config.vuInitMs), config.durationMs, config.measureOffsetMs,
      );
      if (!emitted) {
        emitted = true;
        emitWindowContract(window, config.durationMs, config.measureOffsetMs, config.bucketMs, count);
      }
    }
    return window;
  }

  return {
    // Record an iteration entry; lw = whether the legacy VU-local rule would
    // have measured this iteration. Returns the unified-window cohort.
    begin(entryMs, legacyMeasured) {
      const cohort = cohortAt(entryMs, currentWindow());
      capIterBegin.add(1, { cohort, lw: legacyMeasured ? '1' : '0' });
      if (cohort === COHORT_MEASURE) {
        capIterBeginMeasure.add(1);
        if (!legacyMeasured) {
          capIterBeginLateVu.add(1);
        }
      }
      if (legacyMeasured) {
        capIterBeginLegacy.add(1);
      }
      return cohort;
    },
    // Record an observed iteration exit (every capRun branch must call this).
    end(cohort, legacyMeasured, outcome) {
      capIterEnd.add(1, { cohort, lw: legacyMeasured ? '1' : '0', outcome });
      const counter = capOutcomeCounters[outcome];
      if (cohort === COHORT_MEASURE && counter) {
        counter.add(1);
      }
    },
    window: currentWindow,
    buckets: count,
  };
}

// Rebuild the measurement contract from exported summary metrics (plain
// gauge names — k6 summaries fold tag submetrics into the parent metric).
// Gauge min != max means VUs disagreed on the window (e.g. a per-VU clock
// fallback) — surfaced as divergent_vus so consumers can mark INVALID.
export function contractFromMetrics(metrics, constants) {
  const gauge = (name) => {
    const metric = metrics[`cap_window_${name}`];
    if (!metric) {
      return { value: null, divergent: false, missing: true };
    }
    const values = metric.values || metric;
    const hasMinMax = typeof values.min === 'number' && typeof values.max === 'number';
    return {
      value: typeof values.value === 'number' ? values.value : null,
      divergent: hasMinMax && values.min !== values.max,
      missing: false,
    };
  };
  const gStart = gauge('scenario_start_ms');
  const gWinStart = gauge('measure_start_ms');
  const gWinEnd = gauge('measure_end_ms');
  const gClock = gauge('clock_ok');
  const start = gWinStart.value;
  const end = gWinEnd.value !== null && gWinEnd.value >= 0 ? gWinEnd.value : null;
  const divergent = gStart.divergent || gWinStart.divergent
    || gWinEnd.divergent || gClock.divergent;
  return {
    contract: 'cap-scenario-window-v1',
    scenario_start_ms: gStart.value,
    window_start_ms: start,
    window_end_ms: end,
    window_seconds: start !== null && end !== null && end > start
      ? Math.round((end - start) / 10) / 100 : null,
    duration_ms: gauge('duration_ms').value,
    measure_offset_ms: gauge('measure_offset_ms').value,
    warmup_ms: constants.warmupMs,
    cap_measure_start_ms: constants.measureStartMs,
    bucket_ms: gauge('bucket_ms').value,
    bucket_count: gauge('bucket_count').value,
    scenario_clock_ok: gClock.value,
    divergent_vus: divergent,
  };
}
