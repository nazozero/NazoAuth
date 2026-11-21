import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

function eventsFrom(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.result?.events?.events)) return payload.result.events.events;
  if (Array.isArray(payload?.events?.events)) return payload.events.events;
  throw new Error('Expected normalized invocation records or a Cloudflare telemetry events response');
}

function normalize(event) {
  const worker = event.$workers;
  if (!worker) return { ...event, path: event.path?.split('?')[0] };
  return {
    timestamp: event.timestamp,
    request_id: event.$metadata?.requestId || worker.requestId || event.$metadata?.id,
    path: worker.event?.path?.split('?')[0] || (worker.event?.request?.url ? new URL(worker.event.request.url).pathname : undefined),
    cpu_ms: worker.cpuTimeMs,
    wall_ms: worker.wallTimeMs,
    outcome: worker.outcome,
    status: worker.event?.response?.status,
    version: worker.scriptVersion?.id,
    event_type: worker.eventType,
    run_id: worker.event?.request?.headers?.['x-nazo-acceptance'],
    phase: worker.event?.request?.headers?.['x-nazo-acceptance-phase'],
    invocation: event.$metadata?.type === 'cf-worker-event',
  };
}

function distribution(values) {
  const sorted = values.filter(value => Number.isFinite(value) && value >= 0).sort((a, b) => a - b);
  if (!sorted.length) return { samples: 0, min: null, median: null, p90: null, p95: null, p99: null, max: null, mean: null };
  const percentile = p => sorted[Math.ceil(sorted.length * p) - 1];
  const median = (sorted[Math.floor((sorted.length - 1) / 2)] + sorted[Math.ceil((sorted.length - 1) / 2)]) / 2;
  return {
    samples: sorted.length,
    min: sorted[0], median, p90: percentile(0.9), p95: percentile(0.95), p99: percentile(0.99),
    max: sorted.at(-1), mean: +(sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(3),
  };
}

function countBy(events, key) {
  const counts = {};
  for (const event of events) {
    const value = String(event[key] ?? 'unknown');
    counts[value] = (counts[value] || 0) + 1;
  }
  return counts;
}

function summarize(events) {
  const cpu = distribution(events.map(event => event.cpu_ms));
  const wall = distribution(events.map(event => event.wall_ms));
  const over10 = events.filter(event => event.cpu_ms > 10).length;
  return {
    invocations: events.length,
    cpu_ms: { ...cpu, missing_samples: events.length - cpu.samples, over_10_ms: over10,
      over_10_ms_percent: cpu.samples ? +(over10 * 100 / cpu.samples).toFixed(3) : null },
    wall_ms: wall,
    outcome_counts: countBy(events, 'outcome'), status_counts: countBy(events, 'status'),
    exceeded_cpu: events.filter(event => event.outcome === 'exceededCpu').length,
    exceeded_memory: events.filter(event => event.outcome === 'exceededMemory').length,
  };
}

export function summarizeWorkerLogs(payload, { runId, version, clientResult } = {}) {
  const events = eventsFrom(payload).map(normalize).filter(event =>
    (!runId || event.run_id === runId) && (!version || event.version === version));
  const unique = new Map();
  for (const [index, event] of events.entries()) {
    const key = event.request_id ? `${event.version}:${event.event_type}:${event.request_id}` : `unkeyed:${index}`;
    const previous = unique.get(key);
    // Console messages and the invocation event can share a request ID. Prefer
    // the invocation record, which includes actual platform CPU accounting.
    if (!previous || event.invocation || (!Number.isFinite(previous.cpu_ms) && Number.isFinite(event.cpu_ms))) {
      unique.set(key, event);
    }
  }
  const invocations = [...unique.values()];
  const byPath = new Map();
  const byPhase = new Map();
  for (const event of invocations) {
    const key = `${event.event_type || 'unknown'} ${event.path || '(no HTTP path)'}`;
    if (!byPath.has(key)) byPath.set(key, []);
    byPath.get(key).push(event);
    const phase = event.phase || 'unmarked';
    if (!byPhase.has(phase)) byPhase.set(phase, []);
    byPhase.get(phase).push(event);
  }
  const timestamps = invocations.map(event => event.timestamp).filter(Number.isFinite);
  const summary = summarize(invocations);
  const expected = clientResult?.http?.requests ?? null;
  const fetched = invocations.filter(event => event.event_type === 'fetch').length;
  return {
    source: 'Cloudflare invocation telemetry', filters: { run_id: runId ?? null, version: version ?? null },
    percentile_method: 'nearest rank for p90/p95/p99; median averages the two middle samples when even',
    received_records: events.length, deduplicated_records: invocations.length,
    versions: [...new Set(invocations.map(event => event.version).filter(Boolean))],
    first_event: timestamps.length ? new Date(Math.min(...timestamps)).toISOString() : null,
    last_event: timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null,
    ...summary,
    coverage: { client_requests: expected, logged_fetch_invocations: fetched,
      complete_count: expected === null ? null : fetched === expected,
      cpu_samples_present: summary.cpu_ms.samples > 0 },
    client_http_1102: clientResult?.http?.cloudflare_1102 ?? null,
    by_phase: Object.fromEntries([...byPhase].map(([key, values]) => [key, summarize(values)])),
    by_path: Object.fromEntries([...byPath].sort(([a], [b]) => a.localeCompare(b)).map(([key, values]) => [key, summarize(values)])),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [eventsPath, resultPath] = process.argv.slice(2);
  if (!eventsPath) throw new Error('Usage: node summarize-worker-logs.mjs INVOCATIONS.json [ACCEPTANCE-RESULT.json]');
  const [events, clientResult] = await Promise.all([
    readFile(eventsPath, 'utf8').then(JSON.parse),
    resultPath ? readFile(resultPath, 'utf8').then(JSON.parse) : undefined,
  ]);
  console.log(JSON.stringify(summarizeWorkerLogs(events, {
    runId: process.env.NAZO_WORKER_ACCEPTANCE_RUN_ID,
    version: process.env.NAZO_WORKER_ACCEPTANCE_VERSION,
    clientResult,
  }), null, 2));
}
