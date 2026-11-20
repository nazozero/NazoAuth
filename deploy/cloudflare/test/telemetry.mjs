import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summarizeWorkerLogs } from '../summarize-worker-logs.mjs';

test('CPU samples above 10 ms remain separate from platform rejection', () => {
  const summary = summarizeWorkerLogs([
    { request_id: 'a', event_type: 'fetch', cpu_ms: 12, outcome: 'ok', status: 200 },
    { request_id: 'b', event_type: 'fetch', cpu_ms: 9, outcome: 'ok', status: 200 },
    { request_id: 'c', event_type: 'fetch', cpu_ms: 31, outcome: 'exceededCpu', status: 500 },
    { request_id: 'd', event_type: 'fetch', cpu_ms: 8, outcome: 'exceededMemory', status: 500 },
  ], { clientResult: { http: { requests: 4, cloudflare_1102: 2 } } });
  assert.equal(summary.cpu_ms.over_10_ms, 2);
  assert.equal(summary.exceeded_cpu, 1);
  assert.equal(summary.exceeded_memory, 1);
  assert.equal(summary.client_http_1102, 2);
  assert.equal(summary.coverage.complete_count, true);
  assert.equal(summary.cpu_ms.p95, 31);
  assert.equal(summary.cpu_ms.median, 10.5);
});

test('missing or duplicate telemetry does not become a zero-CPU success claim', () => {
  const summary = summarizeWorkerLogs({ result: { events: { events: [
    { timestamp: 1000, $metadata: { requestId: 'a', type: 'console' }, $workers: { outcome: 'ok', eventType: 'fetch' } },
    { timestamp: 1001, $metadata: { requestId: 'a', type: 'cf-worker-event' }, $workers: {
      cpuTimeMs: 14, wallTimeMs: 300, outcome: 'ok', eventType: 'fetch',
    } },
    { timestamp: 1002, $metadata: { requestId: 'b', type: 'cf-worker-event' }, $workers: { outcome: 'ok', eventType: 'fetch' } },
  ] } } }, { clientResult: { http: { requests: 3, cloudflare_1102: 0 } } });
  assert.equal(summary.invocations, 2);
  assert.equal(summary.cpu_ms.samples, 1);
  assert.equal(summary.cpu_ms.missing_samples, 1);
  assert.equal(summary.coverage.complete_count, false);
  const empty = summarizeWorkerLogs([]);
  assert.equal(empty.cpu_ms.max, null);
  assert.equal(empty.client_http_1102, null);
  assert.equal(empty.coverage.cpu_samples_present, false);
});

test('run and version filters exclude background invocations', () => {
  const summary = summarizeWorkerLogs([
    { run_id: 'wanted', version: 'current', cpu_ms: 2, outcome: 'ok' },
    { run_id: 'wanted', version: 'old', cpu_ms: 80, outcome: 'exceededCpu' },
    { run_id: 'scanner', version: 'current', cpu_ms: 70, outcome: 'exceededCpu' },
  ], { runId: 'wanted', version: 'current' });
  assert.equal(summary.invocations, 1);
  assert.equal(summary.cpu_ms.max, 2);
  assert.equal(summary.exceeded_cpu, 0);
});
