# NazoAuth Performance Benchmarks — Current Baseline

The current B baseline is the reviewed 2026-09-28 incremental evidence for [PR #222](https://github.com/nazozero/NazoAuth/pull/222). Full acceptance is **INCOMPLETE**: 13/20 mode/scenario rows have a reviewed service upper; remaining rows publish real lower bounds. The [complete capacity table](performance-capacity-curve.md), [structured authority](../../perf/results/data/capacity/current-capacity.json) and [report](reports/2026-09-28-incremental-b/report.md) are the unique current source. Original-container rows are explicitly distinguished from replacement-container rows; one interval never mixes their data or different configurations.

Application source `ac266e7a93749694022efd1aeea6ed4d316fbbcc` and binary `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b` are unchanged. Both CPU modes use one application instance, constrained to one or sixteen actual logical CPUs. The visible 64-CPU/128-GiB deployments allocate separate CPU sets for application, PostgreSQL, Valkey and generators. Effective pool, VU, user, observer, image and tool identities are frozen per row in the structured recipes. Production hash strength, audit, protocol checks, source-IP admission and PostgreSQL durability remain unchanged.

| Scenario | App CPUs | PASS L / service FAIL U | Success ops/s | Full P95/P99 ms | Window L/U s |
|---|---:|---|---:|---|---|
| `cap_mixed` | 1 | 600 / 650 | 600 | 45/103 | 660/180 |
| `cap_client_credentials` | 1 | 1375 / 1500 | 1375.006 | 24/46 | 180/180 |
| `cap_authorization_code` | 1 | 325 / 350 | 325 | 50/158 | 180/180 |
| `cap_refresh_token` | 1 | 750 / 812 | 749.994 | 34/74 | 180/180 |
| `cap_mixed` | 16 | 2349 / 2900 | 2349 | 20/29 | 660/660 |
| `cap_client_credentials` | 16 | 6000 / 6500 | 6000.022 | 11/29 | 180/180 |
| `cap_authorization_code` | 16 | 900 / 1000 | 900 | 92/109 | 180/180 |
| `cap_refresh_token` | 16 | 2624 / 2916 | 2624.006 | 13/26 | 180/180 |


Full-operation P50/P95/P99, HTTP req/s, successful operation counts, errors, drops, refusals, unfinished operations, per-sidecar gates and upper failure reasons are retained in the complete table and report. Quantiles are individual operation cohorts, never averaged or replaced by HTTP timings. A measured invalid point or generator-only failure cannot establish a service upper. Windows below 180 seconds are exploration awaiting confirmation; the two passing mixed confirmations use 660 seconds and mature maintenance/audit evidence. None of these short observations proves production long-term capacity.

New multi mixed passes at 2349/s with all four sidecars and a complete locally verified journal. Its 2900/s upper independently fails the FAPI latency gate; the closer drop-only 2610/s attempt is excluded, so refinement remains outstanding. New client credentials [6000,6500) follows a one-factor VU control that removes the former delivery-limited failure. WAL generation and actual WAL write bytes/counts/fsyncs are distinct and include sidecars/background work when divided by main operations. The report preserves the precise bottleneck evidence and its limits.

The report records transport/gate repairs, representative CI costs and remaining serial audit cost. Final exact-head CI is linked from the PR delivery checkpoint. [Original short observations](reports/2026-09-28-current-b/report.md) and earlier long steady-state reports remain historical; no cross-machine/configuration improvement percentage is computed.
