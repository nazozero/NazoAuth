# NazoAuth Performance Benchmarks — Current Baseline

Date: 2026-09-28 (Beijing). The current baseline is PR #222's current B on the
new isolated test deployment. Both CPU modes use one application instance.
The [capacity table](performance-capacity-curve.md) and
[machine-readable authority](../../perf/results/data/capacity/current-capacity.json)
record all ten requested scenarios, including cold Argon2 as a separate class.
The [run report](reports/2026-09-28-current-b/report.md) contains methods,
provenance, maintenance, audit, WAL, bottleneck evidence and CI repair results.

These are short-window observations: initial exploration 90 seconds, later
exploration 60 seconds, candidates 180 seconds and mixed maintenance 660 seconds.
They do not establish production long-term capacity. A missing failure point is
a capacity lower bound, never a maximum; a peak at a failed point is not an
accepted capacity. Individual complete-operation quantiles are never averaged.

## Tested identity and effective deployment

- Application source: `ac266e7a93749694022efd1aeea6ed4d316fbbcc`.
- Application image: `sha256:5f62a3a2247e609d72ee03de1bc0d330873d5742b1f94cd5ec144baa69f2f71d`.
- Running binary: `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b`.
- Migration chain: `812aa6dc33897e769a6ee6d7481aa5bed8b216097d38ce0ca81a3268e4832920`.
- Current endpoint runner image: `sha256:64b272744b87acc391c9a628ed37aa070d8517471527e6b2adc5066ae61664ef` (dd69c9e2).
- Process-visible 64 logical CPUs / own quota 64 / own memory limit 128 GiB.
  Dynamically allocated application 1 or 16, PostgreSQL 16, Valkey 1,
  disjoint load/auxiliary CPU set 31; each point verifies affinity.
- PostgreSQL 18.6, pool 32, fsync/synchronous_commit/full_page_writes enabled,
  max WAL 8 GB, normal five-minute checkpoints and autovacuum. Password hashes,
  Argon2 concurrency, audit and protocol requirements remain unchanged.
- Main VUs/users 64 or 256; ordinary vectors 48,000 and FAPI 49,200. Mixed
  includes every sidecar category with the fixed resource-scaled recipes in
  the report; sidecars are separate operation populations.

Production source did not change after the application build. Later commits
change CI/tests, measurement tools, scheduling and publication. Per-point source,
image, binary, tool identities and effective settings are retained in the
[compact snapshots](../../perf/results/diagnostics/2026-09-28-current-b-selected.json).
The final delivered documentation/source commit and its exact CI checks are
recorded in the delivery checkpoint on [PR #222](https://github.com/nazozero/NazoAuth/pull/222).

## Priority paths

| Scenario | App CPUs | Highest PASS L / first valid FAIL U | Actual success ops/s at L | Complete P95/P99 ms | Effective window s |
|---|---:|---|---:|---|---:|
| `cap_mixed` | 1 | 600 / 700 | 600 | 45/103 | 660 |
| `cap_client_credentials` | 1 | 1600 / 2000 | 1598.494 | 12/25 | 180 |
| `cap_authorization_code` | 1 | 320 / 400 | 320 | 24/35 | 180 |
| `cap_refresh_token` | 1 | 800 / 1000 | 799.989 | 14/42 | 180 |
| `cap_mixed` | 16 | 2000 / 2400 | 2000.002 | 18/24 | 660 |
| `cap_client_credentials` | 16 | 6000 / 7000 | 5999.35 | 15/26 | 180 |
| `cap_authorization_code` | 16 | 960 / 1120 | 960 | 32/45 | 180 |
| `cap_refresh_token` | 16 | 3200 / 4000 | 3200.006 | 16/26 | 180 |

All scene failures, drops, rejections, unfinished operations and HTTP request
rates are in the full capacity table and structured results. Standard acceptance
requires successful complete operations >=99.5% of offered load, drops <=0.1%,
zero unexpected errors, complete-operation P95/P99 <=100/250 ms and intact
runtime/durable-audit evidence. Cold login retains its separate existing gate.

## Maintenance, audit and WAL

The report separates the mixed 660-second effective windows from their
300-second mature maintenance spans after the declared 360-second retention
horizon. It records expired-age/backlog samples and same-span insert/delete
counters, post-drain audit persistence/loss, journal continuity and original
confirmation-journal hashes. A sampled maintenance pass is scoped to that window.

WAL generation (`pg_stat_wal`) and WAL write bytes/writes/fsyncs (`pg_stat_io`)
are reported separately. Mixed bytes per main successful operation include all
sidecars, audit and background work. They are not per-SQL intrinsic costs or
physical-device write amplification. WAL timing is N/A because its timing GUC
was off. No unsupported SQL or hardware bottleneck attribution is made.

## CI and evidence boundaries

The starting compatibility-contract failure was repaired before performance
exploration finished. Dynamic resource-budgeted compilation, reuse of the
all-features build variant and cleanup between isolated audit fixtures preserve
protocol, security, migration, persistence and concurrency assertions. Shared
state tests remain serial. Representative successful Rust jobs were 30m29s and
30m59s before, and 29m54s / 25m16s at repaired checkpoints; runner/cache differences
prevent attributing the whole difference to one change. See the report's step
and fixture breakdown, retained coverage and remaining serial-test costs.

Final checks must match the delivered commit. Older successful checkpoints and
cancelled duplicate runs do not substitute for that validation. See the
[PR checks](https://github.com/nazozero/NazoAuth/pull/222/checks) and final delivery
checkpoint for exact run links and outcomes.

Large streams/logs/journals remain in an external evidence archive; compact
results and hashes are retained in Git. Earlier short-point receiver journals
were not saved as files; their runtime range/hash/anchor proofs were retained.
The test receiver is not a deployment-level WORM attestation, and external mTLS
terminator handshake capacity is outside the trusted-proxy workload boundary.

## Historical evidence

Previous [September 22/23 capacity and long-run evidence](reports/2026-09-22-current-capacity/report.md)
and [refresh-storage experiments](reports/2026-09-22-refresh-storage-redesign/report.md)
remain historical. The previous entry is preserved at
[its original commit](https://github.com/nazozero/NazoAuth/blob/dca30911651611c2f4fb2485ad90b21fad21e37d/docs/performance/performance-benchmarks.md).
Different deployment, windows and operation-latency contracts are reference
context; no improvement percentage is calculated and historical long tests do
not certify this run's long-term capacity.
