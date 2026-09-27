# NazoAuth Current-B Capacity Baseline

Run date: 2026-09-28 Beijing time. This is the only current capacity table.
All rates are complete logical operations per second. The application has one
instance in both modes; only its allowed logical CPU count changes. The load
producer/observers, PostgreSQL and Valkey occupy disjoint CPU sets in this visible
container. These are observations for the registered workload, VUs, data and
short windows, not intrinsic hardware maxima or production long-term capacity.

Candidates use 180-second effective windows; mixed maintenance confirmations use
660 seconds. Exploration used 90 seconds initially and 60 seconds later. Each
row retains its actual window. A valid FAIL above a PASS establishes only the
observed interval between those two loads; no FAIL means **at least L**, not a
maximum. Cold Argon2 login is a separate class with its existing gate.

Structured authority: [current-capacity.json](../../perf/results/data/capacity/current-capacity.json).
Method, provenance, maintenance, WAL, audit and CI: [run report](reports/2026-09-28-current-b/report.md).
Compact selected evidence: [point snapshots](../../perf/results/diagnostics/2026-09-28-current-b-selected.json).

## Single logical CPU

| Scenario | App CPUs | Highest PASS L | First valid FAIL U | Success ops/s | HTTP req/s | P50/P95/P99 ms | Unexpected / drops / rejects / unfinished | Window s | Conclusion |
|---|---:|---:|---:|---:|---:|---|---|---:|---|
| `cap_mixed` | 1 | 600 | 700 | 600 | 869.944 | 4/45/103 | 0/0/0/0 | 660 | [600, 700) observed |
| `cap_client_credentials` | 1 | 1600 | 2000 | 1598.494 | 1598.436 | 4/12/25 | 0/271/0/0 | 180 | [1600, 2000) observed |
| `cap_authorization_code` | 1 | 320 | 400 | 320 | 1280.006 | 15/24/35 | 0/0/0/0 | 180 | [320, 400) observed |
| `cap_refresh_token` | 1 | 800 | 1000 | 799.989 | 800 | 7/14/42 | 0/2/0/0 | 180 | [800, 1000) observed |
| `fapi2_logged_in_high_security` | 1 | 20 | not established | 20 | 100 | 22/31/43.01 | 0/0/0/0 | 180 | at least 20/s; no valid U |
| `cap_introspect` | 1 | 500 | not established | 500 | 500 | 1/3/11 | 0/0/0/0 | 180 | at least 500/s; no valid U |
| `cap_revoke` | 1 | 60 | not established | 60 | 300 | 16/24/38 | 0/0/0/0 | 180 | at least 60/s; no valid U |
| `mtls_client_credentials` | 1 | 250 | not established | 250 | 250 | 4/6/12 | 0/0/0/0 | 180 | at least 250/s; no valid U |
| `par_signed_request_object` | 1 | 150 | not established | 150 | 150 | 3/5/11 | 0/0/0/0 | 180 | at least 150/s; no valid U |

## Sixteen logical CPUs

| Scenario | App CPUs | Highest PASS L | First valid FAIL U | Success ops/s | HTTP req/s | P50/P95/P99 ms | Unexpected / drops / rejects / unfinished | Window s | Conclusion |
|---|---:|---:|---:|---:|---:|---|---|---:|---|
| `cap_mixed` | 16 | 2000 | 2400 | 2000.002 | 2897.598 | 4/18/24 | 0/0/0/0 | 660 | [2000, 2400) observed |
| `cap_client_credentials` | 16 | 6000 | 7000 | 5999.35 | 5999.335 | 4/15/26 | 0/117/0/0 | 180 | [6000, 7000) observed |
| `cap_authorization_code` | 16 | 960 | 1120 | 960 | 3840.056 | 15/32/45 | 0/0/0/0 | 180 | [960, 1120) observed |
| `cap_refresh_token` | 16 | 3200 | 4000 | 3200.006 | 3200.017 | 7/16/26 | 0/0/0/0 | 180 | [3200, 4000) observed |
| `fapi2_logged_in_high_security` | 16 | 320 | not established | 320 | 1600.017 | 24/32/42 | 0/0/0/0 | 180 | at least 320/s; no valid U |
| `cap_introspect` | 16 | 4000 | not established | 4000.011 | 4000.011 | 1/2/3 | 0/0/0/0 | 180 | at least 4000/s; no valid U |
| `cap_revoke` | 16 | 480 | not established | 480 | 2400.034 | 18/33/42 | 0/0/0/0 | 180 | at least 480/s; no valid U |
| `mtls_client_credentials` | 16 | 4000 | not established | 3998.417 | 3998.553 | 4/9/20 | 0/285/0/0 | 180 | at least 4000/s; no valid U |
| `par_signed_request_object` | 16 | 2400 | not established | 2400 | 2399.989 | 3/4/5 | 0/0/0/0 | 180 | at least 2400/s; no valid U |

## Cold Argon2 login — separate class

Each operation includes a new password verification and the complete six-request flow. The existing cold-login protocol/check and five-second HTTP guards apply alongside strict success/drop/error and runtime/audit accounting. Its complete-operation P50/P95/P99 is diagnostic; the ordinary 100/250 ms gate is not applied. Stored seeded hashes remain `m=65536,t=3,p=4`, admission concurrency 8 and queue deadline 100 ms.

| Scenario | App CPUs | Highest PASS L | First valid FAIL U | Success ops/s | HTTP req/s | P50/P95/P99 ms | Unexpected / drops / rejects / unfinished | Window s | Conclusion |
|---|---:|---:|---:|---:|---:|---|---|---:|---|
| `oidc_cold_login_refresh` (single) | 1 | 1 | not established | 1 | 6 | 132/142/153.21 | 0/0/0/0 | 180 | at least 1/s; no valid U |
| `oidc_cold_login_refresh` (multi) | 16 | 16 | not established | 16 | 96.011 | 153/172/184.61 | 0/0/0/0 | 90 | at least 16/s; no valid U; only short probe, 180 s unverified |

## Upper points and failures

| Mode / scenario | U ops/s | Successful ops/s | P95/P99 ms | Drops / unexpected | Window s | Failure |
|---|---:|---:|---|---|---:|---|
| single / `cap_mixed` | 700 | 699 | 94/178 | 90/0 | 90 | drops above 0.1% |
| single / `cap_client_credentials` | 2000 | 1944.083 | 36/43 | 3355/0 | 60 | success below 99.5% offered; drops above 0.1% |
| single / `cap_authorization_code` | 400 | 399.55 | 34/57 | 81/0 | 180 | drops above 0.1% |
| single / `cap_refresh_token` | 1000 | 941.9 | 77/83 | 3486/0 | 60 | success below 99.5% offered; drops above 0.1% |
| multi / `cap_mixed` | 2400 | 2387.817 | 47/142 | 731/0 | 60 | success below 99.5% offered; drops above 0.1% |
| multi / `cap_client_credentials` | 7000 | 6975.983 | 22/33 | 1441/0 | 60 | drops above 0.1% |
| multi / `cap_authorization_code` | 1120 | 1120 | 114/132 | 0/0 | 60 | complete-operation P95 above 100 ms |
| multi / `cap_refresh_token` | 4000 | 3939.667 | 68/81 | 3620/0 | 60 | success below 99.5% offered; drops above 0.1% |

Earlier release measurements remain [historical](reports/2026-09-22-current-capacity/report.md).
The previous current entry is preserved at [its original commit](https://github.com/nazozero/NazoAuth/blob/dca30911651611c2f4fb2485ad90b21fad21e37d/docs/performance/performance-capacity-curve.md).
Different resources, durations and operation-latency contracts prevent a defensible
old/new improvement percentage. Historical 30-minute/three-hour evidence does
not turn this run's short tests into long-term acceptance.
