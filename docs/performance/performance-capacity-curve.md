# NazoAuth Current Capacity Baseline

Canonical capacity record for the current release. Every number below was
measured against `TEST_SOURCE_SHA` on a clean checkout; the full provenance
chain (git → image → binary → migration set → canonical schema) lives in
[reports/2026-09-22-current-capacity/manifest.md](reports/2026-09-22-current-capacity/manifest.md).

- `TEST_SOURCE_SHA`: `fd52b556370fa8d72ecfef35947bae8241e722e6`
- Run date: 2026-09-22/23 UTC
- Host: AMD EPYC 9K65, 64C/128G container host, kernel 5.4.241
- Topology: 1× nazoauth, 1× PostgreSQL 18 (`postgres:18-alpine`,
  `max_wal_size=8GB`, `fsync=on`, `synchronous_commit=on`,
  `checkpoint_timeout=5min`, `checkpoint_completion_target=0.9`,
  `shared_buffers=128MB`), 1× Valkey 8 (`valkey:8-alpine`, `maxmemory=0`,
  `noeviction`)
- Method: adaptive 10-minute constant-arrival-rate points
  (`perf/tools/capacity_search.py`). `PASS` = drops ≤0.1%, measured rate
  ≥99.5% of target, zero unexpected errors, p95 ≤100ms, p99 ≤250ms.
- Structured results: `perf/results/data/capacity/current-capacity.json`.

## Current capacity matrix (10-minute points)

| Scenario | Highest validated 10m | First fail above | measured ops/s | HTTP rps | p95 ms | p99 ms | drops |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cap_mixed` (full sidecars) | 2000 | 2500 | 1998.3 | 2862 | 10.3 | 16.2 | 0.011% |
| `cap_client_credentials` | 3200 | 3400 | 3198.4 | 3198 | 7.3 | 15.2 | 0.05% |
| `cap_authorization_code` | 1125 | 1250 | 1125 | 4499 | 12.2 | 17.4 | 0.012% |
| `cap_refresh_token` | 1440 | 1600 | 1441.7 | 1442 | 9.7 | 14.0 | 0% |
| `fapi2_logged_in_high_security` | 731 | 913 | 731 | 3655 | 11.0 | 17.3 | 0.007% |
| `cap_introspect` | 7812 | 8788 | 7815.1 | 7815 | 1.0 | 1.3 | 0.028% |
| `cap_revoke` | 787 | 875 | 787 | 3935 | 8.5 | 12.4 | 0% |
| `mtls_client_credentials` | 3515 | 3906 | 3515.0 | 3515 | 7.4 | 14.4 | 0% |
| `par_signed_request_object` | >=6102 | not found within ladder | 6102 | 6102 | 1.2 | 8.5 | 0% |

`cap_mixed` carries sidecars on every point: refresh 600/s, argon2 8/s,
metadata 200/s, FAPI 30/s, audit exporter + durable receiver. Its 2500
point attained 2486.7 ops/s (99.47% of target) — a borderline miss against
the 99.5% gate.

`par_signed_request_object` reached the 6-point ladder cap still passing;
no failing point was established, so the entry records `>=6102/s`, not a
maximum.

## Argon2 (`oidc_cold_login_refresh`, separate class)

Argon2 concurrency stays at 8 (not raised for a better number).

| VU | attempted login/s | successful login/s | login 503 | login p50/p95/p99 ms |
|---:|---:|---:|---:|---|
| 8 | 55.1 | 55.1 | 0 | 121.0 / 127.6 / 138.0 |
| 16 | 93.3 | 56.6 | 22,016 (`temporarily_unavailable`) | 156.1 / 255.8 / 269.8 |

At 16 VU the concurrency-8 Argon2 slot limit is the active backpressure:
39.3% of login attempts return `503 temporarily_unavailable`; all other
steps clean. This is the designed protective rejection, reported as
measured.

## Mixed sustained (30 minutes, fresh DB, all sidecars)

| Target | Measured | Attainment | Drops | p95 / p99 ms | Gate |
|---:|---:|---:|---:|---|---|
| 2000 ops/s | 1967.4 ops/s | 98.4% | 0.158% | 11.9 / 37.9 | **FAIL** |
| 1900 ops/s | 1889.1 ops/s | 99.43% | 0.091% | 11.2 / 19.2 | **FAIL** |

`STRICT_30M_CAPACITY_NOT_ESTABLISHED` — both fresh-DB runs missed only the
≥99.5% arrival-fidelity gate via periodic checkpoint-flush dips; the
measured deliveries are reported as observations, not validated capacity.
The 1900–2000 interval was not searched, so no exact maximum is claimed.
Full evidence:
[reports/2026-09-22-current-capacity/report.md](reports/2026-09-22-current-capacity/report.md).
