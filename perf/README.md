# NazoAuth Performance Benchmarks

This directory contains reproducible Docker Compose based load benchmarks for
NazoAuth. It is separate from correctness, conformance, and browser UI tests.

## Run

Run the full matrix:

```sh
make perf
```

Equivalent direct command:

```sh
docker compose -f docker-compose.perf.yml up --build --abort-on-container-exit --exit-code-from perf
```

Run one profile:

```sh
PERF_PROFILE=oidc-mixed make perf
```

Run one scenario:

```sh
PERF_SCENARIO=token_client_credentials PERF_DURATION=30s PERF_VUS=16 make perf
```

Run a short capacity-curve smoke test:

```sh
make perf-capacity-smoke
```

Run the long fixed-arrival-rate capacity curve:

```sh
make perf-capacity
```

The long capacity curve runs 30 minutes per point across 1, 2, and 4 NazoAuth
replicas. It is intended for dedicated benchmark machines, not routine local
verification.

Results are written to `perf/results/*.summary.json` and
`perf/results/*.k6.json`. Markdown reports are written to
`docs/performance-benchmarks.md` and `docs/performance-capacity-curve.md`.

## Load Model

The default model is intentionally closer to production traffic than a shared
happy-path session:

- Multi-user profiles seed a real user pool through `PERF_USER_COUNT`. Each k6
  VU is bound to one user account for the duration of the scenario, with its own
  login session, authorization request, code, refresh token, and DPoP proofs.
- If `PERF_USER_COUNT` is lower than the configured concurrency, the runner
  raises it so the default multi-user case does not collapse into accidental
  account sharing.
- Same-user contention is a separate profile. It deliberately sends concurrent
  flows through one account to expose session, CSRF, refresh rotation, and
  account-level locking behavior under stress.
- `PERF_FLOW_VUS` defaults to `PERF_VUS`. It is only an explicit override for
  long authorization-code style flows, not a hidden reduction in concurrency.

The compose stack also starts a local runtime keyset service before NazoAuth so
FAPI paths can issue the required RS256 and PS256 server-side tokens.

## Profiles

| Profile | Scenarios | Purpose |
| --- | --- | --- |
| `single-endpoint` | `token_client_credentials`, `mtls_client_credentials`, `par_signed_request_object` | Isolates endpoint throughput and authentication overhead. |
| `oidc-mixed` | `refresh_token_rotation`, `introspect_opaque_refresh_token`, `authorize_par_session` | Exercises normal OIDC login, PAR, authorization-code exchange, refresh rotation, and opaque refresh-token introspection across many users. |
| `oidc-same-user-contention` | `same_user_refresh_token_rotation`, `same_user_introspect_opaque_refresh_token`, `same_user_authorize_par_session` | Exercises concurrent operations from one account to reveal account/session contention risks. |
| `fapi2-high-security` | `fapi2_par_jar_private_key_jwt_dpop` | Exercises PAR + signed JAR + `private_key_jwt` + DPoP-bound authorization-code and refresh paths. |
| `capacity` | `token_only_client_credentials`, `oidc_cold_login_refresh`, `oidc_logged_in_authorization_code`, `oidc_refresh_only`, `fapi2_full_security` | Fixed-arrival-rate scenarios used by `perf/capacity.py` to build 1/2/4 replica capacity curves. |

## Capacity Curve Model

`perf/capacity.py` runs one fixed-arrival-rate point at a time, tears down the
compose stack, and repeats for each selected replica count, scenario, and rate.
The default long matrix covers:

- `token_only_client_credentials`: token-only machine-to-machine traffic.
- `oidc_cold_login_refresh`: PAR, password login, authorization decision,
  authorization-code token exchange, and refresh rotation.
- `oidc_logged_in_authorization_code`: one session warm-up per VU, then
  logged-in PAR, authorization decision, and authorization-code exchange.
- `oidc_refresh_only`: one bootstrap flow per VU, then refresh-token rotation.
- `fapi2_full_security`: PAR + signed JAR + `private_key_jwt` + DPoP-bound
  authorization-code and refresh paths.

The report normalizes observed throughput by NazoAuth service CPU usage:
`100%` Docker CPU is treated as one effective CPU core. This avoids claiming
capacity only from raw RPS when the service is consuming many cores.

## Metrics

Each scenario writes:

- k6 HTTP request count, RPS, error rate, p50/p95/p99 latency
- Docker CPU and memory samples for NazoAuth, PostgreSQL, and Valkey
- PostgreSQL `pg_stat_statements` calls, mean statement latency, and
  statements per HTTP request
- NazoAuth DB pool acquire count and wait time from the perf-only
  `/__perf/metrics` endpoint
- Valkey command, hit, miss, expiry, and key-count deltas

The perf-only metrics endpoint is registered only when
`PERF_METRICS_ENABLED=true` is present in the server process environment.

## Notes

The compose file uses disposable perf volumes. It enables
`pg_stat_statements` for database latency and per-request query accounting.
The server profile remains `oauth2-baseline` so ordinary OIDC and FAPI-style
client-level hardening can be measured in one reproducible environment. The
FAPI scenario uses client-level PAR request-object enforcement,
`private_key_jwt`, signed JAR, and DPoP-bound tokens. The mTLS endpoint scenario
uses trusted forwarded certificate thumbprint headers on the isolated perf
network.
