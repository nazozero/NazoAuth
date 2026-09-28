# NazoAuth Performance Benchmarks

This directory contains reproducible Docker Compose based load benchmarks for
NazoAuth. It is separate from correctness, conformance, and browser UI tests.

The runner image pins `orjson==3.12.0` for the streaming evidence decoder.
One-worker checkpoint evidence uses k6's buffered `--quiet --out json=-`
output redirected to the analyzer FIFO. The script writes summaries only
to files; the runner closes its producer lifetime pipe before sampler
shutdown and waiting for the analyzer. This
retains all metric points and flushes the final buffered batch without a
relaxed lag gate.

The runner builds exact k6 v2.2.0 source `00a9a1b7f552d6bb4337278b10ae25aac0f4e666`
from a checksum-verified archive. Its [small JSON output patch](runner/k6-json-throughput.patch)
reuses bounded encodings of immutable tag sets and writes the same complete
sample envelope without repeated reflection. Every metric, timestamp, value,
tag and metadata field is retained; metadata and invalid-value cases use the
stock encoder. Upstream output/metrics tests and added envelope equivalence,
invalid-value and bounded-cache tests run during the image build. Per-point
provenance records the resulting k6 binary hash and runner image.
Install that same binary package when invoking its Python tools on the host:
`python -m pip install --only-binary=:all: orjson==3.12.0`.
Streaming evidence retains the existing cohort, diagnostic-selection and
five-second consumer-lag rules; forensic gzip output uses compression level 1.

For a measured stream-consumer bottleneck, the targeted controller accepts
`--stream-workers 2` through `8` (default `1`). It registers this setting as
part of the recipe and requires enough allocated generator CPUs for the workers
and dispatcher. The application image does not need rebuilding for this change.
Every Point is still decoded and validated; metric sharding preserves exact
cohorts, counts, outcomes, drops and histogram buckets. Native k6 complete-flow
quantiles remain one population. Window contracts reach every shard; missing,
divergent, malformed, failed or late evidence retains its existing invalid gate.
Analyzer stats record each worker's owned-point count and the unchanged
five-second consumer-lag signal.

With multiple workers, the JSON output patch writes every sample directly
to its metric owner's buffered FIFO (`K6_JSON_PARTITIONS=2..8` and
`--out json=<prefix>`). All partitions flush on every existing 200ms output
tick, including quiet ticks, and close after the final flush. Window samples
reach every worker. Each worker decodes and verifies the complete owned JSON
envelope in input order; ownership errors invalidate the stream. The parent
waits for producer EOF before the bounded final drain. This avoids dispatcher
copies and scanning unowned rows. Offline stdin sharding remains available.
Native image tests compare one run's stdout and partitioned outputs for
identical series, windows, cohort counts and histogram populations with
2, 4 and 8 workers; output tests cover metadata, partition ownership,
quiet flushing, write errors and partial-start cleanup.

Forensic selection remains per metric/second. With multiple workers, each
metric belongs to one shard; each shard has an equal share of the existing
512 MiB logical diagnostic budget. Concatenated gzip members form the single
diagnostic artifact. Ordering and truncation of this sampled forensic copy may
change; it remains separate from exhaustive authoritative counters and never
feeds the business verdict. Keep worker count frozen within a capacity interval.

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

Run a short App CPU smoke test:

```sh
./perf/app_cpu_capacity_smoke.sh
```

This test uses the NazoAuth service CPU override only (`PERF_APP_CPUS`, default
`1`; optionally `PERF_APP_TASKSET` for process-level CPU affinity). PostgreSQL,
Valkey, migration, and the k6 perf runner remain unrestricted unless
`APP_CPU_CAPACITY_INFRA_CPUSET` is set explicitly. In nested Docker
environments where Docker CPU quota is not enforced reliably, process-level
`taskset` is the effective limiter.

Run a single-instance full-flow max test:

```sh
./perf/single_instance_full_flow_max.sh
```

This runs one NazoAuth instance through the full OIDC cold-login flow with
short, high-arrival-rate points. The script splits the runner's allowed CPU set
into an application half and an infrastructure half: NazoAuth is pinned to the
application half, while PostgreSQL, Valkey, migration, and k6 use the
infrastructure half. The default scenario is `oidc_cold_login_refresh`, which
includes PAR, password login, authorization decision, authorization-code token
exchange, and refresh-token rotation.

The extended matrix wrapper below is a publishing workflow: it changes local
Git identity, commits reports, and pushes to the current/CNB branch. Run it only
with explicit publication authorization in its dedicated benchmark checkout.
For an unpublished local run, use `perf/capacity.py` with selected scenarios
and leave `CAPACITY_CHECKPOINT_COMMIT=0`.

```sh
./perf/extended_capacity_matrix.sh
```

The long capacity curve runs 30 minutes per point across 1, 2, and 4 NazoAuth
replicas. It is intended for dedicated benchmark machines, not routine local
verification.

Results are written to `perf/results/*.summary.json` and
`perf/results/*.k6.json`. Runners generate Markdown summaries and capacity
reports under `docs/performance/`; a fresh summary is run output, not an
automatically maintained repository baseline. Promote a report only with its
raw JSON, source identity, and environment capture, and update the
[performance index](../docs/performance/README.md). Keep temporary experiments
in the run's artifact directory until they meet that evidence boundary.

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

## Profiles

| Profile | Scenarios | Purpose |
| --- | --- | --- |
| `single-endpoint` | `token_client_credentials`, `mtls_client_credentials`, `par_signed_request_object` | Isolates endpoint throughput and authentication overhead. |
| `oidc-mixed` | `refresh_token_rotation`, `introspect_opaque_refresh_token`, `authorize_par_session` | Exercises normal OIDC login, PAR, authorization-code exchange, refresh rotation, and opaque refresh-token introspection across many users. |
| `oidc-same-user-contention` | `same_user_refresh_token_rotation`, `same_user_introspect_opaque_refresh_token`, `same_user_authorize_par_session` | Exercises concurrent operations from one account to reveal account/session contention risks. |
| `fapi2-high-security` | `fapi2_par_jar_private_key_jwt_dpop`, `fapi2_logged_in_high_security` | Exercises PAR + signed JAR + `private_key_jwt` + DPoP-bound authorization-code and refresh paths. |
| `capacity` | `token_only_client_credentials`, `oidc_cold_login_refresh`, `oidc_logged_in_authorization_code`, `oidc_refresh_only`, `fapi2_full_security`, `fapi2_logged_in_high_security` | Fixed-arrival-rate scenarios used by `perf/capacity.py` to build 1/2/4 replica capacity curves. |
| `extended-capacity` | `mtls_client_credentials`, `par_signed_request_object`, `introspect_opaque_refresh_token`, `authorize_par_session`, `revoke_refresh_token`, `metadata_jwks`, `same_user_refresh_token_rotation`, `same_user_introspect_opaque_refresh_token`, `same_user_authorize_par_session` | Covers protocol and security surfaces that should not be mixed into the primary capacity curve. |

## Capacity Curve Model

Capacity measurements for mTLS issuance, signed PAR, logged-in FAPI, cold
Argon2 login, and metadata/JWKS use the same scenario-clock cohort as `cap_*`.
Their `cap_iter_ms` covers the complete operation, including signing and all
HTTP steps. Any failed response check makes that operation unsuccessful even
when a later step succeeds. Historical results retain their original accounting.
`point_runner.stack_up_pinned` accepts optional `postgres_cpus` and
`valkey_cpus` sets to separate those components from the generator's
`infra_cpus`; application affinity is applied before the runtime starts.

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

`perf/extended_capacity_matrix.sh` runs a separate 30 minute per point
matrix for mTLS, opaque-token introspection, PAR/JAR endpoint cost,
authorization-session cost, token revocation, discovery/JWKS reads, and same-user contention. The current runner has no
CIBA scenario. Dynamic Client Registration still requires
dedicated provisioning setup and is kept out of this matrix.

The report normalizes observed throughput by NazoAuth service CPU usage:
`100%` Docker CPU is treated as one effective CPU core. This avoids claiming
capacity only from raw RPS when the service is consuming many cores.

For strict App CPU tests, `perf/run_capacity.sh` also supports:

| Variable | Meaning |
| --- | --- |
| `PERF_APP_CPUS` | Docker CPU quota for the NazoAuth service, for example `1`, `2`, or `4`. |
| `PERF_APP_TASKSET` | Process-level CPU affinity for NazoAuth. This is the effective limiter in nested Docker environments where CPU quota is not enforced reliably. |
| `PERF_APP_CPUSET` | Optional CPU set for NazoAuth. |
| `PERF_INFRA_CPUSET` | Optional CPU set for PostgreSQL, Valkey, keyset, migrate, and perf runner. |
| `SINGLE_INSTANCE_MAX_DURATION` | Duration per point for `single_instance_full_flow_max.sh`, default `2m`. |
| `SINGLE_INSTANCE_MAX_RATES` | Comma-separated fixed arrival rates for the full-flow max test, default `16,32,64,96,128,192,256,384,512`. |
| `SINGLE_INSTANCE_MAX_MAX_VUS` | k6 maximum VUs for the full-flow max test, default `4096`. |
| `SINGLE_INSTANCE_MAX_SCENARIO` | Scenario for the full-flow max test, default `oidc_cold_login_refresh`. |

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
uses the RFC 9440 `Client-Cert` header carrying the fixture certificate on the
isolated trusted perf network.

`perf/run_capacity.sh` defaults to committing and pushing results. Set both
`CNB_CAPACITY_COMMIT=0` and `CAPACITY_CHECKPOINT_COMMIT=0` for a local run.
The app-CPU and single-instance wrappers disable their own final commit by
default, but inherited checkpoint settings must still be reviewed. The extended
matrix's parent publication step has no equivalent opt-out.

## Incremental current-B acceptance

`perf/tools/current_capacity.py` evaluates the main workload and each of the
four mixed sidecars through `capacity_search.evaluate` with required stream
evidence. A naturally finished sidecar with a terminal summary is not by itself
a business pass. Each sidecar retains its own rate, scenario-specific latency
rules (including the separate cold-login class) and measurement cohort; the
existing common-window check must also cover the main measurement.

Invalid measurement or local preparation takes precedence over a service
failure when combining business, sidecar, health and maintenance verdicts.
Individual failures are retained, but an invalid point cannot establish a
service capacity upper bound. Missing summaries are invalid evidence.
`evaluate_point(point, record, point_directory, confirmation=...)` exposes the
same verdict path for offline reassessment of retained artifacts without load;
keep the original records and publish reassessment separately. Only affected
points with insufficient evidence require new measurement.

For retained point directories, run an offline reassessment first (no Docker,
SSH, image build or new load is performed):

```sh
python perf/tools/current_capacity.py --reevaluate \
  "$POINT_A/point.json" "$POINT_B/point.json" --output "$REASSESSMENT_JSON"
```

For new load, `--mode single|multi` and `--scenarios ...` restrict the search.
`--rates ...` runs only the requested rates for exactly one mode/scenario;
`--window` is their effective duration (default 180 seconds). Existing valid
observations with the same recipe/rate and at least that duration are reused;
`--repeat` explicitly requests a new observation. Mixed `--confirm --window 660`
also checks mature maintenance and preserves the journal. It is unnecessary to
repeat an already valid confirmation under an unchanged recipe.

```sh
python perf/tools/current_capacity.py --stop-at "$STOP_AT" \
  --mode multi --scenarios cap_mixed --rates 2400 3000 --window 180 \
  --vus "$CALIBRATED_VUS" --users "$FIXED_USERS" \
  --pool-connections "$CALIBRATED_POOL"
```

CPU IDs come only from the process affinity. With fewer than four available
logical CPUs, infrastructure shares the available set; this topology is recorded
and must not be described as isolated infrastructure. Default main VUs scale at
64 per allocated application CPU, users at 16 per CPU with a minimum of 64,
and the pool at two connections per allocated PostgreSQL CPU. These are initial
calibration recipes, not resource availability guarantees or validated maxima.
Use deployment-local observations to fit memory and database connection limits.
`--vus`, `--users` and `--pool-connections` independently override them; increasing
VU capacity does not silently change user cardinality. `--sidecar-vus` accepts
four positive counts in argon2/metadata/FAPI/refresh order, without changing
sidecar rates or users. Default sidecar VUs scale upward with application CPUs.

Recipe-specific `registered-config-<id>.json` and `search-state-<id>.json` preserve
independent histories when images, affinity, pool, VUs, users or sidecar settings
change. Do not combine bounds from different recipes. The old unqualified
`search-state.json` is not imported automatically: reassess its archived points
and retain valid published results, then request only missing new points.
Historical reports remain tied to their original controller and configuration.
