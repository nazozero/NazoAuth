# NazoAuth Performance Benchmarks

This directory contains reproducible Docker Compose based load benchmarks for
NazoAuth. It is separate from correctness, conformance, and browser UI tests.

Python benchmark tooling uses Python 3.15.0. The runner recipe pins exact
package versions; coverage and E2E environments use the separate hash locks
under `requirements/`. Redis clients
explicitly use RESP2, the existing socket/connection settings, and zero retries,
preserving the original `from_url` connection-pool behavior on redis-py 8.
Valkey failures remain observable to the seed, ledger, runner and sampler.

Audit evidence distinguishes pending export from retained business facts.
On schemas with `security_audit_events.exported_at`, `pending`/`pending_export`
and oldest-pending age cover only unexported rows. The ledger's `events` and
boundary `total` counters still include every row; `exported_retained` counts
ACKed decision facts kept for replay protection. Those retained rows do not
prevent export drain. Historical schemas without that column keep the original
pending=total semantics and report zero exported-retained rows. Schema capability
is probed once per fixed run/ledger invocation, not per sampled row.
Full retained-row counts are boundary diagnostics, with an additional sparse
60-second sampler observation; pending sampling and acceptance thresholds are
unchanged. Separate statements are observations at different instants, not an
atomic accounting identity while writers/exporters are active.

The runner image pins `orjson==3.12.0` for the streaming evidence decoder.
Checkpoint evidence uses k6's buffered `--quiet --out json=-` output,
redirected to the analyzer FIFO. The script writes summaries only to files;
the runner closes its FIFO descriptor before sampler shutdown and waiting
for the analyzer. This
retains all metric points and flushes the final buffered batch without a
relaxed lag gate.

The native JSON periodic flusher also flushes its stdout buffer after each
batch. Sparse initialization gauges must arrive at that boundary, before a
later workload fills 4 KiB or `Stop()` closes output. Otherwise old VU samples
can appear late although business samples are timely. A native regression
feeds two sub-4-KiB batches and verifies their complete envelopes arrive before
the next batch or shutdown. All samples and the five-second lag gate remain
unchanged.

The runner builds exact k6 v2.3.0 source `e0887846143ab176d4b5483c9d52cf3b3e009f1a`
from a checksum-verified archive. Its [small JSON output patch](runner/k6-json-throughput.patch)
reuses bounded encodings of immutable tag sets and writes the same complete
sample envelope without repeated reflection. Retained samples preserve every
timestamp, value, tag and metadata field; metadata and invalid-value cases use
the stock encoder. The runner sets `K6_JSON_OMIT_UNUSED_HTTP_TIMINGS=1` to omit
only `http_req_blocked`, `http_req_connecting`, `http_req_tls_handshaking`,
`http_req_sending`, `http_req_waiting` and `http_req_receiving` from JSON output.
The evaluator does not consume these six auxiliary timings. Native k6 summaries
and thresholds still receive every metric; complete-operation cohorts/quantiles,
window contracts, outcomes, errors, drops, HTTP totals/duration, network bytes
and VUs remain exhaustive in the stream. Setting the flag to `0` restores full
JSON output. This output setting is recorded in `k6-started.json`; runner image
identity separates its recipes from previous unfiltered images.
Upstream output/metrics tests and added envelope equivalence,
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

The dispatcher sends complete input blocks to workers. Each worker selects
its existing metric partition with a bounded native-row regex cache; new
metrics, window contracts and other JSON layouts use the routing decoder.
This removes per-Point work from the dispatcher. A worker still decodes and
validates every owned Point, in input order, with the same forensic selection.
Available complete input blocks are dispatched immediately. The dispatcher
does not wait to accumulate 64 KiB: low-rate sidecars must reach their consumers
before a later iteration or EOF, under the same five-second lag gate.

Forensic selection remains per metric/second. With multiple workers, each
metric belongs to one shard; each shard has an equal share of the existing
512 MiB logical diagnostic budget. Concatenated gzip members form the single
diagnostic artifact. Ordering and truncation of this sampled forensic copy may
change; it remains separate from exhaustive authoritative counters and never
feeds the business verdict. Keep worker count frozen within a capacity interval.

## CNB Docker-socket controller

The normal host-bind entry in `tools/single_instance_scaling.py` calls Docker
directly; state inspection does not copy output. When a CNB controller shares a
Docker socket but cannot expose its own bind paths to that daemon, use the
committed `tools/cnb_controller.py` entry with named output volumes:

```sh
SIS_CNB_EVIDENCE=/evidence SIS_WORKSPACE=/workspace python perf/tools/cnb_controller.py setup
SIS_CNB_EVIDENCE=/evidence SIS_WORKSPACE=/workspace python perf/tools/cnb_controller.py s21
```

Prepare a fresh, task-owned project and its `scripts`, `pinbin`, `audit-tls`,
`evidence` and `work` volumes before setup. Mount the complete selected Git source
read-only at `/workspace`, writable evidence at `/evidence`, and the work volume
at `/workspace/perf-results`. The controller image needs the existing runner
Python dependencies, Docker/Compose, Git and a C compiler. The public
`/evidence/requests/manifest.json` binds `project`, `source_sha`, `runner_image`,
`app_image`, `helpers` (receiver), `cpus`, `harness_file_sha256`, and each
`requests` entry's exact `path` and `sha256`. Requests retain the normal harness
parameters and gates; the controller verifies their hashes and does not change
rates, VUs, windows, CPU widths, pool size, audit or durability settings.

Only explicit sampler readiness and terminal capture copy output. Running
state/affinity checks never copy whole result directories. Terminal `logs` or
removal resolves the registered name or full instance ID and captures each output
once from that exact instance before removal. All terminal promotion passes
through the same exact-ID ownership and stopped-state inspection in `sync_one`;
the copy record retains that positive proof. A still-running instance is copied
as partial and records a termination error while other collection and existing
owned cleanup continue. The error prevents PASS even if the business metrics pass. Fault finalization verifies the existing ownership label, then
boundedly stops/waits for remaining workloads and attempts their final output
before the existing owned cleanup. One failed copy does not skip other copies
or independent state capture; original failed verdicts and metrics are retained. Sampler metadata is copied before its bounded readiness check.
Required copy failure prevents PASS, records `collector_copy_complete=false`,
keeps any business metrics, and produces `INVALID` after owned cleanup. The
existing exact-window, full-stream, terminal-summary and affinity gates remain
in force; diagnostic event sampling does not replace them. The normal host-bind
path and application code are unchanged.

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

For bounded capacity runs, set an exclusive `SIS_PROJECT`, `SIS_WORKSPACE`,
`SIS_APP_SHA`, and `STOP_AT` as described below, then run:

```sh
make perf-capacity-smoke
make perf-capacity CAPACITY_ARGS="--mode multi --scenarios cap_mixed --rates 2400 --pool-connections 32"
```

The current driver records the workload, binary, infrastructure, CPU assignment,
and measurement windows. Pool comparisons use separate `--pool-connections`
recipes. A shared old resume file cannot establish those identities.

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
| `capacity` | `token_only_client_credentials`, `oidc_cold_login_refresh`, `oidc_logged_in_authorization_code`, `oidc_refresh_only`, `fapi2_full_security`, `fapi2_logged_in_high_security` | Legacy fixed-arrival scenarios; use the current cap scenarios for windowed capacity evidence. |
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
The runtime pinning helper applies affinity under each service process owner's
UID, including non-root daemons below a root-owned init process. Preflight
requires PID 1, its service descendants and every visible service thread to
match the declared CPU set. Generator service threads are checked during the
load wait loop; `generator-affinity.json` records the actual runner/k6 masks.
`service-affinity.json` records the app, PostgreSQL and Valkey service trees
during the existing main and sidecar wait loops, plus a final service snapshot
after all runners finish. Samples retain PID/TID, UID, parent PID, process name, start ticks
and allowed CPUs; they describe the sampled instants, not continuous coverage.
The source-bound static pinset helper reads each snapshot in one process,
without per-thread shell/awk children. It retries failed reads once and
confirms a vanished task directory twice; unreadable still-present tasks,
malformed rows or missing completion metadata make evidence incomplete and
invalidate the point. Snapshot metadata retains read errors, confirmed exits
and Docker-exec round-trip time so observation cost remains visible.
A mismatch invalidates the point. Docker exec inspection and healthcheck roots
are excluded from service-tree verification.

`perf/tools/current_capacity.py` is the supported capacity runner. The old
matrix/soak scripts depended on retired application collectors and were removed.
`perf/tools/capacity_search.py` supplies its evidence evaluator; `pool_size_ab.py`
retains offline `--reeval` for historical A/B records.

Render old capacity records without running containers or changing their source:

```sh
python perf/capacity.py --input perf/results/data/capacity/latest.json --report-path perf/results/reports/capacity.md
```

Legacy records without a valid business measurement window are not capacity
passes. Offline reports do not fill missing source SHA, CPU identity, duration,
or matrix coverage from the current machine. `finalize_capacity_reports.py`
reads recorded durations and marks absent provenance unavailable.

## Metrics

Each scenario writes:

- k6 HTTP request count, RPS, error rate, p50/p95/p99 latency
- Docker CPU and memory samples for NazoAuth, PostgreSQL, and Valkey
- PostgreSQL `pg_stat_statements` calls, mean statement latency, and
  statements per HTTP request
- Task runtime-role PostgreSQL backend states and wait events (database view)
- Valkey command, hit, miss, expiry, and key-count deltas

New runs explicitly declare `blackbox-db-v1`. Application performance endpoints,
pool acquire/wait counters and in-process audit counters are removed. Missing
internal dimensions are `UNAVAILABLE`; process queue gates are `UNVERIFIED`.
DB outbox drainage and receiver chain/ACK reconciliation remain required and
do not establish best-effort in-process queue emptiness. Historical records keep
their original evidence contract and are not silently reclassified or pooled
with new runs. See `perf/docs/blackbox-evidence-contract.md`.

## Notes

The compose file uses disposable perf volumes. It enables
`pg_stat_statements` for database latency and per-request query accounting.
The server profile remains `oauth2-baseline` so ordinary OIDC and FAPI-style
client-level hardening can be measured in one reproducible environment. The
FAPI scenario uses client-level PAR request-object enforcement,
`private_key_jwt`, signed JAR, and DPoP-bound tokens. The mTLS endpoint scenario
uses the RFC 9440 `Client-Cert` header carrying the fixture certificate on the
isolated trusted perf network.

Capacity runners write local reports and JSON checkpoints in ignored
`perf/results/`. Publish results through CI artifacts or the associated issue/PR;
do not commit run-specific output to the source repository.

## Capacity result evaluation

Bind externally retained results to their source SHA, deployment configuration,
workload and measurement window before comparing or reproducing a point.

`perf/tools/current_capacity.py` evaluates the main workload and each of the
four mixed sidecars through `capacity_search.evaluate` with required stream
evidence. A naturally finished sidecar with a terminal summary is not by itself
a business pass. Each sidecar retains its own rate, scenario-specific latency
rules (including the separate cold-login class) and measurement cohort; the
existing common-window check must also cover the main measurement.
Offline reassessment exposes `complete_operation_latency_ms` from each
sidecar's native `cap_iter_ms` cohort. A sidecar without that cohort reports
`null`, never zero or an HTTP-duration substitute. The existing metadata/JWKS
sidecar retains its whole-scenario iteration accounting and request-latency
gate; its HTTP quantiles are labeled separately from complete-operation
quantiles. This reporting field does not alter any verdict.

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
`--application-cpus` sets the multicore application count after measuring
component costs. CPU IDs still come from visible affinity; PostgreSQL keeps
its default count unless `--database-cpus` explicitly calibrates its budget;
released application/database CPUs go to the generator. Database CPU tuning
does not change the connection pool or PostgreSQL durability settings.
The override requires disjoint application/database/Valkey/generator sets and
at least one generator CPU. Changing it creates a separate recipe: remeasure
both endpoints and report the actual application count.
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

P-256 performance fixtures encode `x`, `y`, and `d` as exactly 32 octets, including leading zero octets. Validate deterministic short-coordinate keys in the perf runner with `python -m unittest perf.tests.test_seed_jwk -v`; RSA integer encoding remains unchanged.

## Preview and evidence interpretation

The optional capacity preview binds `127.0.0.1` by default. Set
`CAPACITY_PREVIEW_HOST` explicitly when a controlled remote-access boundary is
available. Dashboard clients share a system snapshot refreshed at most once per
five seconds after collection completes. Authentication and protocol failures
remain visible in preview logs.

Throughput gates use business operations in the measured window, preserving zero
as a valid measured value. A missing business counter is unavailable evidence,
not a reason to substitute HTTP request rate. Stability runs require adjacent,
complete time buckets. Checkpoint correlation counts distinct observed write
windows, not the number of buckets overlapped by a single checkpoint. Load budget
elapsed time ends at the latest observed main or sidecar completion.

The Rust `token_hotpath_perf` fixture reports cold-client group throughput:
`wall_ms` includes thread, HTTP client, and connection setup. Warmup carries
server and token state forward, but does not preserve worker connections.
Per-operation latency ends after the complete response body and excludes worker
construction. The JSONL scope fields identify the setup and timing boundaries
of each measurement.
