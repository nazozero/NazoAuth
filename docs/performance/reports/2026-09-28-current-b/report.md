# Current-B performance exploration and CI repair — 2026-09-28


Date: 2026-09-28. Task start was 2026-09-27 23:47:16 +08:00. The earlier
deadline was 2026-09-28 07:47:16 +08:00; exploration was budgeted to stop by
06:17:16, leaving at least 90 minutes for submission and final CI.

This run tests PR #222's current B only. It does not repeat historical A/B,
ABBA or the 1,800-second matrix. Short observations and maintenance confirmations
do not establish production long-term capacity. Previous deployment results
remain historical records; their machine, operation-latency and duration
contracts differ, so no improvement percentage is calculated against them.

## Identity and deployment

The freshly fetched PR head at task start was
`dca30911651611c2f4fb2485ad90b21fad21e37d`, with the PR open. The application
was built from `ac266e7a93749694022efd1aeea6ed4d316fbbcc`:

- Image: `sha256:5f62a3a2247e609d72ee03de1bc0d330873d5742b1f94cd5ec144baa69f2f71d`.
- Binary: `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b`.
- Applied migration chain: `812aa6dc33897e769a6ee6d7481aa5bed8b216097d38ce0ca81a3268e4832920`.
- Each accepted point verifies checkout/source label, image binary and running
  PID 1 binary; later changes affect CI, tests, documentation and the runner.
- Final capacity endpoints use runner image
  `sha256:64b272744b87acc391c9a628ed37aa070d8517471527e6b2adc5066ae61664ef`,
  built at `dd69c9e2330580422ef417c5a38b726e509c1942`. Earlier runner-image
  observations remain exploration context and are excluded from the current
  endpoint table. Controller revisions are recorded per point; later scheduling
  and post-load archive changes do not change the measured workload.
- Workload producer `oauth.js`: `655cb225eb6647f4b574b8f5356deea1214d1d6750e92b9c58858ba888aac697`.

The [environment capture](../../../../perf/results/environments/2026-09-28-current-b.md)
records the pinned tool versions, process-visible resource files and effective
allocation without machine identifiers or benchmark secrets.

The container's process-visible affinity contained 64 logical CPUs; its own
visible quota was 64 CPUs and memory limit 128 GiB. Allocation derives from
that affinity, without inspecting the host or invisible parents. The application
uses CPU `24` in single-core mode and `24-27,132-143` (16 logical CPUs) in
multi-core mode. PostgreSQL uses `144-159` (16), Valkey `160` (1), and k6,
samplers, audit exporter and durable receiver share `161-191` (31). Application
affinity is set before execution/thread-pool creation and checked in each point.
The generator and server sets are disjoint; auxiliary processes still share
the generator set. Tracked load, exporter and receiver costs are in the
diagnostic evidence; sampler CPU is not separately attributed.

The deployment uses PostgreSQL 18.6, pool size 32, `max_connections=100`,
`shared_buffers=128MB`, `max_wal_size=8GB`, checkpoint timeout 5 minutes,
completion target 0.9, and enabled fsync, synchronous commit and full-page writes.
`track_io_timing=on`; `track_wal_io_timing=off`, so zero WAL timing counters
are N/A for timing interpretation. Existing Valkey benchmark persistence settings
are unchanged; this is not a Valkey crash-durability experiment. Durable issuance
and audit use PostgreSQL and the durable test receiver.

Main VUs are fixed at 64/256 and users at 64/256 for single/multi mode. The
configured vector count is 48,000 for ordinary scenes and 49,200 for FAPI,
including its 1,200-vector reserved offset plus a bounded 48,000-vector replay
slice. The coordinator explicitly registers that FAPI pool before higher-rate
and longer candidates, preventing the existing runner from silently expanding
it with rate/duration. Initial 48,000-vector FAPI probes are exploratory context;
current FAPI endpoints are remeasured with 49,200 and actual counts are recorded.
The workload, pool and VU configuration is not tuned
between formal points. Only the offered arrival rate changes during exploration.
The registered sidecar recipe retains a 210-second duration prototype from
initial 180-second points. It is not the actual duration of later points:
`effective_point.sidecars` in each selected snapshot records the executed
duration (including the 660-second confirmations). Rates, VUs and users stay
fixed within each CPU mode.
The coordinator verifies all secondary candidates before using spare deadline
budget for extra narrowing; a valid same-load mixed confirmation is reused on
controlled restart. These scheduling choices do not alter a gate or test recipe.
No application build or competing heavy task runs in the test container during
formal measurement.

## Measurement and gates

The thin `perf/tools/current_capacity.py` coordinator invokes the existing point
lifecycle, scenario producer, streaming cohort and capacity evaluator. Exploration
uses 90-second effective windows initially and 60 seconds after the budget
adjustment, candidates 180 seconds, and mixed maintenance
confirmations 660 seconds. Warmup is 15 seconds for isolated scenarios and 60
seconds for mixed; neither warmup nor post-load drain enters the denominator.
Points are fresh isolated stacks/databases; the workload keyset is reused.

One scenario clock defines a half-open cohort window. Iteration entry determines
membership, and completion during graceful drain remains attached to that cohort.
Successful operations/s uses successful complete logical operations divided by
that effective window. Full-operation P50/P95/P99 comes from `cap_iter_ms`,
including every request of that flow. Quantiles are neither averaged across
points nor substituted by HTTP request latency. HTTP requests/s is reported
separately on whole seconds fully inside the main window, by request completion
time. Mixed sidecars have their own operation populations and cover the full
main window; their operation rates are not added to the main capacity number.

Standard paths retain success at least 99.5% of offered load, drops at most 0.1%,
zero unexpected errors, and full-operation P95/P99 at most 100/250 ms. Cold
Argon2 is a separate class retaining its existing checks and five-second HTTP
guards, plus strict success/drop/error accounting; its full-operation latency is
reported without applying the standard 100/250-ms gate. Password-hash parameters,
audit and durability are not weakened. Seeded passwords use the existing
argon2-cffi 25.1.0 defaults (`m=65536,t=3,p=4`), while newly generated application
password hashes keep `m=19456,t=2,p=1`; the verification workload exercises the
stored seeded hash. Argon2 concurrency 8 and queue deadline 100 ms are unchanged.

Missing or invalid cohort/runtime/audit evidence yields INVALID, not a pass or
service-failure upper bound. Every accepted point requires no OOM/restart,
no audit queue loss or required-event loss, drained outbox, and durable receiver
hash/sequence reconciliation with a contiguous journal. Mixed also requires all
four sidecars and a collected drained-queue snapshot. The trusted-proxy benchmark
transport exercises certificate-header mTLS handling; it does not measure an
external TLS terminator's handshake cost.

Mixed recipes retain every sidecar category. Single-core offered sidecar flows/s
are cold login 1, metadata/JWKS 13, FAPI 2 and refresh 38. Multi-core rates are
8, 200, 30 and 600 respectively. Each metadata flow makes two HTTP requests.
The independent sidecar warmup is 15 seconds, and sidecar duration extends
30 seconds beyond the main load so the full main measurement has common coverage.

The mixed maintenance gate declares maximum issuance retention 360 seconds
(terminal access-issuance ownership/fence deadlines including skew) and expired-age objective 120
seconds. A 660-second effective confirmation has a 300-second mature window
after that retention horizon, covering multiple maintenance cycles. Existing
two-second sampling requires boundary/sample gaps at most four seconds and at
least 180 mature seconds. The measured `oauth_token_issuances.retain_until` is the maximum of
access-token expiry plus the 60-second acceptance skew and any single-use
grant deadline ([ownership calculation](../../../../crates/persistence-postgres/src/repositories/token_issuance.rs)).
Here access TTL is 300 seconds and authorization-code TTL 60; refresh rotation
uses fresh issuance rather than a long-lived consumed-grant fence. ID-token TTL
600 belongs to a different signed-token/key-verification lifetime, not this
terminal access-ownership retention gate. Expired count alone does not prove failure: age and
same-span insertion/deletion diagnostics distinguish the normal cleanup sawtooth.
This interval does not establish behavior over the one-hour refresh-contract grace.

## Evidence and cost interpretation

WAL generation is the measurement-window delta of `pg_stat_wal.wal_bytes`.
WAL writes, write bytes and fsync counts come from PostgreSQL 18 `pg_stat_io`
for object `wal`, summed across backend/context rows. They measure different
things: generated WAL records are not bytes written to WAL buffers/files, and
reported write bytes are not physical-device write amplification. The counter
definitions follow the [PostgreSQL 18 statistics documentation](https://www.postgresql.org/docs/18/monitoring-stats.html#MONITORING-PG-STAT-IO-VIEW).
Interpolated
boundary deltas can be fractional counts. Mixed WAL/op includes all sidecars,
audit and background activity, divided by successful main operations; it is not
the intrinsic cost of one SQL statement or one token issuance.

CPU is process jiffy deltas within the window, with 100% equal to one logical
CPU's time. RSS is process RSS; summing PostgreSQL process RSS counts shared
pages repeatedly and is not unique resident memory. Pool wait/acquisition is
window-interpolated total wait divided by acquisitions, not a tail percentile.
`pg_stat_statements` deltas span the point including warmup/background tasks;
top statements supply diagnostic context, not proof of CPU usage or critical
path attribution. An upper point limited by VUs or the observer is distinguished
from a demonstrated application saturation ceiling.

Compact source identities, results and selected diagnostics are retained in Git.
High-frequency streams and logs are external run artifacts. Mixed maintenance
confirmations retain the original receiver journal after the load and compare
its SHA-256 to the runtime reconciliation hash. Earlier short points retain
runtime hash, range, contiguity and anchor proofs; their original journal files
were not saved before the fresh-stack teardown.
The test receiver is not a deployment-level WORM attestation.

## CI repair and observed cost

The starting failure was `Verify compatibility contracts` in run
[36327837658](https://github.com/nazozero/NazoAuth/actions/runs/36327837658).
It was a documentation contract failure caused by a workstation-specific
absolute artifact path, not a Rust test failure. `ac266e7a` replaced that path
with the archive filename/hash and preserved the external-only evidence boundary.

`d6ffeb26` budgets Cargo jobs from the runner's allowed CPUs and available
memory (3 GiB/job); the observed runner selected four jobs. Shared PostgreSQL/
Valkey tests remain serial, as do linker threads. Schema materialization now
uses the same all-features package variant as the workspace test, avoiding
the redundant feature-variant build. The scale/planner fixture test reclaims its
synthetic state before handing the database to the following natural-autovacuum
test. All scale, claim, plan and natural append/claim/ack/delete assertions remain;
the following test does not receive a vacuum during its own measured lifecycle.

| Representative run | Queue s | Rust job s | Clippy s | Schema s | Workspace step s | Workspace compile s | Audit suite s |
|---|---:|---:|---:|---:|---:|---:|---:|
| [36258980864](https://github.com/nazozero/NazoAuth/actions/runs/36258980864) | 2 | 1829 | 112 | 57 | 1567 | 460 | 429.57 |
| [36259760141](https://github.com/nazozero/NazoAuth/actions/runs/36259760141) | 2 | 1859 | 114 | 56 | 1601 | 464 | 449.34 |
| [36263512164](https://github.com/nazozero/NazoAuth/actions/runs/36263512164) | 4 | 2578 | 117 | 59 | 2302 | 462 | 1157.24 |
| [36331729318](https://github.com/nazozero/NazoAuth/actions/runs/36331729318), repaired eecdeb91 | 2 | 1794 | 159 | 143 | 1399 | 290 | 422.96 |
| [36337202258](https://github.com/nazozero/NazoAuth/actions/runs/36337202258), b33c05cf | 2 | 1516 | 58 | 44 | 1328 | 205 | 428.29 |

Queue is workflow creation to Rust job start. Container initialization was
12–14 seconds (16 in the slow historical run), native-package setup 9–12 seconds,
and Rust cache restore 23–32 seconds in the sampled earlier runs versus 1 second
in eecdeb91 and 17 seconds in b33c05cf;
these are not the dominant
cost. Reported compiler time is taken from Cargo's completion message and is
contained within its step, not an additional cost. The repaired scale fixture
took about 381 seconds including state handoff; the following natural-autovacuum
test took about 40.5 seconds, versus 69.4/89.7/790 seconds in the three preceding
runs. The slow historical run is an outlier, so a universal improvement percentage
is not inferred. Serial integration execution and the large planner/claim fixture
remain significant costs.

The later b33c05cf job completed in 25m16s with four Cargo jobs and serial test
execution. Cache state differs (restore 17 seconds), so the whole-job difference
from the earlier 30-minute typical runs cannot be attributed solely to one change.
All 11 applicable checks passed on b33c05cf with two justified PR skips; this
checkpoint still does not replace validation of the final documentation commit.

The runner regressions now cover the existing measurement, producer, cohort,
single-instance, pool, maintenance, evidence and audit-prefix contracts in CI
(232 tests).
The high-rate introspection observer initially exceeded its five-second lag
gate and was marked INVALID. `dd69c9e2` reduced JSON decoding/forensic compression
cost with pinned orjson 3.12.0 and gzip level 1, retaining accounting and lag
rules. A 40,000-line diagnostic replay preserved cohort/bin and decompressed
diagnostic hashes; local profiled replay was 0.5265 versus 0.3490 seconds. This
sample experiment is not a service throughput measurement. The captured 40,000
points precede the measurement cohort (zero cohort completions), so this replay
checks sample decoding/binning/compression preservation; it does not independently
prove successful-operation accounting. Nonempty cohort behavior is covered by
the retained regression suite and accepted runtime points. `bc6596bc` corrected
the YAML scalar for the pip option after the preceding workflow failed validation
before creating jobs. Cancelled duplicate CI runs are not counted as successes.

`b33c05cf` corrected the audit predicate for standalone successful signed PAR:
that path stores its request object without emitting an audit event. An unchanged
prefix is valid only with unchanged pre/post hash and all existing two-sided
state, count, pending, identity and journal-integrity checks. Ordinary/issuing
workloads still require progress. The old false PAR failures are invalid tester
observations, not service upper bounds; current accepted PAR points use the
corrected predicate. Empty PAR journal evidence proves prefix consistency, not
delivery throughput for an audit-producing workload.

`714cc059` makes valid observations take precedence over INVALID observer
attempts when choosing bounds at the same offered rate. Among valid observations,
the existing longest-window policy remains; every original verdict and duration
is retained. An invalid longer candidate does not erase a valid short observation
or establish a longer-window pass. Such a result stays a short-window lower bound
with an unverified candidate, and unchanged invalid evidence is not blindly retried.

Final checks must be evaluated on the delivered commit. The older repaired
successful run is evidence for the repair only. Official-source freshness and
the push-only advisory audit are conditionally skipped on PRs; dependency review
still runs. Coverage publication is not an applicable PR workflow and no coverage
percentage is claimed for this task.

## Reproduction and retained files

Use the existing [performance setup](../../../../perf/README.md) to build the
application at the tested source and the runner at the recorded revision, then
check their image/binary identities. Mount the checkout under a path visible to
the Docker daemon (`/workspace` in this deployment); a host-only `/tmp` bind is
not suitable for the external daemon. Initialize the existing keyset and sampler/
receiver images before running the coordinator. Do builds before formal load.

```sh
export SIS_PROJECT=current-b-reproduction
export SIS_WORKSPACE="$PWD"
export SIS_RESULTS="$PWD/perf-results/current-b"
export SIS_PERF_IMAGE=nazoauth-perf-perf
export SIS_APP_SHA=ac266e7a93749694022efd1aeea6ed4d316fbbcc
export SIS_LOAD_BUDGET_S=18000
python perf/tools/current_capacity.py --stop-at '<future ISO timestamp with timezone>'
```

Use a Python environment with the runner's required dependencies. The controller
allocates CPU sets from actual process affinity; `registered-config.json` and
each point capture effective resources, pool, users, vectors, VUs, recipe and
window. The command uses the single current B lifecycle despite the historical
`run_ab_point` function name. A `stop-after-point` file in `SIS_RESULTS` requests
a graceful stop after the current point and state save; it does not interrupt
measurement or turn an unfinished point into a pass. The preserved JSON and
external file manifest identify the exact inputs to every retained observation.


`47134478` repairs the observed 64-character receiver DNS label in FAPI
180-second points. Python IDNA resolution rejected it before TLS connection;
the exporter could not deliver its prefix. Passing business metrics without
receiver/DB/journal evidence remained INVALID. Compact FAPI/PAR point slugs fit
DNS's 63-byte label limit while retaining the full scenario in structured data.
TLS hostname/CA verification and every audit gate remain intact. Eight controller
regressions include actual IDNA encoding across every scenario/mode/window and
configured ladder range, plus uniqueness. The old FAPI long points are retained
only as invalid tester diagnostics; accepted FAPI endpoints are remeasured.

## Capacity observations

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

## Mixed maintenance, audit and WAL

| Mode / point | Result | Effective window s | Generated WAL MiB | WAL write MiB | Writes / fsyncs | Generated / written bytes per main success | Audit events / token-issued (whole point) | Journal archive |
|---|---|---:|---:|---:|---|---|---|---|
| single / `single-cap-mixed-r600-w660-1790538042` | PASS | 660 | 1308.193 | 5456.106 | 406231.228/405983.228 | 3463.989/14447.328 | 536367/335282 | 45dcd4a33f270d59632022f246d5cb453a2b14eda38969947159717ac33a8d72 |
| multi / `multi-cap-mixed-r2000-w660-1790542347` | PASS | 660 | 5840.645 | 16231.019 | 775235.432/774120.489 | 4639.664/12893.518 | 2251005/1514995 | b96fd882c6f57245af35b6d1337741c1ad30ecbe1c1e34c2e8fa7410da8c5fc9 |

| Mode | Maintenance | Mature span s / samples | Max expired age s | Due count first / last / max | Due-count slope/s | Inserted / deleted (same mature span) | Max sample gap s |
|---|---|---|---:|---|---:|---|---:|
| single | PASS | 300 / 148 | 58.435 | 8413/8339/8413 | -0.337 | 138877/141626 | 2.056 |
| multi | PASS | 300 / 146 | 59.531 | 39446/14451/39446 | -101.262 | 619751/537493 | 2.073 |

| Mode | Queue enqueued / persisted / dropped / pending after drain | Durable events / token-issued (whole point) | Gaps / duplicates / malformed | Anchors reconciled |
|---|---|---|---|---|
| single | 67827/67827/0/0 | 536367/335282 | 0/0/0 | PASS |
| multi | 250212/250212/0/0 | 2251005/1514995 | 0/0/0 | PASS |

The multicore mature interval inserted 619,751 rows and deleted 537,493, even while the sampled due count decreased and expiry age stayed below its declared SLO. This does not prove indefinitely bounded total retained inventory.

WAL includes all sidecars and background tasks and is divided by successful main operations. Audit event counts span the whole point including warm-up and drain; they are not measurement-window audit throughput. Exact source snapshots and continuity checks are in the selected evidence.

## Component cost and bottleneck evidence

| Mode / scenario / L or U | Offered / success ops/s | App CPU / allocated | PostgreSQL CPU / 16 | Valkey CPU / 1 | Sampled load/exporter/receiver CPU / 31 | Pool wait ms/acquisition | App peak RSS MiB |
|---|---|---|---|---|---|---:|---:|
| single / `cap_mixed` / L | 600/600 | 0.65/1 | 1.318/16 | 0.047/1 | 0.864/31 | 0.027 | 100.926 |
| single / `cap_mixed` / U | 700/699 | 0.762/1 | 1.553/16 | 0.054/1 | 0.981/31 | 0.638 | 100.984 |
| single / `cap_client_credentials` / L | 1600/1598.494 | 0.822/1 | 1.949/16 | 0.042/1 | 1.147/31 | 0.038 | 34.117 |
| single / `cap_client_credentials` / U | 2000/1944.083 | 0.988/1 | 2.29/16 | 0.046/1 | 1.424/31 | 2.643 | 34.359 |
| single / `cap_authorization_code` / L | 320/320 | 0.712/1 | 1.835/16 | 0.1/1 | 1.246/31 | 0 | 34.148 |
| single / `cap_authorization_code` / U | 400/399.55 | 0.87/1 | 2.098/16 | 0.129/1 | 1.568/31 | 0.015 | 34.867 |
| single / `cap_refresh_token` / L | 800/799.989 | 0.837/1 | 1.929/16 | 0.029/1 | 0.761/31 | 0.018 | 34.594 |
| single / `cap_refresh_token` / U | 1000/941.9 | 0.995/1 | 2.363/16 | 0.03/1 | 0.887/31 | 5.523 | 34.645 |
| multi / `cap_mixed` / L | 2000/2000.002 | 4.586/16 | 4.719/16 | 0.16/1 | 4.104/31 | 0.027 | 142.082 |
| multi / `cap_mixed` / U | 2400/2387.817 | 5.133/16 | 5.33/16 | 0.181/1 | 4.53/31 | 1.266 | 131.84 |
| multi / `cap_client_credentials` / L | 6000/5999.35 | 4.661/16 | 5.652/16 | 0.126/1 | 4.377/31 | 0.375 | 60.816 |
| multi / `cap_client_credentials` / U | 7000/6975.983 | 5.509/16 | 6.631/16 | 0.145/1 | 5.034/31 | 0.836 | 59.508 |
| multi / `cap_authorization_code` / L | 960/960 | 3.091/16 | 5.72/16 | 0.275/1 | 4.056/31 | 0.017 | 60.133 |
| multi / `cap_authorization_code` / U | 1120/1120 | 3.762/16 | 9.302/16 | 0.307/1 | 4.719/31 | 0.801 | 61.426 |
| multi / `cap_refresh_token` / L | 3200/3200.006 | 4.954/16 | 7.572/16 | 0.076/1 | 2.842/31 | 0.134 | 61.305 |
| multi / `cap_refresh_token` / U | 4000/3939.667 | 6.489/16 | 10.959/16 | 0.09/1 | 3.403/31 | 5.175 | 63.754 |

CPU and pool data are observed costs, not proof of a specific SQL cause. Fixed VUs and the stream observer can constrain the offered-load apparatus even with CPU headroom. INVALID observer attempts are excluded from service upper bounds. Per-point wait-event counts and top-level SQL execution deltas remain diagnostic evidence; no per-SQL WAL attribution or physical-disk bottleneck is claimed.

## Retained evidence and limits

An incremental offline reassessment at evaluator commit
`04146234c578e61797aacee7ef7c4687b75653a1` rechecked all 28 selected points
against the shared main/sidecar, health and maintenance verdict path. The
[reassessment](../../../../perf/results/diagnostics/2026-09-28-current-b-reassessment.json)
retains original point SHA-256 identities and separate evaluator results.
Both mixed confirmations and all four sidecar gates pass. The eight original
upper points remain valid measured FAILs; the multicore mixed 2400/s point
also fails FAPI and refresh sidecar gates. These observations do not by
themselves establish a backend maximum: targeted VU calibration and remaining
scenario boundary measurements are being recorded separately by recipe.

The [current authority](../../../../perf/results/data/capacity/current-capacity.json),
[selected point snapshots](../../../../perf/results/diagnostics/2026-09-28-current-b-selected.json),
[invalid tester probes](../../../../perf/results/diagnostics/2026-09-28-current-b-tester-diagnostics.json),
and [decoder profile](../../../../perf/results/diagnostics/2026-09-28-current-b-decoder-profile.json)
are compact Git evidence. The decoder profile used a warm-up sample with zero
measured completions; it supports parser-equivalence diagnostics, not service
throughput. Invalid probes remain invalid and never become failure upper bounds.

The selected raw point directories and both original mixed confirmation
journals are retained outside Git in `20260928-current-b-evidence.tar.gz`
(812,407,286 bytes, SHA-256
`9567bd099ce4953c836d67b949507ecc13871e7f7171e62243f65f63d78d8783`).
Its separate `20260928-current-b-evidence-manifest.json` hashes 925 archived
files (2,899,273,213 uncompressed bytes). The archive includes the manifest
itself. Both files remain in the owned test deployment and a verified copy is
held in the task workspace; the large raw stream is not committed to Git.
Only selected endpoints and mixed confirmations are in this archive. Other
exploration point summaries remain in the test deployment; invalid probes
have only the compact Git diagnostic record. Earlier short-point journals
were not originally retained as files, though their runtime reconciliation
and range/hash evidence remains in the selected snapshots.
