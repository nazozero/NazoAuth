# NazoAuth Performance & Capacity Test — 2026-09-17

Full-interface, capacity-ladder, and endurance benchmark of NazoAuth `main`.

## Executive Summary

- Tested source: `main` @ `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b`
  (GitHub `nazozero/NazoAuth`). GitHub, CNB mirror, and benchmark checkout
  were verified identical before testing.
- **All 135 externally exposed HTTP endpoints** were discovered from the
  registered route table, smoke-tested, and classified. No unexplained
  endpoint remains (`evidence/endpoint_matrix.json`).
- **Maximum sustainable mixed-workload capacity (non-Argon2): ~3,600
  measured flow-operations/s** (`cap_mixed` c32: 3,631 ops/s, 0 errors,
  ≈6,309 HTTP req/s aggregate, p99 = 30 ms). Saturation onset at c64
  (5,114 ops/s, 10.6–10.7 % errors concentrated on token-mint steps —
  consistent with the token rate limiter engaging).
- **Password/Argon2 login is reported separately**: it is intentionally
  CPU-expensive and concurrency-guarded. It reached **332 logins/s at c8
  (0 errors)** and saturated at c16 (419 ops/s, 41 % rejected). This is
  **not** NazoAuth's overall capacity.
- **Read/cache paths are far higher**: userinfo ~40.8k ops/s, metadata +
  JWKS ~200k req/s, introspection 8.2k ops/s at c8 (0 errors). These are
  reported distinctly and must not be conflated with write-path capacity.
- **Endurance**: the mixed workload ran **1 h 46 m at ~3,530 ops/s
  (22,482,541 completed iterations, 0 interrupted)** with flat app RSS
  (~135 MB) and stable latency, then a **~5.4 min infrastructure
  dependency stall** occurred (PostgreSQL and Valkey simultaneously
  reported `Unavailable`; the in-network sampler's own `psycopg.connect`
  hung for the same window). The load generator was concurrently at
  **~87–91 GB RSS** (k6 metric-cardinality accumulation from per-request
  unique tags) and exited at 21:40:24Z — a load-generator/host-memory
  event, not an application crash. The application recovered immediately
  (probe back to 200/6–8 ms) and a post-incident rerun delivered 2,208
  ops/s with 0 errors.
- CPU was **not** the bottleneck at the sustainable point (~10–13 of 64
  allowed cores at plateau). PostgreSQL showed sustained write pressure
  (checkpoints every ~15 s; **381 deadlocks** observed on the `oauth`
  database over the run) — the first degradation signal under heavy
  write-mix. DB-pool waits were negligible at sustainable load
  (avg 0.052 ms).

## Source Identity

| Item | Value |
|------|-------|
| Repository | https://github.com/nazozero/NazoAuth |
| Branch | `main` |
| GitHub main SHA | `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b` |
| CNB mirror SHA | `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b` (fast-forward only) |
| Benchmark checkout SHA | `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b` |
| Deployment ID | `01a0b080-7bd7-7990-b1bd-8f4d94792a8d` |
| Run ID | `20260917-3ff5030e-cnb` |

The committed tree contains perf-harness changes only (fixtures,
scenarios, samplers, one compose escaping fix). **No production code was
modified**, so results reflect `main` exactly.

## Environment

- Host: CNB container, kernel `5.4.241-1-tlinux4-0025.10`, nested Docker.
- CPU: AMD EPYC 9K65 (192 host cores; benchmark cgroup allowance
  **64 logical CPUs**). App plateau consumption ~10–13 effective cores —
  CPU headroom was large at the sustainable point.
- Memory: 128 GiB host.
- Stack (single `docker-compose.perf.yml` deployment): NazoAuth release
  binary, PostgreSQL 18.6, Valkey 8.1.9, k6 runner on the same Docker
  network (`perf_net`, `172.19.0.0/16`).
- Runtime env of note: `TRUSTED_PROXY_CIDRS=172.16.0.0/12`,
  `MTLS_CERTIFICATE_SOURCE=rfc9440`, Argon2id (19 MiB, t=2, p=1) with a
  semaphore limit of **8** and queue timeout 100 ms → `503
  temporarily_unavailable` + `Retry-After: 1` on saturation.
- Container-level `docker stats`/cgroup sampling is unavailable in this
  nested environment (delegated cgroups are not visible); process CPU and
  RSS were sampled by aggregating `/proc/<pid>/stat` inside each
  container instead.

## Test Methodology

1. Sync GitHub `main` → CNB → checkout; record all three SHAs.
2. Discover every registered route from source (`Route::` registrations +
   module-gated route tables) → endpoint matrix.
3. Seed fixtures (`perf/seed.py`): users, OAuth clients, grants
   (incl. `device_sso`), JAR/DPoP/mTLS/FAPI material, replay-safe flow
   vectors (min 1,200).
4. Smoke every endpoint; classify 200/3xx/401/403/404 by module gating.
5. Constant-VU capacity ladders (75 s per point, `PERF_PROFILE=capacity`)
   + constant-arrival-rate ladders for PAR/FAPI2/introspect/revoke.
6. Independent Argon2 login ladder (c1→c16).
7. Sustained mixed workload (~70 % of observed sustainable point) with
   sidecar traffic (Argon2 c6, metadata, FAPI2 r30), 10 s dependency
   sampler (pg/pg_stat/valkey/pool), 3 s process sampler, 30 s HTTP
   probe.
8. Post-incident validation run.

**Units**: `ops/s` = measured business operations per second (one k6
iteration may contain several HTTP requests); `HTTP req/s` = raw request
rate. Both are reported where available. `flow/s` ≈ `ops/s` here.

## Endpoint Coverage

- 135 external endpoints discovered and recorded
  (`evidence/endpoint_matrix.json`), grouped into 7 modules:
  core OAuth/OIDC, FAPI security, CIBA, device flow, WebAuthn/passkeys,
  dynamic client registration, admin/diagnostic.
- Smoke result classes: reachable-200, redirect (browser/UI hand-off,
  e.g. `/device`, `/ciba/{id}` — connection refused only because the
  UI redirect target is unreachable inside the container network),
  auth-gated 401/403, method-404 for module-disabled routes
  (openid4vci/vp, native-SSO dependent paths), and expected
  invalid-payload 4xx for POST validators.
- Endpoints not eligible for capacity testing (destructive admin ops,
  one-shot initialization, UI hand-off pages, external-callback paths)
  are marked `NOT LOAD TESTED` in the matrix with reason and smoke
  status — no endpoint is unexplained.

## Load Model

| Scenario | Executor | Steps per op |
|----------|----------|--------------|
| cap_client_credentials | constant-vus | token (client_credentials) |
| cap_refresh_token | constant-vus | token (refresh) |
| cap_token_exchange | constant-vus | token (exchange) |
| cap_userinfo_pairwise | constant-vus | userinfo |
| cap_authorization_code | constant-vus | PAR → authorize → decision → redeem |
| cap_mixed | constant-vus | weighted mix of the above + SSO/device |
| cap_introspect / cap_revoke | constant-vus | bootstrap + introspect / revoke |
| mtls_client_credentials | constant-vus | token w/ RFC 9440 mTLS |
| par_signed_request_object | constant-arrival-rate | PAR + JAR verify |
| fapi2_par_jar_private_key_jwt_dpop | constant-arrival-rate | PAR+JAR+PKJ+DPoP (incl. login) |
| fapi2_logged_in_high_security | constant-arrival-rate | warm-session FAPI2 token path |
| authorize_par_session / introspect_opaque_refresh_token / revoke_refresh_token | constant-arrival-rate | full login-bound compound flows |
| oidc_cold_login_refresh | constant-vus | cold login + code + refresh (Argon2) |
| metadata_jwks | constant-vus | discovery + JWKS |

## Why Password/Argon2 Is Tested Separately

Password verification uses Argon2id (19 MiB, t=2, p=1) behind a
semaphore of 8 with a 100 ms queue timeout. Excess concurrency receives
`503 temporarily_unavailable` + `Retry-After: 1` by design — a
deliberate overload guard, not a failure of token throughput. Any
scenario embedding login is therefore bounded by this guard, which is
why `cap_mixed`/token scenarios avoid passwords and why login numbers
must never be quoted as "NazoAuth capacity".

## Baseline Benchmarks & Capacity Discovery

Sustainable = 0 % measured errors + flat p99 + no pool starvation across
the 75 s point. All numbers below are measured.

| Scenario | Load | ops/s | HTTP req/s | Errors | p50 | p95 | p99 | Result |
|----------|------|-------|-----------|--------|-----|-----|-----|--------|
| cap_client_credentials | c32 | 4,833 | 4,833 | 0 | — | 8 ms | 13 ms | plateau |
| cap_client_credentials | c64 | 4,951 | 4,951 | 0 | — | 16 ms | 21 ms | plateau peak |
| cap_client_credentials | c128 | 4,792 | 4,792 | 0 | — | 30 ms | 38 ms | plateau |
| cap_refresh_token | c32 | 2,794 | 2,794 | 0 | — | 14 ms | 18 ms | plateau |
| cap_refresh_token | c64 | 2,743 | 2,743 | 0 | — | 27 ms | 34 ms | plateau |
| cap_refresh_token | c128 | 2,714 | 2,714 | 0 | — | 50 ms | 61 ms | plateau |
| cap_token_exchange | c64 | 4,857 | 4,857 | 0 | — | 14 ms | 18 ms | plateau peak |
| cap_token_exchange | c128 | 4,570 | 4,570 | 0 | — | 31 ms | 37 ms | plateau |
| cap_userinfo_pairwise | c64 | 40,754 | 40,754 | 0 | — | 2 ms | 3 ms | read path peak |
| cap_userinfo_pairwise | c128 | 38,691 | 38,691 | 0 | — | 4 ms | 6 ms | read path |
| cap_authorization_code | c64 | 1,238 | ≈4,950 | 0 | — | 51 ms | 75 ms | write-mix knee |
| cap_authorization_code | c128 | 1,292 | ≈5,170 | 0 | — | 104 ms | 177 ms | near saturation |
| **cap_mixed** | **c32** | **3,631** | **6,309** | **0** | **5 ms** | **23 ms** | **30 ms** | **sustainable** |
| cap_mixed | c64 | 5,114 | — | 85,667 (10.6–10.7 % on token steps) | — | 37 ms | 46 ms | **saturation onset** |
| cap_introspect | c8 | 8,194 | 8,194 | 0 | — | 1 ms | 1 ms | clean |
| cap_introspect | c32 | 22,171 | 22,171 | 366,160 (18.2 % introspect step) | — | 2 ms | 2 ms | saturated (throttled) |
| cap_revoke | c32 | 925 | 925 | 0 | — | 35 ms | 51 ms | clean |
| mtls_client_credentials | c32 | 5,712 | 5,712 | 0 | — | 7.7 ms | 10.6 ms | clean |
| mtls_client_credentials | c64 | 5,959 | 5,959 | 0 | — | 13.9 ms | 17.3 ms | plateau peak |
| mtls_client_credentials | c128 | 5,768 | 5,768 | 0 | — | 27.7 ms | 33.4 ms | plateau |
| par_signed_request_object | r1200 | 1,200 | 1,200 | 0 | — | 1.0 ms | 1.4 ms | clean |
| fapi2_logged_in_high_security | r600 | 2,999 | 2,999 | 0 | — | 8.3 ms | 12.5 ms | clean |
| metadata_jwks | c64 | 200,473 | 200,473 | 0 | — | 0.4 ms | 0.7 ms | read peak |

`cap_mixed` c32 detailed step latencies: `par_oidc` p95 6.3 ms,
`token_client_credentials` p95 12.4 ms, `token_exchange` p95 14.0 ms,
`token_refresh` p95 20.1 ms, `userinfo` p95 3.8 ms,
`token_authorization_code` p95 18.2 ms, `authorize` p95 5.9 ms,
`authorize_decision` p95 19.0 ms — at c64 the ~10.6–10.7 % error share
appears identically on `par_oidc`, `token_client_credentials`,
`token_exchange`, and `userinfo` (token-mint path), while `authorize`
and `token_refresh` stayed ≈0 % — consistent with the token rate
limiter engaging, not with dependency exhaustion.

### Points that could not produce a clean capacity claim

| Scenario | Outcome | Cause (step-level evidence) |
|----------|---------|------------------------------|
| authorize_par_session (arrival r200–r2000) | threshold_failed | `login` step error up to 95 % at p99 ≈ 254 ms — Argon2 guard saturation, not PAR/authorize (those steps: 0 %, p99 ≈ 2.5 ms) |
| fapi2_par_jar_private_key_jwt_dpop | threshold_failed | same login-bound guard; PAR/JAR/DPoP steps healthy |
| introspect_opaque_refresh_token (arrival) | threshold_failed | bootstrap login-bound steps dominate errors |
| revoke_refresh_token (arrival r100–r600) | threshold_failed | login step error 76 %, pool wait avg 77 ms during bootstrap contention; `revoke` step itself 0 % errors |
| ciba_private_key_jwt_dpop_poll | invalid as capacity | pending-decision polling semantics made checks fail by construction; CIBA endpoints were smoke-tested instead |
| cap_native_sso_fresh | not a capacity claim | Native SSO runtime module disabled in this deployment |
| fapi2_logged_in_high_security constant-vus points, metadata constant-vus points | no_summary | runner exited before summary write; arrival-rate points above are the valid FAPI2/metadata measurements |

## Argon2 Login Results (separate category)

| Concurrency | Login-flow ops/s | Errors | Login p50 | Login p95 | Login p99 | Result |
|-------------|------------------|--------|-----------|-----------|-----------|--------|
| c1 | 48.3 | 0 | ~105 ms | 105 ms | 108 ms | clean |
| c2 | 92.8 | 0 | — | 111 ms | 114 ms | clean |
| c4 | 177.7 | 0 | — | 116 ms | 119 ms | clean |
| c8 | 332.5 | 0 | — | 124 ms | 128 ms | clean — max measured clean |
| c16 | 419.1 | 41.3 % of login step | 154 ms | 253 ms | 267 ms | saturated — queue-timeout 503s |

Observations: throughput scales linearly to the semaphore bound (~8
parallel hashes ≈ ~60 ms each ⇒ ~330/s clean). At c16 the guard rejects
41 % (fast `503` + `Retry-After: 1`, p99 267 ms) rather than queueing —
the intended fail-fast behavior. Non-login endpoints stayed healthy
during login saturation (the c16 `token_authorization_code`/`refresh`
steps: 0 % errors).

## Sustained Load Test (soak)

- Config: `cap_mixed` at 24 VUs (~70 % of the c32 sustainable point) +
  sidecars (Argon2 c6, metadata, FAPI2 r30), samplers every 3 s (proc)
  / 10 s (pg, valkey, pool) / 30 s (HTTP probe), target 2 h 40 m.
- **Stable phase (19:48:58 → 21:35:08 UTC, ~1 h 46 m)**: 22,482,541
  completed iterations, 0 interrupted; ≈3,530 ops/s sustained;
  probe 200 at 5–8.8 ms throughout; app RSS 138.5 → 126.2 MB (no growth,
  actually declined); pg backends stable at 33–34; no `pg_err`/
  `app_err` sampler entries.
- **Incident (21:35:08 → 21:40:48 UTC, ~5.4 min)**: application logged
  `repository unavailable`, `transient state is unavailable`,
  `failed to store request object jti`, PAR `503`s, CIBA-claim and
  tenant-cache-update failures. Probe: `503` (7.6 s) → timeout (15 s) →
  **one request hung 206.7 s** → recovered to `200` / 7.8 ms. The
  in-network dependency sampler could not connect to PostgreSQL for the
  same 5 min 19 s (its own `psycopg.connect` hung — pg and valkey stayed
  `Up`/healthy per docker). Because both dependencies plus an external
  client stalled simultaneously, this is classified as an
  **infrastructure-level connectivity stall** (nested-docker overlay /
  host memory pressure), not an application crash: the app process
  stayed up, never restarted, and immediately resumed serving.
- **Load-generator factor**: the k6 runner container reached
  **~87–91 GB RSS** (3.6 GB → 87 GB linear growth over 1 h 46 m —
  metric-series accumulation from per-request unique tags such as
  `request_uri`/JTIs), plausibly triggering host memory pressure
  coincident with the stall; the k6 process exited at 21:40:24Z before
  writing a summary (`k6 scenario failed before writing summary:
  capacity/cap_mixed`). Iterations froze at 22,482,541.
- **Recovery**: at 21:40:48 the probe returned to 200/7.8 ms and a
  post-incident `cap_mixed` c8 rerun measured **2,208 ops/s, 0 errors,
  p95 8 ms** — the server returned to full health with no restart.
- Verdict: **1 h 46 m of verified-stable sustained load**; the run did
  not complete the planned 2 h 40 m due to load-generator memory
  exhaustion plus a correlated connectivity stall — reported as
  interrupted, not as a clean pass. Server-side evidence (flat RSS,
  stable latency, immediate recovery) shows no app-level instability in
  the stable window.

## Latency / Resource Trends (soak)

- ops/s: ~3,500–3,700 steady, no throughput drift before the incident.
- probe latency: 5.0–8.8 ms band for 1 h 46 m (no drift).
- app RSS: 138.5 → 126.2 MB — flat/declining, no leak observed.
- pg RSS ~4.5 GB stable; pg active backends 8–26 oscillating.
- valkey RSS 0.89 → 3.30 GB (token/session state accumulation +
  `expired_keys` 7.5 M — TTL churn working; `maxmemory=0`, no evictions).
- runner RSS grew ~24 GB/h to ~91 GB — load-generator-side growth
  (metric cardinality), the dominant observed resource risk.

## CPU / Memory

- App CPU: ~10–13 effective cores at plateau points (proc-jiffies
  sampling), ~19 cores under full soak mix — far below the 64-core
  allowance. **CPU is not the bottleneck** at sustainable load.
- App RSS: ~135 MB steady-state across all ladders and the soak.
- Runner (k6): the only process with unbounded growth (see soak).
- No cpuset/taskset pinning was applied; Docker default scheduling on
  64-core allowance.

## PostgreSQL

- Sustainable point (`cap_mixed` c32): 6,181,356 statement calls,
  mean 0.05 ms/call, ≈13.06 statements per HTTP request; pool acquire
  avg wait 0.052 ms, max observed 1.9 s (transient).
- Soak totals: ~258 M committed xacts, 88.9 M tuples inserted,
  blks_hit/read ratio ≈ 98.4 %; **deadlocks = 381** (concurrent
  token-family write contention — worth follow-up but did not surface
  as client-visible errors at sustainable load).
- Checkpoint pressure: `checkpoints are occurring too frequently (15 s
  apart)` throughout heavy write mix — recommend `max_wal_size` tuning
  for production; not client-visible in-window.
- Pool (`__perf/metrics`): acquire_count ~49.4 M cumulative,
  wait max 468 ms, avg ≈ 0.4 ms — **no pool saturation at sustainable
  load**; the revoke-arrival point briefly showed avg wait 77 ms during
  login-guard contention.
- PostgreSQL was **not** the bottleneck at sustainable load; it is the
  first subsystem showing stress signals (WAL/checkpoint churn,
  deadlocks) under heavy write mix.

## Valkey

- Sustainable point: 2,240,134 commands processed, 1,095,351 hits /
  158 misses (99.99 % hit ratio), 8,111 expired, ~90 k keys.
- Soak: 274 M commands, 131.7 M hits, mem 3.3 GB, 7.5 M expired keys.
- One startup warning `Memory overcommit must be enabled!` noted —
  environmental, no observed impact.
- **Not a bottleneck.**

## Errors

- Sustainable points: 0 measured errors everywhere except the two
  documented saturation cases.
- Saturation signature is consistent and specific: ~10.6–10.7 % on
  token-mint steps at c64 (token rate limiter), and Argon2-guard `503`s
  on login-bound scenarios.
- The 21:35 incident produced `503`s then request hangs up to 206.7 s —
  indicating requests lack a hard deadline when dependencies stall;
  queued pool acquisition appears to wait indefinitely (resilience
  finding, see Bottleneck Analysis).
- `audit.persistence` emitted `queue_full` (audit sink dropped events
  under sustained throughput) — observability loss, not request
  failures, but worth noting.

## Bottleneck Analysis

1. Token-mint rate limiting is the first wall hit on the mixed write
   path (uniform ~10.7 % across token steps at c64).
2. Argon2 semaphore (8) bounds all login-bearing flows at ~330–420
   login-flows/s — by design.
3. PostgreSQL write path (WAL/checkpoint churn, 381 deadlocks) is the
   next stress layer after rate limits — headroom exists but is
   thinner.
4. CPU, pool, and Valkey all showed ample headroom.
5. Resilience finding: during the 5.4 min dependency stall, requests
   hung up to ~207 s rather than failing fast — there is no apparent
   request-level deadline covering dependency stalls; recommend a
   pool-acquire/dependency timeout bound.
6. Load-generator ceiling: k6 metric cardinality grew RSS ~24 GB/h —
   future soaks should reduce tag cardinality or cap `http_req` series.

## Maximum Sustainable Capacity

- Mixed representative workload: **~3,600 ops/s** (≈6,300 HTTP req/s)
  at c32 — measured, error-free, flat latency.
- Single-path plateaus: client_credentials ≈4.9k ops/s; token_exchange
  ≈4.9k ops/s; mTLS client_credentials ≈6.0k ops/s; refresh ≈2.8k ops/s;
  authorization_code ≈1.3k flows/s (≈5.2k req/s); PAR/JAR ≥1.2k/s clean;
  FAPI2 logged-in ≥3.0k/s clean; introspect ≥8.2k ops/s clean (c8);
  metadata/JWKS ~200k req/s (read path).

## Peak Observed Capacity

- cap_mixed c64: 5,114 ops/s (with 10.7 % throttled errors — above
  sustainable).
- cap_userinfo_pairwise c64: 40,754 ops/s; metadata_jwks c64: 200,473
  req/s — read-path peaks.

## Recommended Sustained Range

Plan for **~2.5–3.0k mixed ops/s** (≈70–80 % of the measured 3.6k
sustainable point) per single app instance in this topology, keeping
Argon2 login concurrency within the guard.

## Stability Findings

- No app memory leak, no latency drift, no throughput decay over 1 h 46 m.
- One infrastructure dependency stall (~5.4 min) with immediate clean
  recovery; documented in `evidence/soak/`.
- Audit-sink `queue_full` under sustained load — durable audit is
  lossy at this throughput.
- PG deadlock counter (381) under heavy write mix — non-fatal but real.

## Limitations

- Nested-docker host: no delegated cgroups (container stats sampled via
  /proc aggregation); the 5.4 min connectivity stall's root cause is
  environmental and not fully isolated — flagged honestly rather than
  attributed to the app.
- The soak did not reach its 2 h 40 m target (generator memory
  exhaustion) — endurance claim is bounded to 1 h 46 m.
- CIBA pending-decision polling is smoke-validated only; its capacity
  scenario was semantically invalid and is not reported as a result.
- Some constant-vus points (fapi2 constant-vus, `metadata` typo points)
  exited before summary write — preserved as `no_summary` run logs.
- DCR endpoint returns 404 with module state as deployed; passkey and
  browser hand-off routes are redirect-validated only.

## Evidence Index

```
docs/performance/reports/2026-09-17-capacity-endurance/
├── report.md                        ← this file
├── ladder_summary.json              ← 76 aggregated points incl. steps/pg/pool/valkey
└── evidence/
    ├── endpoint_matrix.json         ← all 135 endpoints + classification
    ├── endpoint_smoke.json          ← raw smoke results
    ├── environment.json             ← host/runtime/module capture
    ├── source-identity.md           ← triple-SHA verification
    ├── point_resources.json         ← per-point app/pg/vk resource aggregates
    ├── ladder/*.summary.json        ← k6 summaries for representative points
    └── soak/
        ├── soak_summary.json        ← soak run + incident classification
        ├── probe_timeline.json      ← 30 s probes incl. 503/timeout/206.7 s rows
        ├── soak_metrics_downsampled.json  ← pg/valkey/pool @ ~60 s + all incident rows
        ├── proc_stats_downsampled.csv     ← per-container CPU jiffies + RSS
        ├── incident_app_filtered.log      ← 38 app log lines, 21:35-21:36 window
        ├── incident_postgres.log          ← checkpoint churn evidence
        ├── soak_wrapper.log         ← orchestration timeline
        └── main_run_tail.log        ← frozen-iteration + runner-exit tail
```

## Reproduction Commands

```bash
# 1. checkout main @ 3ff5030e038ca5de16226c74f8e5759d4ec2cd1b
# 2. stack
docker compose -f docker-compose.perf.yml up -d postgres valkey keyset migrate nazoauth
# 3. capacity point (example: mixed c32)
docker compose -f docker-compose.perf.yml run --rm --no-deps \
  -v $PWD/perf-results/cap_mixed-c32:/out \
  -e PERF_RESULTS_DIR=/out -e PERF_TENANT_HOST=127.0.0.1:8000 \
  -e PERF_DEPLOYMENT_ID=<from valkey: nazo:state:v1:<dep>:*> \
  -e PERF_PROFILE=capacity -e PERF_SCENARIO=cap_mixed \
  -e PERF_EXECUTOR=constant-vus -e PERF_VUS=32 -e PERF_FLOW_VUS=32 \
  -e PERF_PRE_ALLOCATED_VUS=32 -e PERF_MAX_VUS=32 \
  -e PERF_DURATION=75s -e CAP_WARMUP_MS=10000 -e PERF_USER_COUNT=64 perf
# 4. soak: perf/tools/soak_run.sh (main + sidecars + samplers)
# 5. aggregate: perf/tools/aggregate_points.py
```

*Historical note*: the July 2026 pre-release capacity matrix
(`reports/main|extended`, since removed as superseded) is not a statement
about this `main` revision; the current matrix lives in
`../../performance-capacity-curve.md`.
