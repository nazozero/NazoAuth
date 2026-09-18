# NazoAuth Performance Benchmark — Capacity & Endurance (Corrected)

**Run ID:** `20260918-3ff5030e-cnb-r2`
**Source SHA:** `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b` (GitHub `main`)
**Deployment ID:** `01a0b22e-f95c-7212-8ec4-43a7c3f2ced7`
**Date:** 2026-09-18 (all times UTC)
**Status:** supersedes `docs/performance/reports/2026-09-17-capacity-endurance/report.md` (commit `ad84731a`), which contained identified statistical and methodological errors listed in §1.

## 0. Scope statement

All capacity numbers in this report are **topology-specific**: the application container could schedule onto up to 64 of 192 host CPUs (no CPU pinning), alongside co-located PostgreSQL 18.6, Valkey 8.x, and the k6 load generator on the same Docker network. They are **not** single-instance production-capacity claims for arbitrary deployments. No CPU-pinned (1/2/4-core) measurements were taken; see §11 for the recommended follow-up.

## 1. Corrections vs. the superseded report

| # | Previous (wrong) claim | Corrected |
|---|---|---|
| 1 | "332 logins/s" for `oidc_cold_login_refresh` c8 | 332 was **aggregate HTTP req/s** (≈6 requests per flow). Step=`login` measurement: **40.26 attempted = 40.26 successful login/s** at c8. See §6. |
| 2 | "fapi2_logged_in_high_security-r600 = 2999 ops/s" | The point was ~**600 flow/s ≈ 2999 HTTP req/s** (5 requests per flow). Flow/s ≠ req/s. See §7. |
| 3 | "metadata_jwks 200k req/s" presented as flow capacity | `metadata_jwks` issues **2 requests per iteration**. 200k was aggregate HTTP req/s (~100k metadata + ~100k jwks). See §7. |
| 4 | "全接口压测" (all-endpoints load tested) | Coverage is **55 load-tested / 57 smoke-only / 23 not-load-tested** of 135 discovered endpoints. See §4. |
| 5 | "70% capacity" derived from VU-count ratio | Endurance now uses **constant-arrival-rate at an explicit ops/s target**, not VU ratios. See §8. |
| 6 | "soak produced 381 deadlocks" | deadlocks counter start=end=7 → **delta = 0** in the completed soak. The 381 figure conflated the pre-existing counter value with a delta. See §8.3. |
| 7 | c64 errors attributed to "token rate limiter" without status evidence | Error classification now records `{step,status,err}` per failure plus bounded response-body samples (`ERR_SAMPLE`). See §8.2 for actual causes. |
| 8 | Soak described as passed at ~3530 ops/s | The completed soak **failed**: target miss (2361.8 req/s vs 2500 target), 272,567 dropped iterations, 50.7% HTTP error rate. Root cause analysis in §8.2. |
| 9 | Report claimed Argon2 c6 / FAPI r30 sidecars | Actual script ran Argon2 1 VU / FAPI r60; sidecar summaries are now preserved per workload. |
| 10 | No counter-reset handling (negative pool deltas) | Runner clamps negative deltas and flags `counter_reset` instead of averaging negatives. |
| 11 | Sampler collected 133/133 HTTP 404s (no pool data) | Sampler now sends `Host: 127.0.0.1`; DB-pool acquire/wait counters collected. |

## 2. Environment

| Item | Value |
|---|---|
| Host | AMD EPYC 9K65, ~192 logical CPUs, ~128 GiB RAM |
| Kernel | Linux 5.4.241-1-tlinux4-0025.10 |
| App | `nazoauth-perf-nazoauth-1`, single container, no CPU pin (≤64 CPUs visible) |
| DB | PostgreSQL 18.6 (`nazoauth-perf-postgres-1`) |
| Cache/state | Valkey 8.x (`nazoauth-perf-valkey-1`), maxmemory=0 (unlimited) |
| Load gen | k6 2.2.0 in `nazoauth-perf-perf` image (Python 3.14 runner) |
| Tenant routing | Host-header based; all workload requests pinned via `Host: 127.0.0.1:8000` |

Disabled modules in this deployment (relevant to coverage): OpenID4VCI, OpenID4VP, dynamic client registration, federation, mdoc, native SSO.

## 3. Harness corrections applied this round

- k6 `systemTags` excludes `url`/`iter`/`vu` → no unbounded series from `request_uri`, `jti`, `auth_req_id`, `user_code`.
- `res.request.tags` is not populated in k6 2.x → step derived from check-name prefix; `err_classified{step,status,err}` series materialized via thresholds; bounded `ERR_SAMPLE step=… status=… err=… body=…` per-VU log.
- `handleSummary` exports the full metric tree (`*.k6.json`) plus `*.errors.json` for tagged error series.
- Constant-arrival-rate runs previously discarded all k6 logs to `/dev/null`; they now persist to `<run>.k6log` (this defect hid the soak's failure evidence — fixed before soak #2).
- `vector()` wraps inside a bounded slice; pool sized for constant-vus and constant-arrival-rate executors.
- `PERF_SKIP_SEED=1` lets sidecars reuse shared secrets/vectors without destructive re-seeding.
- Counter deltas clamped at ≥0 with `counter_reset` flag.
- `fail()`-path falsy returns fixed (CIBA); `crypto.subtle.digest` given bytes for DPoP `ath`.
- Seed: tenant mTLS trust anchors cleaned before insert (anchor-cap 503 fixed); `oauth_tokens` detach+delete under `ACCESS EXCLUSIVE` lock (rotation FK fixed); admin session `admin_level=2`; `user_client_grants` pre-seeded with `device_sso`.
- Sampler requests `/__perf/metrics` with `Host: 127.0.0.1` (was 404 for all 133 samples).

## 4. Endpoint coverage — 135 discovered endpoints

| Classification | Count | Notes |
|---|---|---|
| Load-tested | **55** | public/discovery, session (`/auth/me*`, `/check_session/status`), admin reads, SCIM, FAPI resource, device, CIBA, token/par/authorize/introspect/revoke/userinfo |
| Smoke-only | **57** | destructive or one-shot operations, external callbacks, browser-UI handoffs, write/admin mutations — smoke verified, not capacity targets |
| Not load-tested | **23** | modules disabled in this deployment: openid4vci (12), openid4vp (3), dynamic client registration (3), federation (3), mdoc (2) — all return expected 404 |

Evidence: `evidence/endpoint_matrix.json`, `evidence/endpoint_smoke.json` (135/135 smoke responses recorded with status + classification).

## 5. Capacity ladder — clean measurements (0 errors unless noted)

Constant-VU executors; each point ≥45 s after warmup. `ops/s` = completed business operations; `HTTP req/s` = raw requests (a flow may contain several requests). All values on this page are measured, not derived.

### 5.1 Mixed workload (`cap_mixed`: 30% userinfo, 25% client_credentials, 15% authz-code, 15% refresh, 15% token-exchange)

| VUs | ops/s | HTTP req/s | p99 (ms) | errors |
|---:|---:|---:|---:|---:|
| 8 | 935.2 | 1,841.4 | 13.5 | 0 |
| 16 | 1,764.0 | 3,533.8 | 13.0 | 0 |
| 32 | 2,887.9 | 5,566.8 | 18.8 | 0 |
| **64** | **3,310.0** | **6,664.8** | 24.2 | 0 |
| 128 | 3,108.7 | 6,114.8 | 46.0 | 0 |

Clean burst envelope peak: **≈3,310 ops/s** (≈6,665 HTTP req/s) at 64 VUs; c128 shows throughput regression + rising tail — the knee.

### 5.2 Single-path ladders

| Scenario | VU range | Measured plateau (ops/s) | HTTP req/s at plateau | Note |
|---|---|---:|---:|---|
| client_credentials | 8–128 | 3,893.5 (c128) | 5,331.0 | saturation heuristic: <10% growth over 2 doublings |
| token_exchange | 8–128 | 3,531.7 (c64) | 4,772.7 | c128 declines to 3,229.7 |
| authorization_code | 8–128 | 954.3 (c128) | 5,307.3 | still rising slowly at c128 |
| refresh_token | 8–128 | 2,211.2 (c128) | 2,976.7 | plateaus ≥c32 ≈2,095 |
| introspect | 8–128 | 12,447.6 (c128) | 16,810.2 | latency-growth stop |
| revoke | 8–128 | 786.5 (c128) | 5,326.8 | plateau ≥c32 ≈749–787; each op mints+revokes |
| userinfo_pairwise | 8–128 | 30,183.7 (c128) | 40,847.1 | read path |
| public_reads (health/jwks/metadata) | 8–128 | 82,124.6 (c32) | 110,288.8 | declines at c128 |
| session_reads (`/auth/me` etc.) | 8–128 | 32,687.2 (c64) | 43,543.7 | session-cookie auth reads |
| admin_reads | 8 | 2,349.3 (c8) | 3,180.8 | admin_level=2 session; includes trust-anchor PEM |
| scim_reads | 4–16 | ~372–388 | ~505–521 | p99 22→185 ms — knee at c16 |
| device_flow | 4–8 | 328.5 (c8) | 1,891.7 | 23 errors @c8 (0.03%) |
| ciba_flow (bc-authorize→decision→token) | 4–64 | 1,063.7 (c64) | 5,817.1 | still rising; DPoP-constrained |
| fapi_resource (DPoP-bound GET) | 4–32 | 7,465.5 (c32) | 9,764.7 | clean reruns 7,823.7/9,764.7 req/s |

### 5.3 Argon2 password login — separate category (§6)

Intentionally excluded from all "capacity" figures above.

## 6. Argon2 / password login (separate measurement)

`oidc_cold_login_refresh` performs full login → authorize → code → token + refresh per iteration. Only the `login` step is password-hashing-bound (Argon2, server concurrency limit = 8). Measured from `http_reqs{step:login}` and login-step failures:

| VUs | attempted login/s | successful login/s | rejected | HTTP req/s (whole flow) | note |
|---:|---:|---:|---:|---:|---|
| 1 | ~5 | ~5 | 0 | 31.5 | |
| 2 | ~10 | ~10 | 0 | 62.2 | |
| 4 | ~21 | ~21 | 0 | 127.0 | |
| 8 | **40.26** | **40.26** | 0 | 241.5 | clean point |
| 16 | 68.62 | **46.92** | **31.6%** | 324.9 | exceeds limiter → rejections (design behavior, threshold_failed) |

Argon2 capacity ≈ **40 successful logins/s** at this topology. The c16 row shows the limiter rejecting ~1/3 of attempts rather than queueing them — correct protective behavior. These numbers must not be quoted as general NazoAuth throughput.

## 7. Composite flows — flow/s vs HTTP req/s (explicit)

Constant-arrival-rate points; each iteration is a multi-request flow.

| Scenario | target flow/s | measured HTTP req/s | req per flow | status |
|---|---:|---:|---:|---|
| fapi2_logged_in_high_security (PAR+JAR+authorize+decision+token+resource) | 30 | 150.0 | ~5 | passed |
| fapi2_logged_in_high_security | 60 | 299.8 | ~5 | passed |
| fapi2_logged_in_high_security | 120 | 599.7 | ~5 | passed |
| fapi2_logged_in_high_security | 240 | 1,199.5 | ~5 | passed |
| oidc_logged_in_authorization_code | 200 | 799.8 | ~4 | passed |
| oidc_logged_in_authorization_code | 400 | 1,599.4 | ~4 | passed |
| oidc_refresh_only | 500 | 499.9 | ~1 | passed |
| oidc_refresh_only | 1,000 | 999.8 | ~1 | passed |
| authorize_par_session | 200 | 449.2 | — | threshold_failed (login-step Argon2 limit) |
| ciba_private_key_jwt_dpop_poll | 60 / 120 | 120.0 / 240.0 | — | invalid: poll semantics (see §9) |
| same_user_refresh_token_rotation | 200 | 545.0 | — | threshold_failed, 985 dropped iterations |

`fapi2_logged_in_high_security` holds linear scaling to at least 240 flow/s (~1,200 req/s) — flows/s equals the configured rate; HTTP req/s ≈ 5× flows/s.

## 8. Endurance (constant-arrival-rate soaks)

### 8.1 Runs

| Run | Target | Duration | Result |
|---|---|---:|---|
| soak #1 | **2,500 ops/s** `cap_mixed` + sidecars (Argon2 8/s, metadata 200 req/s, FAPI2 30 flow/s) | 7,200 s | **FAILED** — see §8.2 |
| soak #2 | **2,000 ops/s** `cap_mixed` + identical sidecars | 7,200 s | **sustained, zero application errors** — see §8.4 |

### 8.2 Soak #1 failure analysis (evidence: `perf-results/soak-failed-2500/`)

Measured at completion:

- HTTP rate **2,361.8 req/s** vs 2,500 target (target miss); measured op rate 2,453.4 ops/s
- **10,822,821** measured ops, **2,172,427** classified errors, HTTP error rate **50.7%**
- **272,567 dropped iterations**
- Status `threshold_failed`; runner RSS grew **0.36 GB → 4.47 GB**

Failure timeline (per-minute `cap_mN_*` buckets): errors were small for ~10 minutes, then escalated sharply at ≈ minute 11–12.

Root cause (evidence-backed):

1. **Application-side DB-pool saturation.** App pool sampler: `wait_max_ns` rose to **59,999 ms** — the 60 s acquire ceiling — and stayed there. PostgreSQL stayed healthy (33–34 backends, active ≤21, deadlocks delta 0).
2. **Token-issuance dependency failures.** App log (starting ~11 min in): `failed to commit token issuance error=unexpected token dependency failure` → `cap_bootstrap`/token steps ~100% failure; ops aborted before downstream steps.
3. **Load-generator amplification.** Client-side `dial tcp …: connect: cannot assign requested address` — ephemeral-port churn under the failure storm contributed to the req/s shortfall and dropped iterations.
4. **Audit sink back-pressure** was chronic under load (`audit.persistence … queue_full`, ~760k events total incl. earlier runs); a plausible contributor to request-path blocking but not isolated as the sole trigger.

Conclusion: **2,500 ops/s sustained is above this topology's steady-state mixed capacity** even though 60-s bursts reach 3,310 ops/s — write-path (token issuance) sustained throughput is the binding constraint.

Sidecar outcomes (soak #1): metadata `passed`; argon2 `threshold_failed` (limiter rejections — expected); fapi2 produced **0 HTTP requests** (sidecar fixture gap — invalid, see §9).

### 8.3 Dependency evidence (soak #1)

| Counter | Start | End | Delta |
|---|---:|---:|---|
| pg `deadlocks` | 7 | 7 | **0** |
| pg `xact_commit` / `xact_rollback` | recorded | recorded | in `pg_counters_*.txt` |
| valkey `expired_keys` | 2,490,546 | 3,845,674 | +1,355,128 (TTL expiry working) |
| valkey `evicted_keys` | — | — | 0 (maxmemory=0, no evictions) |
| valkey keys live | ~814k | ~1.26M | peak ~2.15M mid-run |
| pool `wait_max` | 334 ms | **59,999 ms** | saturation |
| app RSS | ~135 MB steady | — | no app-side leak observed |
| runner RSS | 0.36 GB | 4.47 GB | metric accumulation under failure storm |

### 8.4 Soak #2 result — 2,000 ops/s × 7,200 s (evidence: `perf-results/soak/`)

Main workload `cap_mixed` at constant-arrival-rate 2,000 it/s:

| Metric | Value |
|---|---:|
| Iterations completed | 14,361,983 (**1,994.7 it/s** — 99.7% of target) |
| Measured ops | 14,309,315 (**1,987.4 ops/s**) |
| HTTP requests | 20,856,153 (**2,896.7 req/s**) |
| Op errors | **0** |
| `http_req_failed` | **0** of 20,856,153 |
| `checks` | 33,794,994 pass / **0 fail** |
| ERR_SAMPLE / Request-Failed lines | **0** |
| Dropped iterations | 38,018 (0.26% — see note) |
| Latency p50 / p95 / p99 | 6 / 28 / 88 ms |
| Status | `target_miss` (dropped_iterations > 0 only) |

The 38,018 dropped iterations (~5.3/s average, evenly spread) are **generator-side**: constant-arrival-rate drops an iteration when no VU is free within its slot — brief per-VU jitter collides with the arrival schedule. They are not application failures: every issued request passed. This run demonstrates **sustained 2,000 ops/s ≈ 60% of the measured clean burst capacity (3,310 ops/s) is stable for 2 hours** on this topology, while 2,500 ops/s is not (§8.2).

Dependency counters (start → end):

| Counter | Start | End | Delta |
|---|---:|---:|---|
| pg `deadlocks` | 7 | 7 | **0** |
| pg `xact_commit` | 190,503,058 | 302,651,444 | +112,148,386 |
| pg `xact_rollback` | 177 | 177 | **0** |
| pg backends / active | 33 / 1–21 | steady | no pool exhaustion |
| valkey `evicted_keys` | — | — | 0 |
| valkey `expired_keys` | — | +~1.4M | TTL churn normal |
| app pool `wait_nanos_total` rate | — | ~0.08 ms/acquire | healthy |
| runner RSS | 0.94 GB | 5.48 GB | metric accumulation — bounded, monitor >2 h |
| app RSS | stable (~135 MB class) | — | no app-side leak |

Sidecars (same 2 h window): argon2 — 47.99 HTTP req/s ≈ 8 login/s, 0 errors, 9 drops (`target_miss` cosmetic); metadata — `passed`, 400 req/s, 0 errors; fapi2 — **invalid** (SKIP_SEED vector pool 1,000 < scenario offset 1,200 → 0 requests issued; standalone supplement `fapi2-r30` post-soak: 149.9 req/s, 0 errors — the flow itself is healthy).

## 9. Invalid / excluded results

| Result | Reason |
|---|---|
| `cap_native_sso_fresh` (all points) | native SSO module disabled in this deployment — `ERR_SAMPLE … Native SSO is disabled` |
| `ciba_private_key_jwt_dpop_poll` r60/r120 | poll-with-`interval` semantics can't drive a complete flow; replaced by `cap_ciba_flow` |
| `same_user_refresh_token_rotation` r200 | rotation-family contention — threshold_failed + dropped iterations |
| `authorize_par_session` r200 | login-step Argon2 limiter (expected at 200 login-attempt/s) |
| fapi2 soak sidecars (#1 and #2) | `PERF_SKIP_SEED` left the shared vector pool at 1,000 < fapi2 scenario offset 1,200 → `vector()` failed every iteration with 0 requests; the standalone r30 supplement and the r30–r240 composite points are the valid FAPI2 evidence |
| Early `cap_fapi_resource` c16 (`invalid_dpop_proof` storm) | transient window; clean reruns passed — original point discarded |
| Early `cap_admin_reads` (~24k 503s) | stale trust-anchor accumulation in seed → fixed; point discarded |
| soak #1 totals | failed run — analysis only, not an endurance claim |

## 10. Resilience / correctness findings (carried + new)

1. **Pool acquire ceiling 60 s**: requests can wait ~60 s for a connection before failing — no shorter server-side deadline (evidence: pool `wait_max_ns` = 59.999 s; one probe observed 206.7 s request hangs in the earlier incident window).
2. **Audit durability**: under sustained high authorization rates the audit durable sink drops events (`queue_full`) — audit loss, not request loss, at moderate rates; at soak #1 rates it coincided with pool saturation.
3. **Unrouted-host responses close connections**: requests with an unknown `Host` get `404 + Connection: close` — under load this churns client ports (generator-side amplification observed).
4. **PostgreSQL checkpoints** remained aggressive under write load (observed ~15 s cadence) — write-path pressure consistent with §8.2.
5. **k6 metric memory**: under a multi-hour failure storm the runner's RSS grew to ~4.5 GB — bounded but material; RSS is sampled every 10 s for app/pg/valkey/runner/sidecars.

## 11. Follow-up recommended

- CPU-pinned capacity runs (1/2/4 cores via cpuset) for deployment-meaningful numbers.
- Increase/timeout-bound DB pool acquire; decouple audit enqueue from token-commit path.
- Distribute load generation across source IPs if sustained rates >~15k req/s are needed.

## 12. Evidence index

`docs/performance/reports/2026-09-18-capacity-endurance/evidence/`

- `endpoint_matrix.json`, `endpoint_smoke.json` — 135 endpoints, classification + smoke status
- `ladder/*/latest.json` + `*.k6.json` + `*.errors.json` — per-point summaries incl. per-step metrics and tagged error series
- `composites/` — composite flow points
- `argon2/` — cold-login ladder + step=login recount (`recount_argon2.py`)
- `soak-failed-2500/` — failed soak #1: summary, k6 metrics, sampler series, RSS series, pg/valkey start/end counters, sidecar artifacts
- `soak/` — soak #2 (2,000 ops/s): same artifact set
- `environment.json` — host/topology/module-state capture
- `proc-stats-2026-09-18.csv` — 10-s process CPU/RSS samples

## 13. Reproduce

```bash
docker compose -f docker-compose.perf.yml up -d            # stack
bash perf/cap_ladder.sh cap_mixed "8 16 32 64 128" 60      # ladder
bash perf/tools/soak_run.sh                               # soak (SOAK_RATE=2000)
python3 perf-results/recount_argon2.py                    # step=login recount
```
