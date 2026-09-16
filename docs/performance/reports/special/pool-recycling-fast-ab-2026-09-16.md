# Pool RecyclingMethod Verified vs Fast — A/B Diagnosis — 2026-09-16

## 1. Verdict

**ADOPT FAST** — all acceptance criteria met (see §5).

`ManagerConfig.recycling_method` is the only production-code delta under test
(`crates/persistence-postgres/src/pool.rs`): `Verified` (default, `SELECT 1`
ping per checkout) vs `Fast` (transaction/broken-state check only).

- `SELECT $1`/op: 5.01 (cc) / 7.01 (refresh) → **0.00**, exactly equal to
  `pool_acquire`/op — the ping per checkout is eliminated, checkouts unchanged.
- Top-level SQL/op drops by exactly the ping count: cc 15.02→10.01,
  refresh 26.03→19.01. No nested-statement change (cc 0.00, refresh 2.00 both
  modes — refresh's 2 nested/op is the refresh-context validation inside a SQL
  function, not a wire RTT).
- Throughput: **+5.9% … +22.4%**; latency improved or held steady at every reported percentile.
- Failure semantics: backend termination → **0 failed probes**; full PostgreSQL
  container restart → **2 bounded 503s** per path, recovery <0.3s, no restart,
  no partial issuance/rotation.

## 2. Tested Source

| 项 | 值 |
|---|---|
| Base SHA | `9adbb53c`（gh main，PR #211 已合并） |
| A/B 变量 | `pool.rs`: `config.recycling_method = RecyclingMethod::Fast`（Verified 腿 = 未修改默认） |
| 环境 | 同一容器化单机栈（PG 18.6 + Valkey 同机）；两腿各自完整 4 点矩阵顺序执行 |
| 协议 | 15s warmup → gap 排空 → `pg_stat_statements_reset()` + baseline → 60s measure → 排空 → final；activity/locks ~300ms 采样；`pg_stat_statements` dump 含 `toplevel` 列 |

## 3. A/B Matrix（每点 15s warmup + 60s measure，0 errors）

| Point | Mode | ops/s | Δ vs Verified | p50 | p95 | p99 | tl SQL/op | nested/op | SELECT$1/op | acquire/op | pool wait ms |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cc-c8 | Verified | 1739.3 | — | 4 | 7 | 11 | 15.05 | 0.00 | 5.02 | 5.02 | 0.09 |
| cc-c8 | **Fast** | **2128.6** | **+22.4%** | 3 | 6 | 10 | 10.02 | 0.00 | 0.00 | 5.02 | 0.06 |
| cc-c32 | Verified | 5090.0 | — | 6 | 10 | 16 | 15.02 | 0.00 | 5.01 | 5.01 | 0.21 |
| cc-c32 | **Fast** | **5680.8** | **+11.6%** | 5 | 9 | 15 | 10.01 | 0.00 | 0.00 | 5.01 | 0.19 |
| refresh-c8 | Verified | 1101.0 | — | 7 | 10 | 14 | 26.08 | 2.00 | 7.04 | 7.04 | 0.09 |
| refresh-c8 | **Fast** | **1165.7** | **+5.9%** | 6 | 10 | 14 | 19.04 | 2.00 | 0.00 | 7.04 | 0.07 |
| refresh-c32 | Verified | 2959.4 | — | 10 | 16 | 21 | 26.03 | 2.00 | 7.01 | 7.01 | 0.21 |
| refresh-c32 | **Fast** | **3258.4** | **+10.1%** | 9 | 15 | 21 | 19.01 | 2.00 | 0.00 | 7.01 | 0.17 |

c8 is primarily RTT-latency bound, so removing 5/7 checkout pings produces the
largest direct latency benefit. At c32 the workload is closer to WAL/commit
saturation, so throughput gains narrow but remain material. Wait distributions
remain qualitatively unchanged (`LWLock|WALWrite` is still the leading active wait).

## 4. Failure Semantics on Fast

### 4.1 `pg_terminate_backend`

- cc probe: 21 runtime backends terminated → **0 failures**.
- refresh probe: 3 runtime backends terminated → **0 failures**.
- Socket closure is detected by the connection driver; dead pooled objects are
  discarded and new physical connections are established on demand.

### 4.2 PostgreSQL container restart

| Path | Failures | Error | Recovery | Partial state |
|---|---:|---|---|---|
| cc | 2 | HTTP 503 `server_error` | 0.26s after final failure | none |
| refresh | 2 | HTTP 503 `server_error` | 0.27s | none; retrying the same refresh token succeeds |

Failures are bounded and fail closed; NazoAuth reconnects automatically without restart.

### 4.3 Uncovered boundary

A silent half-open TCP path with no FIN/RST was not reproduced by the local
Docker bridge. Under `Fast`, the first real business SQL on such a stale
connection may fail before the connection is discarded. This is accepted here;
no transparent token-issuance retry is introduced.

## 5. Acceptance Criteria

| # | Condition | Result |
|---|---|---|
| 1 | `SELECT $1`/op → ~0 | ✅ 0.00 at all four points |
| 2 | measurable throughput/latency benefit | ✅ +5.9% to +22.4% |
| 3 | normal A/B errors = 0 | ✅ |
| 4 | stale connection cannot produce false success | ✅ |
| 5 | DB failures fail closed | ✅ only bounded 503s observed |
| 6 | no partial issuance/rotation | ✅ refresh retry with same token succeeds |
| 7 | broken connection discarded | ✅ |
| 8 | automatic reconnect | ✅ <0.3s in restart probe |
| 9 | no NazoAuth restart required | ✅ |
| 10 | failures bounded | ✅ 2 per path during PG restart |

## 6. Conclusion

**ADOPT FAST.**

- cc: +11.6% at c32 / +22.4% at c8; removes ~5 zero-business-value wire RTT/op.
- refresh: +10.1% at c32 / +5.9% at c8; removes ~7 zero-business-value wire RTT/op.
- Transparent business retries remain intentionally out of scope.

Next candidates, not implemented here: collapse repeated `oauth_clients` reads;
refresh `parent SELECT + revoke UPDATE → UPDATE ... RETURNING`; family
`EXISTS + INSERT → conditional INSERT`; merge audit preflight SQL without caching results.

## 7. Retained Evidence

The repository keeps only the minimum structured evidence needed to reproduce
this report:

- `perf/results/waitprobe-ab-verified-2026-09-16/` and
  `perf/results/waitprobe-ab-fast-2026-09-16/`: `aggregate.json`, per-point
  `points/*.json`, `runs/*.summary.json`, and `meta.txt`.
- `perf/results/failprobe-2026-09-16/`: focused cc/refresh terminate/restart probes.
- Harness: `perf/wait_ab.sh`, `perf/aggregate_ab.py`, `perf/failprobe.py`, and
  `perf/wait_sampler.py`.

High-frequency activity/lock streams, transient sampler/driver logs, and checksum
manifests are intentionally not retained in Git when their information is already
represented in the structured point/aggregate results.
