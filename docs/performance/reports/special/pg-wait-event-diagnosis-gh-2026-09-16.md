# PG Wait-Event Diagnosis — Token Write Path on GH main — 2026-09-16

## 1. Executive Summary

- **Tested source**: `main` @ `9adbb53c71571328d1cb57c4af63d121036464f9`（GitHub main，含已合并的 token-issuance / security-state lifecycle 重构）。cnb 仓库 main 已本轮对齐到该 SHA（旧 cnb tip 归档于 `archive/cnb-main-pre-gh-sync`）。
- **结论**：上一轮发现的 `security_audit_chain_state` 单行 tuple 锁瓶颈在新代码上**已消除**——重构把审计事件持久化（`nazo_persist_security_audit_event`，随业务事务提交 + outbox）与链头 append（exporter 批量 `nazo_append_security_audit_chain`）分离，链头锁移出请求路径。
- 新形态：**commit/WAL-write bound + 顺序 RTT 数量 bound**。每业务操作 = 1 个事务；活跃等待首位是挂在 `COMMIT` 上的 `LWLock|WALWrite`（42–53%）；`pg_locks` 等待样本为 **0**；backend 忙率仅 ~44–48%。
- 吞吐（严格 60s 测量窗口，0 错误 0 rollback）：client_credentials 1627→**4573 ops/s**，refresh_token 1017→**3092 ops/s**，两条路径均在本测试包线约 c32 后进入吞吐平台。
- 对比同协议重构前测量（cnb `c44fc1f3`）：cc 264→275、refresh 179→184 ops/s，约 **17 倍吞吐差异**。该差异对应整个已合并的 issuance/lifecycle 重构包；wait-event 数据能证明旧实现的审计链行锁是旧瓶颈，但没有 isolated A/B 将 17x 单独归因于审计链改动。
- 后续带 `toplevel` 的 Verified/Fast A/B 进一步校准了语句口径：Verified 下 cc ≈15 top-level SQL/op；refresh ≈26 top-level SQL/op + 2 nested/op。`SELECT $1` pool ping 分别占 5/7 top-level calls，因此真实业务 wire RTT 约为 cc **10/op**、refresh **19/op**。
- Refresh 的 `pg_advisory_xact_lock`（2/op）保持 0 等待；family 竞争被排除。

## 2. Tested Source & Environment

| 项 | 值 |
|---|---|
| Tested SHA | `9adbb53c71571328d1cb57c4af63d121036464f9`（gh main；PR #211 重构已合并） |
| 对照 SHA | `c44fc1f304ae186aa88470beb8e2d42ec5ef5cc3`（cnb main 旧 tip） |
| 环境 | 同规格单机 Docker Compose（PG 18.6 + Valkey，同机部署）；新一轮容器，无 cargo cache 全新构建 |
| Harness 分支 | `perf/pg-wait-diagnosis-gh-20260916` |

环境修复记录（harness 侧，非生产代码）：

1. `postgres-init` 的 `DO $$` heredoc 被 compose 转义破坏，因此本轮手动执行等效角色 SQL。
2. gh 审计最小权限模型要求 runtime role 不得直接持有 ledger 表权限；直接 `GRANT ALL TABLES` 会被 privilege preflight 拒绝。
3. `perf/env.yaml` 补齐 `SIGNING_KEY_ENCRYPTION_KEY_ID` 与 32-byte base64url wrapping key。

PostgreSQL：`track_io_timing=on`、`track_wal_io_timing=on`、`pg_stat_statements.track=all`。

## 3. Methodology

15s warmup → gap 排空 → `pg_stat_statements_reset()` + `pg_stat_database` / `pg_stat_wal` / `pg_stat_io` baseline → 60s measure → 停发排空 → final snapshot；`pg_stat_activity` / `pg_locks` ~300ms 采样。Refresh measurement 内只执行连续 `refresh → successor` rotation；cc 每 op 是一次 `/token`。

## 4. Per-Point Results

| Point | ops | ops/s | p50 | p95 | p99 | err | observed stmt/op † | SQL ms/op | xact/s* | WAL B/op | fsync/op | fsync ms/op | pool wait ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cc-c8 | 97617 | 1627.0 | 4 | 8 | 13 | 0 | 15.05 | 0.43 | 15749 | 1944 | 4.2 | 0.50 | 0.08 |
| cc-c16 | 176035 | 2933.9 | 5 | 8 | 13 | 0 | 15.03 | 0.46 | 28223 | 2018 | 4.3 | 0.29 | 0.09 |
| cc-c32 | 273608 | 4560.1 | 6 | 10 | 16 | 0 | 15.02 | 0.51 | 43821 | 2130 | 4.2 | 0.20 | 0.25 |
| cc-c64 | 274355 | 4572.6 | 13 | 19 | 25 | 0 | 15.02 | 0.51 | 44116 | 2634 | 4.2 | 0.21 | 1.60 |
| refresh-c8 | 61005 | 1016.8 | 7 | 11 | 16 | 0 | 28.08 | 1.68 | 13083 | 6305 | 6.0 | 0.66 | 0.08 |
| refresh-c16 | 114660 | 1911.0 | 8 | 12 | 16 | 0 | 28.04 | 1.46 | 24521 | 9039 | 6.1 | 0.43 | 0.09 |
| refresh-c32 | 183220 | 3053.7 | 10 | 15 | 21 | 0 | 28.03 | 1.63 | 41806 | 7461 | 5.9 | 0.28 | 0.24 |
| refresh-c64 | 185522 | 3092.0 | 20 | 29 | 36 | 0 | 28.03 | 1.66 | 39627 | 8128 | 5.9 | 0.27 | 1.65 |

\* `xact_commit` includes autocommit statements such as pool pings; explicit business BEGIN/COMMIT counting is 1.0/op.
† The original diagnosis dump did not capture the `toplevel` column. The later A/B did: cc's ~15 calls are top-level; refresh's ~28 observed calls split into ~26 top-level + ~2 nested. With Verified pings removed from the accounting, application business wire RTT is ~10/op for cc and ~19/op for refresh.

c32→c64 concurrency doubles while throughput rises only ~0.3% (cc) / ~1.2% (refresh) and median latency roughly doubles, which is the tested-envelope saturation signal used here.

## 5. Wait-Event Analysis

### 5.1 Active wait samples

| wait_event_type \| event | cc-c64 | refresh-c64 |
|---|---:|---:|
| `LWLock\|WALWrite` | **53.3%** | **42.9%** |
| active, no wait | 23.9% | 37.0% |
| `Client\|ClientRead` | 15.4% | 13.7% |
| `IO\|WalSync` | 7.2% | 5.7% |
| `Lock\|*` | **0%** | **0%** |

`pg_locks` showed zero waiting samples. The previous singleton tuple-lock bottleneck is absent.

### 5.2 Top SQL by total execution time

cc-c64:

| calls/op | Δtotal ms | mean ms | statement |
|---:|---:|---:|---|
| 1.0 | 49,402 | 0.180 | `nazo_persist_security_audit_event(...)` |
| 1.0 | 30,857 | 0.112 | `nazo_security_audit_shared_privilege_preflight(...)` |
| 1.0 | 28,601 | 0.104 | `INSERT oauth_token_issuances` |
| 1.0 | 12,510 | 0.046 | full `oauth_clients` read |
| 1.0 | 8,379 | 0.031 | `oauth_clients.is_active` read |
| 5.0 | 1,617 | 0.001 | `SELECT $1` pool ping |

refresh-c64:

| calls/op | Δtotal ms | mean ms | statement |
|---:|---:|---:|---|
| 1.0 | 88,881 | 0.479 | `INSERT oauth_tokens` |
| 1.0 | 77,825 | 0.419 | revoke `UPDATE oauth_tokens` |
| 2.0 | 52,005 | 0.140 | `nazo_persist_security_audit_event(...)` |
| 1.0 | 22,966 | 0.124 | `INSERT oauth_token_issuances` |
| 1.0 | 19,215 | 0.104 | audit privilege preflight |
| 2.0 | 833 | 0.002 | `pg_advisory_xact_lock` |

No single business statement dominates. The cost is additive across sequential wire calls plus commit/WAL serialization.

### 5.3 `SELECT $1`: pool recycling ping

Across all eight wait-diagnosis points, `SELECT $1` calls/op matches `db_pool.acquire_count`/op to three decimals: cc ≈5.01/op and refresh ≈7.01/op. This identifies the query as diesel-async's default `RecyclingMethod::Verified` checkout ping.

The subsequent isolated A/B (`pool-recycling-fast-ab-2026-09-16.md`) validates the hypothesis: switching only to `RecyclingMethod::Fast` removes those calls exactly and improves throughput without changing checkout counts.

## 6. Diagnosis

1. **Current write-path shape**: c8→c32 is primarily sequential DB RTT latency bound; c32→c64 moves into WAL/commit serialization pressure.
2. **Client Credentials**: Verified baseline has ~15 top-level wire calls/op, of which ~5 are pool pings; application business wire calls are ~10/op.
3. **Refresh**: Verified baseline has ~26 top-level wire calls/op plus ~2 nested calls; ~7 top-level calls are pool pings, leaving ~19 application business wire calls/op.
4. **Shared bottleneck**: sequential wire latency + commit WAL path; the old shared audit-chain tuple lock is gone.
5. **Measured redundant work**: pool ping, repeated `oauth_clients` reads, and several mergeable refresh state operations appear in the hot path.
6. **Next candidates**: keep `Fast`; collapse repeated client-secret/client reads; consider `parent SELECT + revoke UPDATE → UPDATE ... RETURNING`; consider conditional family insert. Audit preflight remains fail-closed and should not be result-cached.

## 7. Scope and Limitations

- ops/s is `cap_measure_ops / 60s` for the strict measurement window.
- This is a synthetic single-host Docker benchmark, not a universal production capacity claim.
- CPU attribution on this host was not reliable enough to drive the diagnosis.
- The ~17x pre/post-refactor difference is a package-level comparison, not an isolated audit-chain A/B.

## 8. Retained Evidence

`perf/results/waitprobe-matrix-gh-2026-09-16/` retains `aggregate.json`, per-point `points/*.json`, `runs/*.summary.json`, and `meta.txt`. These structured files contain the baseline/final PG snapshots and aggregated wait/lock/statement data needed to review the conclusions.

High-frequency activity/lock streams, transient sampler/driver logs, and checksum manifests are intentionally not retained in Git when their information is already represented in the structured point/aggregate results.
