# PG Wait-Event Diagnosis — Token Write Path on GH main — 2026-09-16

## 1. Executive Summary

- **Tested source**: `main` @ `9adbb53c71571328d1cb57c4af63d121036464f9`（GitHub main，含已合并的 token-issuance / security-state lifecycle 重构）。cnb 仓库 main 已本轮对齐到该 SHA（旧 cnb tip 归档于 `archive/cnb-main-pre-gh-sync`）。
- **结论**：上一轮发现的 `security_audit_chain_state` 单行 tuple 锁瓶颈在新代码上**已消除**——重构把审计事件持久化（`nazo_persist_security_audit_event`，随业务事务提交 + outbox）与链头 append（exporter 批量 `nazo_append_security_audit_chain`）分离，链头锁移出请求路径。
- 新形态：**commit/WAL-write bound + 顺序 RTT 数量 bound**。每业务操作 = 1 个事务（BEGIN/COMMIT 恰为 1.0/op）、15（cc）/28（refresh）条顺序 SQL；活跃等待首位是挂在 `COMMIT` 上的 `LWLock|WALWrite`（42–53%）；`pg_locks` 等待样本为 **0**；backend 忙率仅 ~44–48%，说明单 op 延迟（RTT 串 + commit）而非 PG 总算力是当前限制。
- 吞吐（严格 60s 测量窗口，0 错误 0 rollback）：
  - client_credentials：1627 → **4573 ops/s**（c8→c64，~c32 饱和）
  - refresh_token：1017 → **3092 ops/s**（~c32 饱和）
  - 对比同协议重构前测量（cnb `c44fc1f3`）：cc 264→275、refresh 179→184 ops/s —— **约 17 倍提升**。
- SQL/op：cc 35.3→**15.0**，refresh 59.5→**28.0** —— 重构约减半每 op 语句数，与吞吐提升同向。
- Refresh 的 `pg_advisory_xact_lock`（2/op）依旧 0 等待；family 竞争两轮均被排除。

## 2. Tested Source & Environment

| 项 | 值 |
|---|---|
| Tested SHA | `9adbb53c71571328d1cb57c4af63d121036464f9`（gh main；PR #211 重构已合并） |
| 对照 SHA | `c44fc1f304ae186aa88470beb8e2d42ec5ef5cc3`（cnb main 旧 tip，见 `pg-wait-event-diagnosis-2026-09-15.md`） |
| 环境 | 同规格单机 Docker Compose（PG 18.6 + Valkey，同机部署）；新一轮容器，无 cargo cache 全新构建 |
| Harness 分支 | `perf/pg-wait-diagnosis-gh-20260916`：从 `perf/pg-wait-diagnosis-20260915` 移植 wait-event 工具链与 cap 场景；为适配 gh 代码移除已删除的 CIBA fixture，并补 `SIGNING_KEY_ENCRYPTION_KEY{,_ID}` |

环境修复记录（harness 侧，非生产代码）：

1. `postgres-init` 的 `DO $$` heredoc 仍被 compose 转义破坏（exit 3）——手动执行等效角色 SQL（已知问题）。
2. gh 的审计最小权限模型要求 runtime role **不得**直接持有 ledger 表权限：先 `REVOKE ALL` 4 张 ledger 表，再 `GRANT EXECUTE ON ALL FUNCTIONS`。直接 `GRANT ALL TABLES` 会导致 `privilege_preflight` 拒绝（`direct_ledger_privilege` 违规）。
3. `perf/env.yaml` 增加 `SIGNING_KEY_ENCRYPTION_KEY_ID` + 32-byte base64url `SIGNING_KEY_ENCRYPTION_KEY`（gh 新增必填项）。

PostgreSQL 设置：`track_io_timing=on`、`track_wal_io_timing=on`（ALTER SYSTEM 开启）、`pg_stat_statements.track=all`。

## 3. Methodology

与上一份诊断完全相同的严格隔离协议：15s warmup → gap 排空 → `pg_stat_statements_reset()` + `pg_stat_database`/`pg_stat_wal`/`pg_stat_io` baseline → 60s measure → 停发排空 → final snapshot；`pg_stat_activity`/`pg_locks` ~300ms 采样；refresh measurement 内仅 `refresh→successor` 连续 rotation（measure 相位禁 mint）；cc 每 op 一次 `/token`。

## 4. Per-Point Results

| Point | ops | ops/s | p50 | p95 | p99 | err | SQL/op | SQL ms/op | xact/s* | WAL B/op | WAL rec/op | fsync/op | fsync ms/op | pool wait ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cc-c8 | 97617 | 1627.0 | 4 | 8 | 13 | 0 | 15.05 | 0.43 | 15749 | 1944 | — | 4.2 | 0.50 | 0.08 |
| cc-c16 | 176035 | 2933.9 | 5 | 8 | 13 | 0 | 15.03 | 0.46 | 28223 | 2018 | — | 4.3 | 0.29 | 0.09 |
| cc-c32 | 273608 | 4560.1 | 6 | 10 | 16 | 0 | 15.02 | 0.51 | 43821 | 2130 | — | 4.2 | 0.20 | 0.25 |
| cc-c64 | 274355 | 4572.6 | 13 | 19 | 25 | 0 | 15.02 | 0.51 | 44116 | 2634 | — | 4.2 | 0.21 | 1.60 |
| refresh-c8 | 61005 | 1016.8 | 7 | 11 | 16 | 0 | 28.08 | 1.68 | 13083 | 6305 | — | 6.0 | 0.66 | 0.08 |
| refresh-c16 | 114660 | 1911.0 | 8 | 12 | 16 | 0 | 28.04 | 1.46 | 24521 | 9039 | — | 6.1 | 0.43 | 0.09 |
| refresh-c32 | 183220 | 3053.7 | 10 | 15 | 21 | 0 | 28.03 | 1.63 | 41806 | 7461 | — | 5.9 | 0.28 | 0.24 |
| refresh-c64 | 185522 | 3092.0 | 20 | 29 | 36 | 0 | 28.03 | 1.66 | 39627 | 8128 | — | 5.9 | 0.27 | 1.65 |

\* `xact_commit` 差分含大量 autocommit 单语句事务（`SELECT $1` 探针 ~5/op）；显式 `BEGIN`/`COMMIT` 语句计数恰为 **1.0/op**（两条路径一致）——重构把每 op 收敛到单一事务。

饱和判据：c32→c64 并发翻倍而吞吐 +0.3%（cc）/ +1.2%（refresh），同时 p50 翻倍——标准排队饱和。两条路径在该 harness 包线内饱和于 ~4.6k / ~3.1k ops/s。

## 5. Wait-Event 分析

### 5.1 测量窗口 active 等待样本占比

| wait_event_type \| event | cc-c64 | refresh-c64 |
|---|---|---|
| `LWLock\|WALWrite`（挂在 COMMIT qid） | **53.3%** | **42.9%** |
| `None\|None`（active 无等待=执行中） | 23.9% | 37.0% |
| `Client\|ClientRead`（等下一语句=app 侧时间） | 15.4% | 13.7% |
| `IO\|WalSync` | 7.2% | 5.7% |
| `Lock\|*`（全部） | **0%** | **0%** |
| 其他 IO/LWLock | <0.4% | <0.7% |

`pg_locks` 采样：两条路径 `waiting=false` 计数为 **0**——上一轮占 ~3700 样本的 `tuple|AccessExclusiveLock|waiting` 完全消失。exporter worker 的 `nazo_append_security_audit_chain` 因批量调用频率低未进入 top-60。

### 5.2 pg_stat_statements top（reset 后窗口差分）

cc-c64（按 Δtotal_exec_time）：

| calls/op | Δtotal ms | mean ms | 语句 |
|---|---|---|---|
| 1.0 | 49,402 | 0.180 | `SELECT nazo_persist_security_audit_event(...)` |
| 1.0 | 30,857 | 0.112 | `SELECT policy_satisfied FROM nazo_security_audit_shared_privilege_preflight(...)` |
| 1.0 | 28,601 | 0.104 | `INSERT INTO oauth_token_issuances ...` |
| 1.0 | 12,510 | 0.046 | `SELECT oauth_clients.*` |
| 1.0 | 8,379 | 0.031 | `SELECT oauth_clients.is_active` |
| 5.0 | 1,617 | 0.001 | `SELECT $1`（驱动探针） |

refresh-c64：

| calls/op | Δtotal ms | mean ms | 语句 |
|---|---|---|---|
| 1.0 | 88,881 | 0.479 | `INSERT INTO oauth_tokens (refresh...)` |
| 1.0 | 77,825 | 0.419 | `UPDATE oauth_tokens SET revoked_at=...` |
| 2.0 | 52,005 | 0.140 | `nazo_persist_security_audit_event(...)` ×2 |
| 1.0 | 22,966 | 0.124 | `INSERT INTO oauth_token_issuances ...` |
| 1.0 | 19,215 | 0.104 | `shared_privilege_preflight` |
| 2.0 | 833 | 0.002 | `pg_advisory_xact_lock`（瞬时获取） |

特征：所有语句 mean <0.5ms、无单点垄断——时间分散在 15–28 条顺序语句上，每条一次 RTT。

## 6. 诊断结论（对六个问题的回答，gh main）

1. **写路径现在属于哪一类瓶颈？** —— **round-trip × commit bound**：每 op 的延迟 = 15–28 条顺序 SQL RTT（~0.25ms 级）+ 事务 commit 的 WAL insert/fsync。高并发下 `LWLock|WALWrite`（WAL 缓冲区插入竞争，挂在 COMMIT 上）成为最大等待项；backend 忙率 ~45% 表明 PG 侧仍有富余，瓶颈在**单 op 延迟结构**而非锁或总算力。非 lock bound、非单条 SQL bound、纯 fsync 占比小（0.2–0.7ms/op）。
2. **Client Credentials 第一瓶颈**：每 op 15 条顺序 RTT + commit WAL 写路径。
3. **Refresh 第一瓶颈**：同一 commit 路径，叠加更多 SQL/op（28）与两条相对较重的语句（`oauth_tokens` insert 0.48ms / revoke update 0.42ms）。
4. **两条路径的共同瓶颈**：`COMMIT` 的 WAL 写/落盘路径 + 顺序 RTT 数量——shared commit-path bound（上一轮的 shared issuance lock 已被重构消除）。
5. **静态审计发现的冗余 RTT 是否在实际 top path**：在——`persist_security_audit_event`（1–2/op）、`shared_privilege_preflight`（1/op）、`oauth_clients` 多次读取、`SELECT $1` 探针都在 top-by-calls/time；但单条均 <0.2ms，是**可加性成本**而非串行化点。减 RTT 的杠杆现在是线性的：cc 每减 1 条 RTT ≈ 减 ~0.3ms/op 延迟 ≈ 提升上限。
6. **下一步最值得优化**：
   - 减少每 op 顺序 SQL 数（cc 15→个位数、refresh 28→~15）：合并 `oauth_clients` 的多次读取为一次、preflight 结果随连接/事务缓存、审计 persist 参数批量化。
   - refresh 侧：`oauth_tokens` 的 `revoke UPDATE` + `successor INSERT` 可评估合并为单条 CTE；`pg_advisory_xact_lock` 2 次/op 虽瞬时但可省 2 RTT。
   - `SELECT $1` 探针 5–12 次/op 来源定位（驱动/连接池检查），可在 pool 配置层消除。
   - WAL 侧：`synchronous_commit` 对可延迟的写入（outbox/审计）分级是结构选项，需语义评审；当前 fsync 本身仅 ~0.2–0.7ms/op，不是第一杠杆。

## 7. 口径与限制

- 与上一份报告同一口径修正：ops/s = `cap_measure_ops` / 60s 严格窗口。
- `sql_calls_per_op` 为 reset 后窗口内应用账号调用数 / 业务 op，含 exporter worker 与极少数后台语句（可辨认）；不包含采样器/报表查询（不同 userid）。
- 两份诊断的绝对值按同一协议测量，可直接对比；但环境为全新容器（同规格），跨容器绝对值存在正常硬件噪声，量级结论不受影响。
- CPU 指标沿用既往限制：该宿主 cgroup 采样不可靠，未用于判定。
- c32→c64 吞吐平坦+延迟翻倍判定为饱和；但 backend 忙率 <50%，>c64 的包线未测——"真实上限可能在 4.6k 之上"与"已饱和"两种读法都可能，本报告保守标注为 tested-envelope 内饱和点。

## 8. Raw Evidence

`perf/results/waitprobe-matrix-gh-2026-09-16/`（结构同上份：aggregate.json、points/、runs/、raw/{activity,locks}.jsonl、SHA256SUMS、驱动/采样日志）。

远端工作目录：`/workspace/perf-results/waitprobe-matrix/`（容器为临时资源，仓库内为权威副本）。

相关报告：`pg-wait-event-diagnosis-2026-09-15.md`（重构前对照测量）、`main-capacity-stress-2026-09-15.md`（容量基线，其绝对值口径已在新报告中注明稀释问题）。
