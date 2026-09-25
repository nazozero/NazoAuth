# Business-pool connection residency attribution

任务：`business-pool-residency-attribution` —— 解释已优化后的 mixed
3000/s 下 business DB pool 为何仍有约 60ms acquisition wait。
**本任务只做归因，未实施任何生产优化。**

## 登记信息

| 字段 | 值 |
|---|---|
| BASE_SHA | `f093a25606f71e840a85ec8ce610501c5f879cdc` |
| 分支 | `perf/business-pool-residency-f093a256` |
| binary | `tap-b:86b2df16`，sha256 `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a` |
| binary↔base 等价性 | `git diff 86b2df16..f093a256 -- crates/**/src migrations/**` 为空：镜像即 reviewed head 的生产语义 |
| observer | `perf/tools/residency_observer.py` sha256 `9e2c6f456ea78ba9802063f86cdf42c2827a913eec8283148b205bdc466ee9f8` |
| observer 频率 | 名义 250ms；窗口内实测 419-420 样本/105s ≈ 3.99Hz（≈100% 达成率），单样本采集跨度 mean 2.25ms / p95 3.7ms |
| runtime role | `nazoauth_perf_runtime`（从受测镜像 `/app/.env.yaml` 的 `DATABASE_URL` 解析，非硬编码） |
| DB_POOL_CHANGED | **NO**（pool=24、audit queue=4096、worker=1、durability 全开均未变） |
| PRODUCTION_CHANGES | **NONE**（`crates/**/src` 零修改；新增仅 `perf/tools/*`、`perf/tests/*`、本报告目录） |

## 方法学与身份核验

每 250ms 样本同时采：
`/__perf/metrics` 的 `connections / idle_connections / waiting_acquisitions /
acquire_count / wait_nanos_*`，以及限定 `datname='oauth' AND
usename='nazoauth_perf_runtime' AND backend_type='client backend'` 的
逐 backend `pg_stat_activity`（pid、application_name、client_addr、state、
wait_event、query_id、xact/query/state_change、backend_xid/xmin）。
observer 使用独立 postgres admin 连接，不经过 business pool；周期性
`role_check` 行记录 oauth 库上全部 usename 分布。

**身份核验：成立。** 窗口内 runtime-role backend 数恒为 24 = pool
connections；其它角色只有 `nazoauth_perf_exporter`（1，audit worker）与
`postgres`（1，observer 自身）。backend `client_addr` 均为 app 容器地址，
`backend_start` 均落在 stack_up 时段。三点样本有效率：cc 180/180、
m1 419/419、m2 420/420 —— **valid_ratio = 1.00**，零 `extra_runtime_backends`
/ `negative_idle_estimate`。

## 三点结果

| 点 | ops/s | p99 | checked_out avg/p95 | pool_waiting avg/p95 | acq/s | wait/acq | implied residency | app CPU | PG CPU |
|---|---|---|---|---|---|---|---|---|---|
| CC | 6150.6 | 29ms | 24.0 / 24 | 36.0 / 40 | 18480 | **1.99ms** | 1.30ms | 2.74/8 核 | 4.04 核 |
| M1 | 2769.5 | 1092ms | 24.0 / 24 | 1151.8 / 1301 | 17896 | **64.5ms** | 1.34ms | 3.90/8 核 | 5.46 核 |
| M2 | 2717.9 | 1177ms | 24.0 / 24 | 1236.9 / 1308 | 17559 | **70.6ms** | 1.37ms | 3.88/8 核 | 5.77 核 |

`implied residency = mean(checked_out) / acquire_rate`（Little's law 交叉校验）。
`wait/acq = Δwait_nanos_total / Δacquire_count`（同窗口累计量差分）。

**checkout 状态分布（占 checked-out 连接时间比例，mean）：**

| 点 | active | idle in transaction | pg-idle（已checkout但PG空闲） | other |
|---|---|---|---|---|
| CC | 56.1% (13.5) | 19.7% (4.7) | 24.3% (5.8) | 0 |
| M1 | 48.1% (11.5) | 21.6% (5.2) | 30.4% (7.3) | 0 |
| M2 | 49.2% (11.8) | 21.8% (5.2) | 29.0% (7.0) | 0 |

## 连接在等什么（核心回答）

**24 条连接在高压窗口中全部 checkout（idle_connections=0），
acquisition 队列 1150–1317 深。** ~60ms wait 是纯排队延迟：
`队列深度 × 单次驻留 / 并发度 ≈ 1274 × 1.34ms / 24 ≈ 71ms`，与观测
57–70ms 一致。池服务率 ≈ 17.9k acq/s；需求 ≈ 6.44 acq/op × ~2900
op/s ≈ 18.6k/s ≥ 容量 → 队列持续存在。

**单次 ~1.34ms checkout 驻留的分解（M1/M2 均值）：**

- **PostgreSQL active 执行 ≈ 48–49%**（~0.65ms/checkout）。
  其中 wait event 分布（占 active 样本）：
  `LWLock:WALWrite` 43–45%、`no_wait` 32–37%、`Client:ClientRead` ~15%、
  `IO:WalSync` ~7%、`IO:Wal*`/`DataFile*` ~0.3%、`Lock:advisory` ~0.2%。
  **WAL 相关合计 ≈ 52% of active ≈ 25% 的全部 conn-time**，且按 query
  class 归因 `begin_commit`（COMMIT）占 active 样本 ~40% —— 即
  **WAL 提交刷盘是 PG 侧主导等待**，作用于 token issuance / refresh /
  audit append 等写事务的 COMMIT 阶段。
- **idle in transaction ≈ 22%**（~0.29ms/checkout）——窗口内年龄
  **98.7% <1ms、p99≈2.8ms、≥20ms 仅 ~0.05%**（max 38.8ms）。
  即全部为正常的语句间 handoff，非事务内驻留。
- **PG-idle-but-checked-out ≈ 29–30%**（~0.40ms/checkout）——窗口内
  年龄 **p99≈4.3ms、≥20ms≈0%**。逐 pid 追踪显示 24 条 conn 状态分布
  完全均匀（无长驻专用 conn）；同一 conn 连续 idle 样本的 query_id
  持续变化，即样本间隙内有查询执行——这些是 checkout→query→return→
  再出借流水线上亚毫秒级的应用侧交接，不是持有。

（采样期外曾观测到 ~1s 级 idle 年龄，已确认为窗口外 drain/teardown
阶段污染，不作为依据；窗口内统计见 `windowed-idle-stats.json`。）

## idle-in-transaction 专项

M1 共 2171 个 itx backend 样本：`<1ms` 2142（98.7%）、`1-5ms` 13、
`5-20ms` 15、`20-100ms` 1。时间加权：5-20ms 桶占 itx 时间 ~60%，
但其绝对量级极小（itx 本身只占 conn-time 22% 且几乎全是亚毫秒）。
top query_id 类别：`issuance_insert`（时间份额 25.7%）、
`refresh_family`（25.2%）、`audit_append`（13.6%）、`users FOR SHARE`/
`pg_advisory_xact_lock`（other, 12%）、`BEGIN`（8%）、`client`（6.7%）
—— 分布在多个事务阶段，无单一主导阶段；绝大多数为 statement
handoff 而非 application gap。UNKNOWN（query_id 为空）单独存在但不显著。

## pool-wait 条件分布

`P(waiting>0)` = 1.0（两点全程）；在 waiting>0 样本中
`checked_out ≥ 23` 比例 = 1.0，active 均值 11.5–11.8、itx 5.2、
pg-idle 7.0–7.3 —— 与无条件分布一致（相关非因果）。

## active wait 分布

见上表；`Lock:advisory` 仅 7–12 样本（锁等待可忽略；已按 spec 采
`pg_blocking_pids`，无持续阻塞链）。`Client:ClientRead` ~15% 为
active 状态下等客户端下一段流水线输入。

## 既有结论复核

- `PREVIOUS_CONNECTION_HOLD_CLAIM = NOT_ESTABLISHED`。
  上轮基于**全局** `pg_stat_activity` 的 "connection hold" 归因不成立：
  角色限定后的证据显示，没有任何 conn 被应用长时间持有——
  idle-in-tx 与 pg-idle 的窗口内年龄全部亚毫秒~4ms 级；
  ~60ms wait 是饱和排队而非持有。
- client-secret 两阶段结构（`dispatch/mod.rs` 的
  `client_authentication_snapshot` → `client_secret_digest_matches`
  → `commit_token_issuance` 三次 checkout）经源码复核属实；
  stored digest 从不 SELECT 到 Rust，属刻意安全边界，本任务未触碰。

## 决策

`PRIMARY_SCALING_LIMIT = POSTGRES_EXECUTION_WAIT`

判据与边界说明：
- checked-out conn-time 中 **active 为最大单一成份（48–49%）**；
  且 conn 真正"等待"只发生在 active 态——其中 **52% 的 active 样本
  wait event 指向 WAL（LWLock:WALWrite + IO:WalSync/WalWrite/WalInit*），
  query class 以 COMMIT 为主**。PG/app CPU 均有富余（app 3.9/8 核、
  PG ~5.5 核），故瓶颈是 WAL 刷盘的串行化延迟而非算力。
- 排除 A（TRANSACTION_INTER_STATEMENT_HOLD）：itx 份额仅 22% 且
  98.7% 为亚毫秒 handoff，无持续指向单一事务阶段的长驻。
- 排除 B（APP_HOLD_OUTSIDE_TRANSACTION）：pg-idle-checked-out 差额
  存在（~30%）但窗口内年龄 p99≈4.3ms、无任何 ≥20ms 的持有；
  代码审计未发现 `DbConnection` 跨 await/非 DB 工作持有的位置——
  该差额是高频借还流水线的正常交接时间。
- 排除 D（POOL_CAPACITY_CANDIDATE）：`无主导 WAL/IO bottleneck`
  前置条件不满足（WALWrite 为第一大 active wait）；增大 pool 只会
  加深 WAL 提交竞争，不建议执行 24→32 A/B。
- C 的 "checked-out 主要处于 active" 一项为 plurality（48–49%）而非
  过半数；其余 ~52% 全部为亚毫秒 pipeline 交接（服务时间而非等待），
  故按"连接实际等待的内容"判为 PG 执行期 WAL 等待。

`NEXT_PRODUCTION_CANDIDATE` = 将 client_credentials 发放路径的
三次顺序 checkout（snapshot → digest EXISTS → commit txn）合并为
**单次借用的同会话流水线**（保持 digest 只在 PG 内做 EXISTS 比较、
不把 stored verifier 读入 Rust——安全边界不变）。预期 CC 类路径
acq/op 由 ~2.93 降至 ~1，削减每 op 的借还交接与排队需求；
对 mixed 缓解幅度取决于 client-credentials 流量占比。本任务未实施，
仅登记为后续实验候选。

## 证据

`evidence/`：
- `agg-{cc,m1,m2}.json` — 每点完整聚合（validity、pool、runtime_state、
  shares、littles_law、waiting_conditioned、idle_in_tx、active_wait、
  observer 健康）。
- `windowed-idle-stats.json` — 窗口内 pg-idle/itx 年龄分位与
  wait/acq。
- `residency-{cc,m1,m2}.jsonl.gz` — 压缩原始样本流（meta + role_check
  + pgss identity map + 逐样本 pool/backend 状态）。
- `manifest.json` — 登记字段汇总。

测试：`perf/tests/test_residency_analyze.py` 7/7 通过；
`py_compile` 全部新工具通过；真实负载 = CC 60s + M1 120s + M2 120s =
300s（预算 420s，含失败尝试零次）。

```
BASE_SHA = f093a25606f71e840a85ec8ce610501c5f879cdc
OBSERVER_SHA256 = 9e2c6f456ea78ba9802063f86cdf42c2827a913eec8283148b205bdc466ee9f8
BINARY_SHA256 = 046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a
RUNTIME_ROLE = nazoauth_perf_runtime（来自受测镜像 /app/.env.yaml）
OBSERVER_INTERVAL = 250ms（实测 ≈3.99Hz，无降频）
PREVIOUS_CONNECTION_HOLD_CLAIM = NOT_ESTABLISHED
PRIMARY_SCALING_LIMIT = POSTGRES_EXECUTION_WAIT
NEXT_PRODUCTION_CANDIDATE = CC 路径三次 checkout 合并为单会话流水线（保留 in-PG digest 边界）
DB_POOL_CHANGED = NO
PRODUCTION_CHANGES = NONE
```
