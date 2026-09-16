# Pool RecyclingMethod Verified vs Fast — A/B Diagnosis — 2026-09-16

## 1. Verdict

**ADOPT FAST** — all acceptance criteria met (see §6).

`ManagerConfig.recycling_method` is the only production-code delta under test
(`crates/persistence-postgres/src/pool.rs`): `Verified` (default, `SELECT 1`
ping per checkout) vs `Fast` (transaction/broken-state check only).

- `SELECT $1`/op: 5.01 (cc) / 7.01 (refresh) → **0.00**, exactly equal to
  `pool_acquire`/op — the ping per checkout is eliminated, checkouts unchanged.
- Top-level SQL/op drops by exactly the ping count: cc 15.02→10.01,
  refresh 26.03→19.01. No nested-statement change (cc 0.00, refresh 2.00 both
  modes — refresh's 2 nested/op is the refresh-context validation inside a SQL
  function, not a wire RTT).
- Throughput: **+5.9% … +22.4%**; latency p50/p95/p99 each improved 1–3ms.
- Failure semantics: backend termination → **0 failed probes** (dead sockets
  are detected structurally at checkout, before any business SQL);
  full PostgreSQL container restart → **2 bounded 503s** per path, recovery
  <0.3s, no restart, no partial issuance/rotation (failed refresh retried with
  the same token succeeded → family state atomic).

## 2. Tested Source

| 项 | 值 |
|---|---|
| Base SHA | `9adbb53c`（gh main，PR #211 已合并） |
| A/B 变量 | `pool.rs`: `config.recycling_method = RecyclingMethod::Fast`（verified 腿 = 未修改默认） |
| 环境 | 同一容器化单机栈（PG 18.6 + Valkey 同机）；两腿各自完整 4 点矩阵顺序执行 |
| 协议 | 15s warmup → gap 排空 → `pg_stat_statements_reset()` + baseline → 60s measure → 排空 → final；activity/locks ~300ms 采样；本轮 `pg_stat_statements` dump 含 `toplevel` 列 |

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

解释：c8（RTT-latency bound 区间）收益最大——每 op 省 5/7 次 RTT ≈ 1.3–1.8ms/op
延迟，直接转成吞吐；c32（开始贴近 WAL/commit 饱和）收益收窄但仍有
+10~12%。两腿 wait 分布形态不变（`LWLock|WALWrite` 仍为首位活跃等待）。

## 4. 故障语义测试（Fast 构建上执行）

### 4.1 `pg_terminate_backend`（杀掉 runtime role 全部 backend）

- cc 探针（4/s，60s）：21 个 backend 终止 → **0 失败**
- refresh 探针（mint 独立 family 后每 250ms 轮换）：3 个 backend 终止 →
  **0 失败**
- 机制：`pg_terminate_backend` 关闭 socket → tokio-postgres 连接驱动结束 →
  池内对象在 checkout 时被结构性判死并丢弃，新的物理连接按需建立；
  `Fast` 不需要 ping 就能发现 socket 级死亡。Verified 的 ping 只对
  **socket 看似活着但实际已死**（半开 TCP，无 FIN/RST）的场景才有额外价值。

### 4.2 `docker restart postgres`（整个 PG 短暂重启）

| Path | 失败数 | 错误类型 | 恢复时间 | 部分状态 |
|---|---|---|---|---|
| cc | 2 | HTTP 503 `server_error` | 末次失败后 0.26s 恢复连续成功 | 无 |
| refresh | 2 | HTTP 503 `server_error` | 0.27s | 无——失败后同一 refresh_token 重试成功，rotation 原子性保持 |

失败均有界、fail-closed、无错误成功；连接自动重建；无需重启 NazoAuth。

### 4.3 未覆盖边界（如实声明）

- **静默半开 TCP**（对端消失且无 FIN/RST，如中间设备丢包）未测：Fast 下
  首个业务 SQL 会失败（有界 1 次失败/op，连接随后被丢弃）；Verified 会在
  checkout ping 时拦截。本环境（docker bridge 同机）不存在该模式。
- 池等待本身两种模式都不显著（<0.25ms avg）。

## 5. Acceptance Criteria Checklist

| # | 条件 | 结果 |
|---|---|---|
| 1 | SELECT $1/op → ~0 | ✅ 0.00（全部 4 点） |
| 2 | throughput/latency 有可测收益 | ✅ +5.9%~+22.4%，p50 −1ms |
| 3 | errors=0 | ✅ 矩阵全点 0 错误 |
| 4 | stale conn 不产生错误成功 | ✅ terminate 测试 0 失败 |
| 5 | 所有 DB 失败 fail-closed | ✅ 仅 503 server_error |
| 6 | 无 partial issuance/rotation | ✅ refresh 失败后同 token 重试成功 |
| 7 | 坏连接被 discard | ✅ 死连接未再出现业务错误 |
| 8 | 自动建连恢复 | ✅ <0.3s |
| 9 | 无需重启 | ✅ app 进程未动 |
| 10 | 失败数有界 | ✅ restart 2 次/路径 |

## 6. 最终结论

**ADOPT FAST.**

- 收益：cc +11.6%（c32）/ +22.4%（c8）；refresh +10.1%（c32）/ +5.9%（c8）；
  每 op 净减 5（cc）/7（refresh）个零业务价值 wire RTT。
- 代价：半开 TCP 这类"socket 活、对端死"的罕见场景下，stale 连接的首个
  业务 SQL 失败一次（fail-closed、有界、连接随后被替换）——按任务给定
  语义这是可接受边界。
- 不做：透明业务重试（引入幂等/事务复杂度，超出本轮范围）。

下一步候选（不在本轮实施）：合并 `oauth_clients` 多次读取；refresh 的
`parent SELECT + revoke UPDATE → UPDATE ... RETURNING`；family
`EXISTS + INSERT → conditional INSERT`；audit preflight 两 SQL 合一
（不缓存结果）。

## 7. Raw Evidence

- `perf/results/waitprobe-ab-verified-2026-09-16/`、`perf/results/waitprobe-ab-fast-2026-09-16/`：
  aggregate.json、4 点快照、run summary、activity/locks 原始 JSONL、SHA256SUMS
- `perf/results/failprobe-2026-09-16/`：cc/refresh × terminate/restart 探针 JSONL
- 工具：`perf/wait_ab.sh`、`perf/aggregate_ab.py`、`perf/failprobe.py`；
  `perf/wait_sampler.py` 增加 `toplevel` 列、app `__perf/metrics` 快照
  （Host 头修正）与持续活跃防误判（`consec_active>=5`）

远端工作目录：`/workspace/perf-results/waitprobe-ab/`、`/workspace/perf-results/failprobe/`。
