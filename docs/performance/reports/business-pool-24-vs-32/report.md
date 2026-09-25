# Business pool 24 vs 32 — 单变量 A/B

**任务**：验证 benchmark 长期固定的 `DATABASE_MAX_CONNECTIONS=24`
是否低于生产默认（32）而人为限制容量。

- BASE_SHA: `23c98ff394b038b3f7e230c0a2f3b4422c230605`
  （含 native RSA key reuse、best-effort audit batch、
  transactional token-audit preflight elision）
- 来源分支 `perf/postgres-group-commit-4c77e1e0`
- 本分支 `perf/business-pool-24-vs-32-23c98ff3`
- app image `tap-b:86b2df16`，binary sha256 四点一致：
  `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a`
- runtime role `nazoauth_perf_runtime`（source: DATABASE_URL）
- harness_sha `7b27933b`

## 变量施加方式

仅容器 env `DATABASE_MAX_CONNECTIONS=24|32` 注入 nazoauth
（compose override `environment:`）。ConfigSource 优先级 env > file >
generated，进程 env 覆盖烘焙的 `/app/.env.yaml`（24）——生产镜像与
`DEFAULT_DATABASE_MAX_CONNECTIONS=32` 均未改。四点实测
`pool_size_observed` 与 runtime-role `pg_stat_activity` backend 峰值
与配置一致（24↔24，32↔32），非仅 env 字符串。

## 环境确认（postgres-only diag）

| GUC | 值 |
|---|---|
| server_version | 18.6 |
| max_connections | **100**（32 业务 + exporter + observer + admin 余量充足） |
| fsync / synchronous_commit / full_page_writes | on / on / on |
| wal_sync_method | fdatasync |
| commit_delay | **0**（上轮已恢复，复核一致） |
| commit_siblings | 5 |
| track_wal_io_timing | **off**（实验性 ALTER SYSTEM 已恢复） |
| max_wal_size / checkpoint_timeout / completion_target | 8GB / 5min / 0.9 |
| shared_buffers | 128MB |

baseline_mismatches = 空；headroom_ok = true。
未触碰 max_connections，未跑 pg_test_fsync。

## 协议

mixed only（CC 在 pool=24 已 ~6k ops/s，非本轮缺口）：
`cap_mixed` constant-arrival 3000/s，120s + 15s warmup，
pre 256 / max 1024 VUs；sidecars refresh=600 argon2=8 meta=200
fapi=30（同 120s、同启动顺序、自然退出）。顺序 A1→B1→B2→A2。
audit exporter+receiver 全程；runtime-role 250ms observer 全程；
每点 fresh DB/Valkey、同 seed；负载中不 reset/不强制 checkpoint。

负载账本（独立 `SIS_RESULTS=/workspace/perf-results/p24v32`）：

| 点 | load_seconds | 状态 |
|---|---|---|
| A1 / B1 / B2 / A2 | 130.5 / 130.5 / 130.4 / 130.4 | 全 completed |
| **合计** | **521.8s / 600s** | 无失败尝试、无第五点 |

## 结果

| 指标 | A1 (pool24) | B1 (pool32) | B2 (pool32) | A2 (pool24) |
|---|---|---|---|---|
| successful ops/s | 2613.3 | **2952.9** | **2954.0** | 2744.3 |
| attempted ops/s | 2628.7 | 2995.9 | 2999.3 | 2753.8 |
| attainment | 87.6% | **99.86%** | **99.98%** | 91.8% |
| drop_fraction | 0.1209 | 0.0031 | 0.0020 | 0.0783 |
| op p50 / p95 / p99 (ms) | 248 / 1129 / 1256 | **7 / 57 / 144** | **6 / 46 / 101** | 225 / 1036 / 1148 |
| http_rps | 3822 | 4311 | 4313 | 4017 |
| acquire/op | 6.41 | 6.46 | 6.46 | 6.39 |
| wait/acquire (ms) | 75.3 | **1.59** | **1.04** | 68.0 |
| waiting_acq mean/max | 1268 / 1319 | **29.8 / 332** | **18.8 / 321** | 1195 / 1315 |
| checked_out mean/max | 24.0 / 24 | 25.9 / 32 | 25.0 / 32 | 24.0 / 24 |
| pool_size_observed | 24 | 32 | 32 | 24 |
| runtime backends max | 24 | 32 | 32 | 24 |
| WAL wait share (active) | 41.1% | 49.9% | 45.4% | 45.5% |
| commits/fsync | 1.89 | 2.07 | 2.08 | 1.95 |
| WAL bytes/s | 11.4MB | 12.6MB | 12.6MB | 11.9MB |
| WAL fsyncs/s | 1285 | 1345 | 1345 | 1303 |
| app CPU (cores) | 4.91 | 5.20 | 5.09 | 5.02 |
| PG CPU (cores) | 8.85 | 8.21 | 8.72 | 7.81 |
| app RSS (MB) | 166.6 | 113.7 | 104.6 | 163.6 |
| PG RSS (MB) | 3764 | 4910 | 4977 | 3805 |
| audit enqueued==persisted | 53997==53997 | 59832==59832 | 59842==59842 | 56485==56485 |
| health failed checks | [] | [] | [] | [] |

健康门四点全 PASS：unexpected=0、queue_full=0、dropped=0、
pending=0、receiver/DB 对账 PASS、journal gap=0 dup=0、refresh
invariants（active≤10、spent≤64、backlog=0）、sidecars 全完成、
无 OOM/restart。

## 判定

| 门 | 结果 |
|---|---|
| A spread ≤5% | 4.77% ✓ |
| 每 B ≥1.03·max(A) | floor 2826.7；2952.9/2954.0 ✓ |
| mean(B)/mean(A) ≥1.04 | **1.1025** ✓ |
| p99 bounded | A ref 1148ms → B 144/101ms（大幅改善）✓ |
| drop 恶化 ≤0.1pp | A max 12.09% → B 0.31%/0.20%（改善）✓ |
| 结构门（waiting −30% 或 wait/acq −30%） | waiting −97.6%，wait/acq −98.1% ✓✓ |
| WAL 份额护栏 ≤+10pp | A mean 43.3% → B 49.9%/45.4%（+6.6/+2.1pp）✓ |

**POOL_32 = PASS**

## 解释

- pool=24 确为 benchmark 人为限制：24 连接全程 checkout、
  waiting ~1200+，pool=32 后 waiting 降至 ~20–30、
  checked_out mean 仅 ~26/32——池上限不再是绑定约束。
- 容量提升真实：successful ops +10.25%（2678.8→2953.4），
  attainment 91.8%→~99.9%，p99 −89%，drop −97%。
- WAL 仍是下一约束但未恶化超标：active 中 WALWrite+WalSync 份额
  +6.6pp（≤10pp 护栏内）；commits/fsync 1.9→2.07 略改善；
  fsyncs/s 与 WAL bytes/s 随吞吐同比增长属预期。
- **strict 3000 gate 仍未 PASS**（勘误见下）：B attempted
  2995.9/2999.3 ops/s 已 ≥99.5%（≥2985）且 p95/p99/unexpected 达标，
  但 drop_fraction 0.0031/0.0020 > 0.001 → **FAIL**（如实报告，
  不四舍五入）。
- 资源成本：+8 backend → 各 backend 进程 RSS 求和 +~1159MB；
  app RSS 反降 ~57MB（排队减少）；PG CPU 基本持平。

## 勘误（capacity-window-accounting 修复后追加）

**STRICT_3000_GATE 口径修正。** 旧判定混用了不同 population：
`drop_fraction` 取 whole-run（dropped_iterations / 全scenario
scheduled），而 ops/latency/unexpected 取 measurement cohort。修复后
统一为 measurement cohort（entry ∈ [measure_start, measure_end)），
从原始 `cap_iter_begin_measure` / `cap_measure_*` 计数器重算：

- `OLD_STRICT_3000_VERDICT = INVALID_MIXED_WINDOW_ACCOUNTING`
- B1: scheduled=315000, started=completed=314570, dropped=430,
  drop=0.1365% → `CORRECTED_SHORT_3000_GATE_B1 = FAIL`
- B2: scheduled=315000, started=completed=314925, dropped=75,
  drop=0.0238%, rate 2999.3/s, iter p95=46ms p99=101ms →
  `CORRECTED_SHORT_3000_GATE_B2 = PASS`

POOL_32 = PASS 结论不变（其预注册 A/B 门独立于 capacity gate）。

**PG RSS 解释勘误。** 上文“+8 backend → PG RSS +~1159MB
（≈145MB/backend 实测）”是对各 backend 进程 RSS 的求和，重复计算了
shared buffers / shared mappings / shared libraries，不能称为实际
物理内存成本。更正：`SUMMED_PROCESS_RSS_DELTA ≈ +1.16GB`；
`PHYSICAL_MEMORY_DELTA = NOT_ESTABLISHED`（未来以容器 cgroup
memory usage / PSS 为准）。

## 后续动作

- `perf/env.yaml` 24 → 32：benchmark 此前将 pool 固定在生产默认
  之下，现已对齐。**不表示 32 是所有部署的最优/强制值**——小型
  部署仍可通过配置下调；生产默认常量本就是 32 未改。
- 下一容量限制仍在 PG 侧 WAL/commit 路径（WAL 份额 ~45–50%），
  候选 `wal_sync_method` 独立 A/B 仅登记、不在本任务执行。
- `GROUP_COMMIT_CANDIDATE = FAIL` 维持不改；commit_delay=0。

## 注册字段

```
POOL_24_BASELINE_STABLE = YES (A spread 4.77% ≤5%)
POOL_32 = PASS
MIXED_THROUGHPUT_CHANGE = +10.25% (2678.8 -> 2953.4 ops/s)
POOL_WAIT_CHANGE = waiting -97.6% (1231.6 -> 24.3 mean), wait/acq -98.1%
STRICT_3000_GATE = (superseded — see 勘误: OLD_STRICT_3000_VERDICT = INVALID_MIXED_WINDOW_ACCOUNTING; CORRECTED B1=FAIL B2=PASS)
BENCHMARK_POOL_ALIGNED_TO_DEFAULT = YES
GROUP_COMMIT_CANDIDATE = FAIL
COMMIT_DELAY = 0
RSA_REUSE_STATUS = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS = PASS_AND_PRESENT
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS_AND_PRESENT
DURABILITY_CHANGED = NO
PRODUCTION_CODE_CHANGED = NO
STRICT_30M_CAPACITY = NOT_TESTED
```

## 证据

`evidence/evidence.tar.gz`：verdict、manifest、四点 point.json /
provenance / ledger / vkledger / pgss / wal 快照、250ms
residency.jsonl、proc-detail.jsonl、soak-metrics.jsonl；
`budget.json`（521.8s）。

## 边界

- 未跑 CC（本任务定义）；未做 30min soak；未测其它 pool 尺寸；
  未扩大 PG max_connections；未改任何 PG GUC。
- 历史 `2026-09-21-poolstarve-ab-30m` 的 pool=32 证据仅说明 32
  可正常运行，不作为本轮结论依据（旧代码/旧负载/不同变量）。
- 未 merge main、未部署、无生产 Rust 变更（`crates/**/src` 零修改）。
