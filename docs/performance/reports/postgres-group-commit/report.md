# PostgreSQL group-commit `commit_delay` A/B

任务：验证已确认的 WAL commit 瓶颈能否通过 PostgreSQL 原生
group-commit `commit_delay` 在**完全保持 durability** 的前提下改善
吞吐与 pool 排队。单变量 A/B；无生产 Rust 改动；pool=24 未动；
durability 全开未动。

## 登记信息

| 字段 | 值 |
|---|---|
| BASE_SHA | `4c77e1e08ff05768333527e24e6f877eeafa861b` |
| 分支 | `perf/postgres-group-commit-4c77e1e0` |
| binary | `tap-b:86b2df16`，sha256 `046c7d40…0bba60a`（生产语义 = f093a256） |
| PG_VERSION | `18.6`（`postgres:18-alpine` 固定摘要镜像） |
| WAL_SYNC_METHOD | `fdatasync` |
| COMMIT_SIBLINGS | `5`（SHOW 确认，未改） |
| FSYNC_AVG_US | **500.0**（本 run 内 pg_test_fsync single-8kB fdatasync） |
| CANDIDATE_COMMIT_DELAY_US | **250**（round(500/2)，全 run 唯一候选） |
| durability | A/B 两侧每点经全新 runtime-role session SHOW 确认：fsync=on、synchronous_commit=on、full_page_writes=on |
| 变量施加方式 | `ALTER ROLE nazoauth_perf_runtime IN DATABASE oauth SET commit_delay='0'/'250'` + `ALTER SYSTEM track_wal_io_timing=on`（A/B 一致）；每次于 infra 健康后、nazoauth 启动前注入；audit exporter 角色不受影响 |
| pg_test_fsync 时长 | 48.3s（本 run；不计入负载预算） |

## 结果 — CC（constant-vus=64 × 60s + 15s warmup，四点全 PASS 健康门）

| 点 | delay | ops/s | p50 | p95 | p99 | acq/op | wait/acq | commits | WAL fsyncs | commits/fsync | active WALWrite+WalSync 份额 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A1 | 0 | 6080.0 | 10 | 16 | 28 | 2.970 | 2.00ms | 364478 | 81529 | 4.47 | 66.6% |
| B1 | 250 | 5672.2 | 10 | 17 | 32 | 2.945 | 2.15ms | 338923 | 50042 | **6.77** | 72.3% |
| B2 | 250 | 5577.4 | 10 | 17 | 32 | 2.964 | 2.18ms | 335781 | 50279 | **6.68** | 67.7% |
| A2 | 0 | 5996.6 | 10 | 16 | 29 | 2.947 | 2.03ms | 356342 | 79969 | 4.46 | 61.7% |

同窗口速率：WAL fsyncs/s 1352/1296 → **806/818（−39%）**；
WAL writes/s 1355/1299 → 809/820；WAL bytes/s 16.2MB→14.9MB。
fsync_time 合计（pg_stat_io，run 全程）：57.0s/56.8s → 42.9s/42.9s。
CPU：app 3.8–4.1/8 核、PG 5.9–6.5 核 —— 均有富余。
健康门：四点全部 `unexpected=0`、`local_no_request=0`、
`expected_rejection=0`、queue_full=0、dropped_required=0、outbox
drained、receiver/DB 对账 PASS、journal 连续、无 OOM/restart。

## 门评估（预注册，evaluate_cc）

- `a_spread_le_5pct`：**PASS**（A1/A2 spread 1.37%）
- `throughput_non_regression_3pct`：**FAIL**——B1 5672.2 / B2 5577.4
  < floor 5897.6（相对 A_max 分别 **−6.7% / −8.3%**）
- `p99_bounded`：**FAIL**——B p99=32ms，相对 A ref 28ms **+14.3%**
  且绝对 **+4ms**，两个条件同时触发
- `structural_group_commit`：**PASS**——commits/fsync +51.7%/+49.7%
  （≥+10% 满足；WAL wait 份额未降反升：0.62–0.67→0.68–0.72）

**CC verdict = FAIL → mixed 按协议未执行**（"没有任何吞吐回退才允许
继续 mixed"不满足；结构上虽有改善，但回退门先失败）。

## 机制解释

group commit **确实按预期工作**——commits/fsync 4.46→6.7，fsync
次数 −39%，证明 commit_delay=250us 成功把更多 commit 聚进同一
flush。但净效果为负：

1. **A 侧自然 group-commit 已高效**：并发 64 下本就有 ~4.5 commits
   挤进同一次 fsync（先到者替全队 flush）。候选只把批次从 ~4.5 提到
   ~6.7，边际收益小。
2. **每次 commit 多付 ≤250us 睡眠**：CC 路径约 **1 business write
   commit/op**（A1 commits=364478 ≈ 6080 ops/s × 60s；表中的 ~3 是
   pool acquisitions/op，非 commits）。每 commit 的 leader 睡眠成本
   （~0.25ms 上限）超过省下的 fsync 摊薄收益（fsync_time/op 仅
   0.246→0.200ms）。
3. 此存储 fdatasync 仅 ~0.25–0.5ms（快存储），WAL commit 瓶颈的
   主要成份是 WALInsertLock/flush 串行化等待而非 fsync 次数本身——
   减少 fsync 次数不能消除 leader 自身延迟。
4. WALWrite+WalSync 的 active 份额不降反升（61.7–66.6%→67.7–72.3%），
   与"leader 在组内等待"一致；未观察到独立的 `CommitDelay`
   wait_event（睡眠期 backend 记为 active/no-wait 或 WALWrite 下）。

## 决策

```
GROUP_COMMIT_CANDIDATE = FAIL
COMMIT_DELAY_RETAINED = NO
```

依据 §15：吞吐回退（−6.7%/−8.3%，超 3% 门）且 p99 双条件恶化；
虽然 group-commit 结构指标明确改善，性能门不通过。**未执行
mixed**、未做任何第二候选搜索（协议禁止调参）。

## 如实披露

- `pg_test_fsync` 共执行 3 次（两次 --phase diag 验证 + 最终 run 内
  一次）：fsync_avg 分别 240/230/**500**us → 候选 120/115/**250**。
  本存储单次同步时延测量值波动大；负载实验使用且仅使用 run 内测量
  值 500us→250us，四点一致。更早的验证性测量不进入实验结论。
- 首次 A1 尝试因 `sisgc-keyset` 镜像 tag 未预打在 stack_up 失败
  （基础设施失败，未产生负载；预算账本仅含 4 个 completed 点）。
- `NEW_REAL_LOAD_TIME = 271.1s`（4 点 × ~68s，含每点边界），预算
  660s。
- 收尾已验证：`ALTER ROLE nazoauth_perf_runtime IN DATABASE oauth
  RESET commit_delay` + `ALTER SYSTEM RESET track_wal_io_timing`，
  全新 runtime session `SHOW commit_delay=0`、`track_wal_io_timing=off`。

## 注册字段

```
BASE_SHA = 4c77e1e08ff05768333527e24e6f877eeafa861b
PG_VERSION = 18.6
WAL_SYNC_METHOD = fdatasync
FSYNC_AVG_US = 500.0
CANDIDATE_COMMIT_DELAY_US = 250
COMMIT_SIBLINGS = 5
GROUP_COMMIT_CANDIDATE = FAIL
COMMIT_DELAY_RETAINED = NO
STRICT_3000_GATE = NOT_TESTED
DURABILITY_CHANGED = NO
DB_POOL_CHANGED = NO
PRODUCTION_CODE_CHANGED = NO
STRICT_30M_CAPACITY = NOT_TESTED
POSTGRES_ROLE_SETTING_RESTORED = YES
```

## 证据

`evidence/`：`group-commit-{diag,cc,manifest,restore}.json`、
`budget.json`、每点 `point.json` / `wal-{pre,post}.json` /
`pgss-post.json` / `residency.jsonl.gz`；`gc-evidence.tgz` 为同一批
打包件。工具：`perf/tools/group_commit_ab.py`（17/17 单测）、
`soak_sampler` wal_io 序列、`wal_snapshot`/`wal_delta`、
`PRE_APP_HOOK` 注入点、`pgss_delta` commit_txn 类。
