# Capacity window accounting repair

**任务**：修复 cap_* capacity gate 混用 whole-run 与 post-warmup
measurement-window 指标的问题；零负载离线重算 pool32 证据；条件满足后
运行一次 pool=32 的 3000/s formal confirmation。

- BASE_SHA: `c983b1ec98bfbc50b9ddf4fb7a216704b95495e0`
- 分支: `perf/capacity-window-accounting-c983b1ec`
- harness_sha: `7809bc84`
- 生产 `crates/**/src` 零修改；`DATABASE_MAX_CONNECTIONS=32`、
  `commit_delay=0`、`wal_sync_method=fdatasync` 均未动。

## 修复内容

### 唯一 authoritative population

capRun 正式 gate 现在统一读取 **measurement cohort**——iteration
ENTRY time ∈ `[measure_start_ms, measure_end_ms)`（contract
`cap-scenario-window-v1`）。whole-run 指标保留为诊断字段
（`full_run_*` / 旧顶层字段，标注 deprecated），不再进入 capRun
正式 verdict。非 capRun 场景保持 whole-scenario 语义不变。

### 新模块 `perf/tools/measure_schedule.py`

- `scheduled_arrivals_in_window()`：constant-arrival-rate 的理论
  arrival 数按有理数精确计算（arrival k 在 `scenario_start +
  k·time_unit/rate`，半开窗口，边界含 start 不含 end）。任何无法
  精确解释的输入（缺字段、rate≤0、倒置窗口、窗口在 scenario 前）
  返回 None → 调用方记 INVALID，不取近似值。
- `cohort_accounting()`：从原始 k6 summary counters 核算
  scheduled / started(`cap_iter_begin_measure`) / completed
  (`cap_measure_*` outcome 之和) / unfinished / dropped /
  drop_fraction / `pre_measure_drops_estimate`。一致性校验：
  `outcomes 之和 != cap_measure_ops` → INVALID；
  `scheduled < started` → INVALID（禁止 clamp）；
  `started != completed` → 记 `unfinished_measure` 并 INVALID。

### `runner.py` 投影

`measure` 块新增 scheduled/started/completed/unfinished/dropped/
drop_fraction/pre_measure_drops_estimate/cohort_problems；新增
`full_run` 别名块；顶层 `drop_fraction`/`dropped_iterations`/
`iterations_completed`/`latency_ms` 保留为 whole-run 诊断
（注释标注 deprecated，正式 gate 不读）。
`load_model` 记录 `time_unit`。

### `capacity_search.evaluate`（capRun 分支）

- gate 输入：`measure_drop_fraction` ≤0.001、`cap_measure_unexpected`=0、
  `cap_iter_ms` p95≤100ms p99≤250ms（op latency 治理口径，
  `cap_measure_ms` 一并报告）、`rate_for_gate` ≥ target·0.995
  （阈值政策未动）。
- `threshold_failed`（whole-run 健康护栏 checks>0.99 /
  http_req_failed<1% / http p99<5s）对 capRun 降级为诊断值，
  不再无条件否决 measurement cohort verdict；进程崩溃、stream
  parse 失败、contract invalid、cohort 不一致仍 INVALID/FAIL。
- generator 归因：只要 `measure_drop_fraction > 0.001` 即检查
  vus_max≥CAP_MAX_VUS、analyzer lag/overflow 等证据；有证据 →
  `LOAD_GENERATOR_INVALID`（不记 SUT FAIL），无证据 → 正常 FAIL。
  （Errata：`vus_max≥CAP_MAX_VUS` 单独不再构成 generator-resource
  证据，见 FORMAL3000 节 Errata；归因规则已在后续任务修正为
  `injector_vu_cap_reached` 诊断 + 独立资源证据。）

### `extract_point_metrics` / `pool_size_ab`

point.json 新增 `measure_{scheduled,started,completed,unfinished,
dropped,drop_fraction}`、`cohort_valid`、`iter_p{50,95,99}_ms`、
`full_run_*`；`pool_size_ab._strict_gate` 改用 measurement cohort
并输出明细字段。

### `proc_detail_sampler`

新增容器 cgroup memory usage 采样（v1 `memory.usage_in_bytes` /
v2 `memory.current`），替代 backend RSS 求和作为物理内存诊断
（本轮 formal 点上该 cgroup 文件在嵌套容器内不可读，记
NOT_MEASURED——采样能力已就位，非 gate 输入）。

## 单元测试

`test_capacity_window.py` 21 例 + 修正两处旧 fixture（补全 cohort
计数器）+ `test_pool_size_ab` strict fixture 更新。全部调用真实
`evaluate()`。覆盖：315000 精确调度、非整秒窗口、不同 timeUnit、
边界含/斥、倒置/零率/缺字段 INVALID、whole-run drop 干净而
measure 超阈 FAIL、whole-run p99 高而 measure 合法 PASS、
measure unexpected>0 FAIL、scheduled<started INVALID、
started≠completed INVALID、缺 contract INVALID、non-capRun 走
whole-run、generator 证据分类、threshold_failed 不再覆盖干净
cohort、B1/B2 真实数字形状。`perf/tests` 全套 **267 通过**。

## 离线重算（NEW_REAL_LOAD_TIME = 0s）

数据源：`docs/performance/reports/business-pool-24-vs-32` 的原始
k6 证据（`cap_iter_begin_measure` 为真实 counter，非估算）。

| 点 | scheduled | started=completed | dropped | drop_frac | rate_for_gate | gate p95/p99 | verdict |
|---|---|---|---|---|---|---|---|
| A1 | 315000 | 276013 | 38987 | 12.38% | 2628.7 | 1129/1256 | FAIL |
| B1 | 315000 | 314570 | 430 | **0.1365%** | 2995.9 | 57/144 | **FAIL** |
| B2 | 315000 | 314925 | 75 | **0.0238%** | 2999.3 | 46/101 | **PASS** |
| A2 | 315000 | 289145 | 25855 | 8.21% | 2753.8 | 1036/1148 | FAIL |

- started==completed==ops==Σoutcomes（unfinished=0，四点一致）。
- `pre_measure_drops_estimate`：B1 690、B2 638（估计值，非观察值）。
- 结论修正：旧报告 `STRICT_3000_GATE = FAIL` 是 whole-run drop
  混入所致 → `OLD_STRICT_3000_VERDICT =
  INVALID_MIXED_WINDOW_ACCOUNTING`；修正后
  `CORRECTED_SHORT_3000_GATE_B1 = FAIL`、`B2 = PASS`。
- `POOL_32 = PASS` 不变（其 A/B 门独立成立），`perf/env.yaml=32`
  保留。pool32 报告已追加勘误，原始数据与 verdict 未改。
- pool32 报告 PG RSS 解释勘误：+8 backend 的 RSS 求和增量
  (~1.16GB) 重复计算 shared buffers/mappings，改记
  `SUMMED_PROCESS_RSS_DELTA ≈ +1.16GB`、
  `PHYSICAL_MEMORY_DELTA = NOT_ESTABLISHED`。

## FORMAL3000（单点，pool=32）

前置条件全部成立（测试通过、B1/B2 离线恢复、B2 short gate PASS
证明 3000/s 处于可确认边界、无未决 generator INVALID）→ 运行一次。

配置：`cap_mixed` constant-arrival 3000/s，**scenario wall 600s，
authoritative measurement window = 585s**（CAP_WARMUP_MS=15000），
pre 256 / max 1024，sidecars refresh=600 argon2=8 meta=200 fapi=30
各 600s 全程，pool=32 env 覆盖，app 8 物理核 pinset，审计全程。
`sis-perf` 工具镜像按修复后代码重建（app binary 不变：
`046c7d40…60a`）。

### 结果

```
scenario wall: 612.6s   measurement window: 585s
scheduled = 1,755,000   started = completed = 1,184,955
measure dropped = 570,045   drop_fraction = 32.48%
measured ops/s = 2025.6   iter p50/p95/p99 = 321/1712/2025 ms
unexpected = 0   audit enqueued==persisted==211,362, dropped=0
vus_max = 1024 = configured CAP_MAX_VUS  -> generator evidence present
verdict = LOAD_GENERATOR_INVALID
```

**`FORMAL_10M_3000_CAPACITY = NOT_ESTABLISHED`（point 为
LOAD_GENERATOR_INVALID，非 SUT FAIL，也非 PASS）**。

证据链（如实记录，不归咎任何一方）：

- generator 侧正证据：`vus_max` 顶到配置上限 1024 → 到达率无法
  保持，570k drops 不能计为 SUT 容量失败。
- 同时 SUT 侧确有恶化：窗口内 iter p50 321ms / p99 2025ms，
  measured 2025 ops/s（低于 120s 点的 2953），pool 32/32 全程
  打满、waiting 均值 ~1284（60s 桶均值 970→1313 持续饱和，
  末桶才回落），WAL wait 份额 47.2%，commits/fsync 1.69。
  持续 600s 的 3000/s 是否 SUT 侧也超限，本点证据无法分离
  （drop 归因被 generator 饱和污染）——这正是
  LOAD_GENERATOR_INVALID 而非 FAIL 的原因。
- 健康门全 PASS：unexpected=0、audit 对账一致、journal 无
  gap/dup/fault、refresh invariants 界内、无 OOM/restart、
  sidecars 全部 terminal complete。
- `POSTGRES_MEMORY_METRIC = NOT_MEASURED`（cgroup memory 文件
  在该嵌套容器不可读；RSS 求和法已废止）。

### Errata（formal3000-load-model-repair，后续任务修正解释）

上面 `verdict = LOAD_GENERATOR_INVALID` 是当时的归因口径；后续
审计确认 `vus_max == maxVUs` 单独不足以证明 load-generator
机器资源饱和。修正后的解释：

- `INJECTOR_CONCURRENCY_CAP_REACHED = YES`（诊断字段）：dropped
  iteration 可能来自 VU 预分配/上限不足，也可能来自 SUT 变慢使
  每个 VU 被占用更久。本点 mean `cap_iter` ≈497ms、target 3000/s，
  Little's Law 平均并发需求 ≈1491 > maxVUs=1024——即便 SUT 完全
  达标也不需要持续 1024 个活跃 VU，VU 顶格本身是容量不足的
  一致症状而非独立硬件证据。
- generator 资源证据如实保留：k6 CPU ≈2 cores、CPU throttling=0、
  k6 RSS peak ≈5.5GB——没有 generator CPU/内存饱和的正证据。
- 同时发现 load-model 缺陷：`cap_iter_begin_late_vu=21640`、
  `measure_started=1,184,955` → `late_vu_fraction≈1.83%`
  （runtime VU 扩容）；且 `capRefreshOp` 丢弃了 refresh 响应中的
  新 `access_token`，subject token 约 240s 后过期走完整
  authorization-code rebootstrap，与首个 timed checkpoint
  （~279s）时间区间重叠。
- 综合：`OLD_F3000_STATUS = LOAD_MODEL_CONFOUNDED`。
  `FORMAL_10M_3000_CAPACITY = NOT_ESTABLISHED` 结论不变——
  drop/rate 既不能证 SUT FAIL 也不能证 PASS；不回溯改判。

### 停止

预算 612.6s/660s 用尽且规则禁止重复跑/换 rate/加 VU 重试 →
停止。下一步选项（不执行）：提高 `maxVUs` 后重跑同一 formal
点、或先做 3000/s 持续负载的 SUT 侧剖析（pool/WAL 已饱和迹象
明确）。`wal_sync_method` 保持 `NOT_TESTED`。

## 注册字段

```
OFFLINE_REANALYSIS_LOAD_TIME = 0s
FORMAL_REAL_LOAD_TIME = 612.6s / 660s
POOL_32 = PASS (不变)
BENCHMARK_POOL_ALIGNED_TO_DEFAULT = YES
OLD_STRICT_3000_VERDICT = INVALID_MIXED_WINDOW_ACCOUNTING
CORRECTED_SHORT_3000_GATE_B1 = FAIL (drop 430/315000 = 0.1365%)
CORRECTED_SHORT_3000_GATE_B2 = PASS (drop 75/315000 = 0.0238%)
FORMAL_10M_3000_CAPACITY = NOT_ESTABLISHED (LOAD_MODEL_CONFOUNDED;
旧记录写作 LOAD_GENERATOR_INVALID，见上节 Errata)
POSTGRES_MEMORY_METRIC = NOT_MEASURED (cgroup path unreadable)
SUMMED_RSS_PHYSICAL_INTERPRETATION = RETRACTED
GROUP_COMMIT_CANDIDATE = FAIL
COMMIT_DELAY = 0
WAL_SYNC_METHOD_CANDIDATE = NOT_TESTED
RSA_REUSE_STATUS = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS = PASS_AND_PRESENT
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS_AND_PRESENT
DATABASE_MAX_CONNECTIONS = 32
DURABILITY_CHANGED = NO
PRODUCTION_CODE_CHANGED = NO
```

## 证据

- `evidence/recompute/{A1,B1,B2,A2}/`：原始 k6.json + summary.json；
  `corrected-verdicts.json`。
- `evidence/formal3000.tar.gz`（含解压目录）：verdict、manifest、
  point.json、provenance、residency/proc-detail/soak-metrics 流、
  ledger/vkledger/wal/pgss 快照、cap-cap-mixed.k6.json/summary/
  run.log。

## 边界

- 未改 gate 阈值政策；未测其它 pool；未跑 wal_sync_method；
  未 merge main；未部署。
- formal 点按旧口径记为 LOAD_GENERATOR_INVALID（修正后解释为
  LOAD_MODEL_CONFOUNDED：injector VU cap + late-VU + subjectAt
  fixture 缺陷），非 SUT FAIL：按规则不消耗"失败重跑"额度判断，
  但预算已尽，本轮不再追加负载。
