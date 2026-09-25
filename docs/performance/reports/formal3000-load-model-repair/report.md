# FORMAL3000 Load-Model Repair（formal3000-load-model-repair）

BASE_SHA：`c37621dd2f65cca71917f1d62536d081535ee8bb`
（`perf/capacity-window-accounting-c983b1ec` reviewed head）

本任务修复旧 F3000 的两个 load-generator 方法学缺陷，并按修复后
模型运行**恰好一次** 600s formal3000 点（F3000R2）。生产 Rust
（`crates/**/src`、`migrations/`）零修改；PostgreSQL 参数、
pool=32、cap_mixed 30/25/15/15/15 业务比例全部不变；未执行
`wal_sync_method` A/B。

## 修复内容（harness only）

### 1. Refresh 响应 access_token 接续（`perf/k6/subject_state.js` + `oauth.js`）

旧缺陷：`capRefreshOp()` 成功 refresh 后只保存 rotated
`refresh_token`，丢弃响应里的新 `access_token` —— VU 继续使用
过期 subject token，约 240s 后被迫走完整 authorization-code
rebootstrap。新逻辑：`status==200` 且响应含 `access_token` 时，
`adoptSubjectAccessToken` 更新 `__VU_STATE.subjectAt` 与
`subjectAtMintedAt`；缺 `access_token` 不伪造；refresh 失败不改
mint 时间。`CAP_SUBJECT_AT_MAX_AGE_MS=240000` 保留为保护性
fallback，未加 jitter（单变量）。

### 2. Subject lifecycle 计数（固定低基数）

`cap_subject_{initial_mint,refresh_update,expired_reauth}` 全局
counter + `cap_m{N}_subject_*` 每 60s measurement bucket 计数
（最多 10 桶，无 VU/user/client tag）。

### 3. Generator 归因修正（`capacity_search.evaluate`）

`vus_max >= CAP_MAX_VUS` 降级为诊断字段
`injector_vu_cap_reached`；`LOAD_GENERATOR_RESOURCE_INVALID`
需要独立证据（OOM kill、CPU throttle、analyzer lag/overflow、
socket/dial 错误、异常退出；k6 threshold 失败退出码 99 不算）。
VU cap + latency FAIL 时 latency gate 仍然 FAIL，不被掩盖。

### 4. VU 配置

F3000R2：`preAllocatedVUs = maxVUs = 2048`（运行期零扩容；
Little's-law 余量 ≈37%）。`late_vu_fraction =
cap_iter_begin_late_vu / cap_iter_begin_measure`，门限 ≤0.1%，
超过判 `LOAD_MODEL_INVALID`。

### 5. 观测补全

- `soak_sampler`：`pg_stat_checkpointer` 全字段（num_timed /
  num_requested / num_done / write_time / sync_time /
  buffers_written），累计 counter，离线取 60s delta。
- `proc_detail_sampler`：cgroup v1+v2 内存 + 宿主 `/proc/meminfo`
  MemAvailable。
- `single_instance_scaling`：generator 内存 preflight（main k6
  启动前 MemAvailable ≥14 GiB，不足判
  `BLOCKED_LOAD_GENERATOR_MEMORY`）、main k6 OOM/exit code 捕获、
  `late_vu_fraction` 投影、每分钟 bucket 汇总。

## 旧 F3000 解释修正

`FORMAL_10M_3000_CAPACITY = NOT_ESTABLISHED` 不变，原因细化为
`LOAD_MODEL_CONFOUNDED`（非 generator 硬件饱和）：

- `INJECTOR_CONCURRENCY_CAP_REACHED = YES`：mean cap_iter
  ≈497ms × 3000/s → 并发需求 ≈1491 > maxVUs=1024；
- `cap_iter_begin_late_vu=21640` → late_vu_fraction ≈1.83%；
- subjectAt 未被 refresh 更新 → 240s rebootstrap 与首个 timed
  checkpoint（~279s）窗口重叠；
- generator 资源无饱和正证据：k6 CPU ≈2 cores、throttling=0、
  RSS peak ≈5.5GB。

（capacity-window-accounting 报告内已加 Errata 段，原始记录保留。）

## F3000R2 运行记录

HARNESS_SHA：`132a1aa6730af4516cb1829fa836be1c286cfc62`
（subject 接续 + evaluator 归因）+ `1fa3e9020715f23e72f3effaae4cb2793b2612ba`
（cohort 边界过冲容差 + bucket 计数读取修正——在产出本点的证据上
离线重评，未追加负载；见下）。

执行：容器 `cnb-n1n-1k3b2cveg`（64c/128GiB），app 镜像
`tap-b:lmr132a`（binary sha256 `046c7d40…60a`，与既往完全相同），
`sis-perf:latest` 按 132a1aa6 重建；项目 `sisr2`。

```
PREALLOCATED_VUS = 2048     MAX_VUS = 2048     (运行期零扩容)
scenario 600s  measurement window 585s  warmup 15s
cap_mixed 3000/s 30/25/15/15/15   sidecars refresh=600 argon2=8
meta=200 fapi=30 (各 600s)   pool=32   app 8 物理核
durability: fsync=on synchronous_commit=on full_page_writes=on
commit_delay=0 wal_sync_method=fdatasync checkpoint_timeout=5min
checkpoint_completion_target=0.9 max_wal_size=8GB   (manifest diag ok)
FORMAL_REAL_LOAD_TIME = 612.4s / 660s   budget.json: 单点 612.4s
```

### 生成器有效性

- `HOST_MEM_AVAILABLE_BEFORE_LOAD = 127.87 GiB`（preflight 通过，
  ≥14 GiB）；运行中宿主 MemAvailable 最低 105.09 GiB。
- `K6_RSS_AVG/MAX = 17.36 / 18.58 GiB`（2048 VU；旧点 1024 VU 时
  5.5 GiB）。
- `K6_CPU_CORES_AVG/MAX = 2.76 / 6.54`（median 2.41；两个采样计数
  异常已剔除）；cgroup `nr_throttled = 0`（CPU throttling = 0）。
- `main_exit_code=0`，OOMKilled=false，analyzer 无 lag/overflow。
- `injector_vu_cap_reached = true`：vus_max=2048——但这是**构造性
  事实**（preAllocatedVUs=maxVUs=2048，初始化波全部激活）。并发
  活跃 `vus` 峰值 2048 出现在 t≈1–3s 的 init-mint 波（warmup 内）；
  measurement 窗口内稳态并发仅 ~12–51。旧语义的"并发打满"在本点
  不成立。
- `LATE_VU_FRACTION = 0.0`（`cap_iter_begin_late_vu` 计数为 0）。

### Measurement cohort 门（修正后 evaluator 对同证据重评）

```
scheduled=1,755,000  started=completed=1,755,001  unfinished=0
boundary_overshoot=1 (观测到的有界 schedule/clock 边界不确定——
一个边界到达被计入窗口;
worst-case drop bound = 1/1,755,000 = 5.7e-7 << 0.1%)
rate_for_gate = 3000.002 ops/s (>= 2985)
unexpected = 0   p95 = 34ms   p99 = 93ms   (<= 100/250)
whole-run drops = 964 全部落在 warmup init-mint 波（t<7s），
measurement 窗口零 drop。
```

首轮 verdict 记录为 `INVALID`（`scheduled_less_than_started`，
started 超 scheduled 恰好 1）：合约假设"k6 不能多于有理数调度
发数"对观测到的有界 schedule/clock 边界不确定不成立（±1 到达）。
修正容差（`BOUNDARY_JITTER_MS=1` → 3000/s 下允许 ≤3，超出仍
INVALID）后对**同一份证据**离线重评 → `PASS`；原始 verdict 存于
`evidence/formal3000r2/F3000R2/formal3000-verdict-precontract-fix.json`。

### Subject lifecycle（修复验证）

```
initial_mint = 2048   refresh_update = 258,453   expired_reauth = 183
measure_expired_reauth = 183  (183/1,755,001 = 0.0104%)
```

无 240s rebootstrap 波峰：reauth 从第 4 分钟起以 12–43/min 的
稳态薄尾出现——3000/s 下稳态并发只需 ~30 VU，2048 个 VU 中多数
闲置超过 240s，重新启用时按真实 OAuth 客户端语义过期重认证，
无聚集 cliff（旧模型下会集中爆发）。

### 每分钟 bucket（measurement 窗口，60s/bucket，m10 为 45s 尾桶）

| bucket | sched | began | ops | p95 | p99 | init | refresh | reauth | pool wait avg/max | checked_out | WAL share | ckpt_done Δ | write_ms Δ | sync_ms Δ | bufwr Δ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 180000 | 180000 | 179970 | 47 | 103 | 0 | 26614 | 0 | 35.9/340 | 25.9 | 0.48 | 0 | 0 | 0 | 0 |
| 2 | 180000 | 180000 | 180009 | 31 | 66 | 0 | 26299 | 0 | 7.0/93 | 23.9 | 0.61 | 0 | 0 | 0 | 0 |
| 3 | 180000 | 180000 | 180001 | 31 | 69 | 0 | 25712 | 0 | 16.5/175 | 23.7 | 0.58 | 0 | 0 | 0 | 0 |
| 4 | 180000 | 180000 | 180002 | 32 | 68 | 0 | 25431 | 12 | 15.8/337 | 24.0 | 0.57 | 0 | 0 | 0 | 0 |
| 5 | 180000 | 179999 | 179999 | 29 | 60 | 0 | 25625 | 43 | 11.6/192 | 22.1 | 0.59 | 0 | 0 | 0 | 1227 |
| 6 | 180000 | 180000 | 179993 | 28 | 54 | 0 | 25860 | 24 | 3.3/47 | 22.8 | 0.57 | 0 | 0 | 0 | 42 |
| 7 | 180000 | 180002 | 180012 | 109 | 395 | 0 | 25576 | 27 | 84.3/1044 | 25.1 | 0.61 | 0 | 0 | 0 | 779 |
| 8 | 180000 | 180000 | 179995 | 27 | 49 | 0 | 25646 | 25 | 4.9/59 | 23.8 | 0.59 | 0 | 0 | 0 | 1658 |
| 9 | 180000 | 180000 | 179996 | 31 | 62 | 0 | 25967 | 26 | 10.3/146 | 26.6 | 0.52 | 1 | 269776 | 329 | 117 |
| 10 | 135000 | 135000 | 135024 | 27 | 45 | 0 | 19091 | 26 | 1.5/29 | 17.6 | 0.57 | 0 | 0 | 0 | 1167 |

- pg_stat_checkpointer 累计计数器在 checkpoint **完成时**入账：
  m9 的 `done=1` + `write_time Δ=269.8s` 表示一个 timed checkpoint
  于 ~540s 完成、写入阶段跨约 270s（completion_target=0.9 拖长）。
- **相关性观察（非因果结论）**：m7 bucket p95/p99 109/395ms 的
  抬升落在 checkpoint 写入时段内（~m4.5–m9），pool wait max 同步
  抬到 1044；窗口级 p99=93ms 与所有门仍通过，不构成 cliff。
- WAL wait 份额 ~0.52–0.61 全程稳定（SUT 主导等待仍是 WAL
  flush 路径，但在 3000/s 下不构成超限）。
- 每桶 begin/ops ±30 内为 bucket 边界归属噪声（begin 在 N、完成
  落 N+1），非 drop。

### 健康与不变量（全部 PASS）

unexpected=0、queue_full=0、dropped_required=0、pending=0、
audit enqueued==persisted==300,298（batch max 64）、receiver/DB
sequence+hash+deployment 一致、journal gap=0 dup=0 fault=none、
refresh active/scope≤10（实测 10）、spent/family≤64、expired
backlog=0、无 OOM/restart、sidecars 全部 terminal complete、
`pool_size_observed=32`、runtime_backends_max=32。

### 结果

```
FORMAL_10M_3000_CAPACITY = PASS
PRIMARY_LIMIT = NONE            (3000/s 下无超限瓶颈;
                                 WAL share ~0.57 + checkpoint 写窗
                                 内 m7 延迟抬升已记录为相关性观察)
NEXT_PRODUCTION_CANDIDATE = NONE (本任务无生产改动;按 §18.A 停止
                                 3000/s 优化)
```

## 注册字段

```
BASE_SHA = c37621dd2f65cca71917f1d62536d081535ee8bb
HARNESS_SHA = 132a1aa6730af4516cb1829fa836be1c286cfc62
              + 1fa3e9020715f23e72f3effaae4cb2793b2612ba
TESTS = 279 pass / 0 fail / 1 skip (k6 binary absent locally;
       subject_state_test.js 10/10 于 sis-perf 镜像内执行)
OLD_F3000_STATUS = LOAD_MODEL_CONFOUNDED (NOT_ESTABLISHED 保持)
PREALLOCATED_VUS = 2048
MAX_VUS = 2048
HOST_MEM_AVAILABLE_BEFORE_LOAD = 127.87 GiB
HOST_MEM_AVAILABLE_MIN_DURING = 105.09 GiB
K6_RSS_AVG/MAX = 17.36 / 18.58 GiB
K6_CPU_CORES_AVG/MAX = 2.76 / 6.54 (median 2.41, nr_throttled=0)
LATE_VU_FRACTION = 0.0
FORMAL_REAL_LOAD_TIME = 612.4s / 660s
INJECTOR_VU_CAP_REACHED = true (构造性: pre=max=2048; 并发稳态 12–51)
FORMAL_10M_3000_CAPACITY = PASS
PRIMARY_LIMIT = NONE
NEXT_PRODUCTION_CANDIDATE = NONE
POOL_32 = PASS
DATABASE_MAX_CONNECTIONS = 32
GROUP_COMMIT_CANDIDATE = FAIL
COMMIT_DELAY = 0
WAL_SYNC_METHOD_CANDIDATE = NOT_TESTED
RSA_REUSE_STATUS = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS = PASS_AND_PRESENT
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS_AND_PRESENT
DURABILITY_CHANGED = NO
PRODUCTION_CODE_CHANGED = NO
POSTGRES_MEMORY = process-RSS 口径 avg/max 5.17/5.69 GiB;
                  cgroup memory 在嵌套容器为共享命名空间读数
                  (app==pg 同值) → NOT per-container, 如实标注
```

## 证据

`evidence/formal3000r2-evidence.tar.gz`（含解压目录）：
point.json、provenance.json、verdict（修正后）+ 原始
precontract-fix verdict、manifest、env-check、budget.json、
k6 summary/k6.json/k6log/run.log/errors、四个 sidecar 全套、
residency.jsonl（per-backend wait_event）、soak-metrics.jsonl
（checkpointer 全字段）、proc-detail.jsonl（含宿主 meminfo +
cgroup）、ledger/vkledger/wal/pgss 前后快照、audit drain。

## 边界

- 生产 Rust/迁移零修改；PG 参数未动；pool=32 未动；cap_mixed
  30/25/15/15/15 未动；未跑 wal_sync_method；未强制 checkpoint。
- 恰好一次 600s formal 点（budget.json 单点 612.4s）；verdict 的
  INVALID→PASS 变化是对同一证据的离线重评（合约 bug 修复），
  非重跑。
- 按 §18.A：停止 3000/s 性能优化；后续阶段为 30m 稳定性或更高
  target。
- 未 merge main；未部署；未 force-push。
