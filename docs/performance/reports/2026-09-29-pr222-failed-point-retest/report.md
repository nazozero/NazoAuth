# PR #222 失败点补测

完成状态 **COMPLETE**；四点验收状态 **FAIL**。

TASK_STARTED_AT=2026-09-29T10:40:36Z；11:35:36Z 停载预留；11:40:36Z 交付硬截止。重试不重置计时。

被测源码/性能 harness：a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e / a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e。工具 checkpoint 86e6f925；最终报告提交在 PR 回复中单列。生产构建输入和二进制与旧 3b6d8d3c 一致。

仅四个旧失败点；五个旧通过点和旧容量矩阵均保留。不同 CNB 实例/CPU ID，角色数量、池、速率和二进制一致；不称同环境 A/B，不计算百分比。

| 点 | 轮次 | 应用 CPU | 负载 ops/s | 成功 ops/s | HTTP req/s | 完整 P50/P95/P99 ms | E/D/R/U | 有效正式 s | 主路径/整点 |
|---|---|---:|---:|---:|---:|---|---|---:|---|
| 多核授权码 | 旧 | 16 | 800 | 714.05 | 2924.432 | 143/1802/2060 | 0/5157/0/0 | 60 | FAIL/FAIL |
| 多核授权码 | 新 | 16 | 800 | 689.983 | 2844.765 | 1206/2201/2388 | 0/6601/0/0 | 60 | FAIL/FAIL |
| 单核 mixed | 旧 | 1 | 400 | 400 | 575.81 | 6/37/77 | 0/0/0/0 | 60 | PASS/FAIL |
| 单核 mixed | 新 | 1 | 400 | 400 | 578.805 | 16/122/213 | 0/0/0/0 | 60 | FAIL/FAIL |
| 多核 mixed | 旧 | 16 | 1600 | 1599.967 | 2339.255 | 6/30/63 | 0/0/2/0 | 60 | PASS/FAIL |
| 多核 mixed | 新 | 16 | 1600 | 1586.8 | 2315.691 | 41/468/988 | 0/790/2/0 | 60 | FAIL/FAIL |
| 多核 mixed 成熟 | 旧 | 16 | 800 | 799.902 | 1166.708 | 6/29/52 | 0/0/56/0 | 570 | PASS/FAIL |
| 多核 mixed 成熟 | 新 | 16 | 800 | 799.904 | 1166.891 | 11/162/448 | 0/0/55/0 | 570 | FAIL/FAIL |

E/D/R/U=非预期逻辑操作/正式 drop/预期拒绝/未完成。完整操作 prepare→end；HTTP req/s 为既有 whole-scenario 率，含预热。local_no_request 与 prepare 分类单独保留。

| mixed 点 | 轮次 | sidecar | 负载 | 成功/s | 完整 P50/P95/P99 ms | E/D/R/U | 正式 s | 判定 |
|---|---|---|---:|---:|---|---|---:|---|
| 单核 mixed | 旧 | argon2 | 1 | 1 | 290/354.1/417.18 | 0/0/0/0 | 135 | PASS |
| 单核 mixed | 旧 | meta | 13 | 13 | 1/3.3/12 | 0/0/0/0 | 135 | PASS |
| 单核 mixed | 旧 | fapi | 2 | 2 | 35/140.1/224.55 | 0/0/0/0 | 135 | FAIL |
| 单核 mixed | 旧 | refresh | 38 | 38 | 9/40/73.71 | 0/0/0/0 | 135 | PASS |
| 单核 mixed | 新 | argon2 | 1 | 1 | 399/504.1/554.92 | 0/0/0/0 | 135 | PASS |
| 单核 mixed | 新 | meta | 13 | 13 | 1/9/23 | 0/0/0/0 | 135 | PASS |
| 单核 mixed | 新 | fapi | 2 | 2 | 144/235/267.72 | 0/0/0/0 | 135 | FAIL |
| 单核 mixed | 新 | refresh | 38 | 38 | 29/95/143.71 | 0/0/0/0 | 135 | PASS |
| 多核 mixed | 旧 | argon2 | 8 | 8 | 178/206.05/253.84 | 0/0/0/0 | 135 | PASS |
| 多核 mixed | 旧 | meta | 200 | 200 | 1/1/1 | 0/0/0/0 | 135 | PASS |
| 多核 mixed | 旧 | fapi | 30 | 30 | 41/63/105 | 0/0/0/0 | 135 | PASS |
| 多核 mixed | 旧 | refresh | 600 | 598.993 | 8/16/35 | 0/137/0/0 | 135 | FAIL |
| 多核 mixed | 新 | argon2 | 8 | 7.541 | 375/1401.45/2150.92 | 0/62/0/0 | 135 | FAIL |
| 多核 mixed | 新 | meta | 200 | 200 | 1/4/7 | 0/0/0/0 | 135 | PASS |
| 多核 mixed | 新 | fapi | 30 | 29.252 | 231/1109.6/1732.04 | 0/101/0/0 | 135 | FAIL |
| 多核 mixed | 新 | refresh | 600 | 486.259 | 42/232/494 | 0/15355/0/0 | 135 | FAIL |
| 多核 mixed 成熟 | 旧 | argon2 | 8 | 7.997 | 171/195/301.31 | 0/2/0/0 | 645 | PASS |
| 多核 mixed 成熟 | 旧 | meta | 200 | 200 | 1/1/1 | 0/0/0/0 | 645 | PASS |
| 多核 mixed 成熟 | 旧 | fapi | 30 | 30 | 39/59/156 | 0/0/0/0 | 645 | PASS |
| 多核 mixed 成熟 | 旧 | refresh | 600 | 597.682 | 8/14/38.96 | 0/1495/0/0 | 645 | FAIL |
| 多核 mixed 成熟 | 新 | argon2 | 8 | 7.915 | 240/620/1131.96 | 0/55/0/0 | 645 | FAIL |
| 多核 mixed 成熟 | 新 | meta | 200 | 200 | 1/6/8 | 0/0/0/0 | 645 | PASS |
| 多核 mixed 成熟 | 新 | fapi | 30 | 29.843 | 116/464.6/964.56 | 0/101/0/0 | 645 | FAIL |
| 多核 mixed 成熟 | 新 | refresh | 600 | 568.667 | 14/108/276 | 0/20210/0/0 | 645 | FAIL |

主 runner single 64 / multi 992 VU，种子和登录 session 64/992；refresh sidecar 64 VU、多核 600 ops/s。侧载共享主种子文件，其 user_count 不是独立用户池。未记录正式窗口 VU/user ID 的地方不能从种子数断言实际参与集合。实际 affinity 与冻结配置见 manifest。

| 新点 | Fresh/legacy | SingleUse 行/累计插入 | WAL 生成 MiB | WAL 写入 MiB | 池等待 ms/acquire | 审计 |
|---|---|---|---:|---:|---:|---|
| 多核授权码 | 0/0 | 53400/53400 | 367.168 | 1110.981 | 64.012 | PASS |
| 单核 mixed | 0/0 | 7735/7735 | 67.614 | 325.216 | 0.208 | PASS |
| 多核 mixed | 0/0 | 34757/34757 | 356.364 | 1167.281 | 14.033 | PASS |
| 多核 mixed 成熟 | 0/0 | 46953/101794 | 2461.424 | 8550.068 | 2.922 | PASS |

WAL generation=pg_stat_wal；write bytes=pg_stat_io WAL 对象，分别报告。每主成功操作成本含侧载/后台；不称物理介质字节。合法 SingleUse 保留。旧纯 CC 零行/零插入原生 SHA 已重新核对，未在本轮重跑。

| 新点 | 组件 | 进程 CPU 核均值 | RSS 平均/峰值 MiB | 样本 |
|---|---|---:|---|---:|
| 多核授权码 | app | 2.981 | 111.297/112.613 | 11 |
| 多核授权码 | audit-receiver | 0.052 | 7.25/7.336 | 11 |
| 多核授权码 | audit-worker | 0.09 | 19.982/20.059 | 11 |
| 多核授权码 | postgres | 7.289 | 4124.067/5045.828 | 11 |
| 多核授权码 | sis-load-POINT | 2.458 | 4876.828/5061.371 | 11 |
| 多核授权码 | valkey | 0.094 | 24.792/30.992 | 11 |
| 单核 mixed | app | 0.676 | 55.93/100.738 | 10 |
| 单核 mixed | audit-receiver | 0.031 | 8.238/8.27 | 10 |
| 单核 mixed | audit-worker | 0.062 | 20.28/20.383 | 10 |
| 单核 mixed | postgres | 1.425 | 1937.943/2088.547 | 10 |
| 单核 mixed | sis-load-POINT | 0.552 | 459.961/470.27 | 10 |
| 单核 mixed | sis-side-argon2-POINT | 0.016 | 470.984/494.25 | 10 |
| 单核 mixed | sis-side-fapi-POINT | 0.034 | 397.14/413.887 | 10 |
| 单核 mixed | sis-side-meta-POINT | 0.031 | 387.777/391.461 | 10 |
| 单核 mixed | sis-side-refresh-POINT | 0.061 | 443.72/455.949 | 10 |
| 单核 mixed | valkey | 0.036 | 13.655/14.363 | 10 |
| 多核 mixed | app | 5.126 | 175.921/240.031 | 10 |
| 多核 mixed | audit-receiver | 0.062 | 9.488/9.676 | 10 |
| 多核 mixed | audit-worker | 0.108 | 20.071/20.402 | 10 |
| 多核 mixed | postgres | 6.046 | 5000.971/5216.59 | 10 |
| 多核 mixed | sis-load-POINT | 1.778 | 5037.375/5049.684 | 10 |
| 多核 mixed | sis-side-argon2-POINT | 0.054 | 410.276/411.863 | 10 |
| 多核 mixed | sis-side-fapi-POINT | 0.337 | 516.532/520.547 | 10 |
| 多核 mixed | sis-side-meta-POINT | 0.207 | 475.302/476.973 | 10 |
| 多核 mixed | sis-side-refresh-POINT | 0.396 | 660.434/678.922 | 10 |
| 多核 mixed | valkey | 0.069 | 27.981/33.188 | 10 |
| 多核 mixed 成熟 | app | 3.968 | 162.212/236.359 | 96 |
| 多核 mixed 成熟 | audit-receiver | 0.061 | 9.405/9.773 | 96 |
| 多核 mixed 成熟 | audit-worker | 0.11 | 20.527/20.816 | 96 |
| 多核 mixed 成熟 | postgres | 4.282 | 5149.426/5586.699 | 96 |
| 多核 mixed 成熟 | sis-load-POINT | 0.992 | 5206.879/5354.395 | 96 |
| 多核 mixed 成熟 | sis-side-argon2-POINT | 0.058 | 414.801/427.918 | 96 |
| 多核 mixed 成熟 | sis-side-fapi-POINT | 0.344 | 530.14/550.414 | 96 |
| 多核 mixed 成熟 | sis-side-meta-POINT | 0.219 | 471.168/509.766 | 96 |
| 多核 mixed 成熟 | sis-side-refresh-POINT | 0.465 | 726.884/801.777 | 96 |
| 多核 mixed 成熟 | valkey | 0.053 | 48.233/57.355 | 96 |

RSS 为容器内进程求和，PG 共享页重复计数，不是物理内存。审计组件本轮已采样。OOM/重启、退出、VU/调度、流式解析/lag/截断及资源身份见 summary 与诊断；load_generator_evidence=absent 不等于排除生成器。

成熟维护与确认 journal（保留 retention=360、expired-age SLO=120、audit drain）：
~~~json
{
  "status": "PASS",
  "pass": true,
  "retention_seconds": 360,
  "max_expired_age_seconds": 120,
  "minimum_mature_observation_seconds": 180,
  "max_sample_gap_seconds": 4,
  "mature_window_s": [
    1790680116.868,
    1790680326.868
  ],
  "samples": 100,
  "problems": [],
  "observed_max_sample_gap_seconds": 2.1882340908050537,
  "observed_sample_span_s": [
    1790680117.61553,
    1790680325.89336
  ],
  "oldest_expired_age": {
    "samples": 100,
    "first": 23.615530014038086,
    "last": 50.893359899520874,
    "min": 0.23180890083312988,
    "max": 59.15097498893738,
    "slope_per_s": -0.002617699426400887
  },
  "due_count": {
    "samples": 3,
    "first": 2817,
    "last": 3166,
    "min": 2817,
    "max": 3166,
    "slope_per_s": 2.852276351323534
  },
  "counter_window": {
    "start_s": 1790680117.61553,
    "end_s": 1790680325.89336,
    "inserted": 32988,
    "deleted": 28679,
    "inserted_per_s": 158.38459627766318,
    "deleted_per_s": 137.69588446244398
  },
  "reason": "sampled_expiry_age_within_declared_slo",
  "scope": "sampled issuance maintenance SLO; not all-state or indefinite steady state"
}
~~~
~~~json
{
  "bytes": 995030196,
  "collected": true,
  "file": "/workspace/perf-results/failed-point-retest-20260929T104036Z/multi/s3-multi-1790679637/audit-journal.jsonl",
  "sha256": "e86aff4a326c45ae39deab78c2cabd4e5dc733ba16688e63b61dbf6fdae4939d",
  "source_hash_match": true
}
~~~

唯一 60 秒对照：授权码 800，预热 15→60 秒；FAIL，成功 800/s，完整 29/101/673 ms。原 FAIL 保留。配置除预热时长外保持，预热同时推进家族/收据时间人口，不能单独证明实际缓存计划因果或称问题已解决。

工具超时尝试原生保存为 INVALID；仅补该受影响点，总工具预算加 60 秒，正式窗口和原判定均未改变。对照及工具尝试不计入四点必测。

## 失败原因证据链

- **多核 authorization code：已确认的事实**是池排队、family SQL 高成本与 WAL 等待同时发生。既有 residency_analyze 给出 240 个正式样本、235 个有效（97.92%；5 个因非原子快照产生负 idle estimate 被排除）；有效池 checked-out 均值 30.243/32，waiting 均值 639.064、最大 961。活动连接样本中 WALWrite 969、WalSync 174；没有把 ClientRead 或 idle-in-transaction 当锁等待。普通 load_family 查询 qid=3059364362978693673 的 since-reset 53,400 次调用累计 158,818 ms，357,428,575 shared-buffer hits、0 shared reads；DELETE qid=8718669233736325932 为 44,472 次、52,892 ms。缺 pre 行，因此是 since-reset 观察，不是补零后的严格差值。
- **有证据支持的授权码候选**：早期统计信息/缓存计划导致宽行缺失查询错误访问路径。首次 autoanalyze 为 10:51:42Z，正式窗口约 +40 秒，之后 VU、drop 与长尾明显恢复。fresh-plan-observations 保留独立观察者会话的 EXPLAIN，但它不是应用连接的实际缓存计划。WALWrite/WalSync 也是可见等待来源；不能据此宣称设备性能是唯一根因。未观测到独立长时间业务锁阻塞不等于全程零锁。
- **单核 mixed/FAPI 的旧证据**：正式 270 个完整操作全部保留，29 个 >100 ms 操作全部与冷登录 HTTP 区间重叠；不与保留冷登录区间重叠的 136 个操作最大 55 ms，P95 44.25 ms。五个实际步骤是 PAR、authorize、decision、code token、refresh token；本 recipe 不是另一个资源访问场景。code token 与 refresh token 尾部较大。新点分步结果与 overlap 文件一并交付。相关性支持应用单 CPU 的冷登录竞争，尚无线程调度/CPU 火焰图证明具体执行争用。
- **多核 mixed / refresh**：旧低 P99 不排除更少量长尾；旧成熟 forensic 截断已保留。新短点主路径也 FAIL，refresh 正式 drop 15,355/81,000，完整 P95/P99 232/494 ms；冷登录和 FAPI 也失败。新成熟点 refresh 正式 drop 20,210/387,000，P95/P99 108/276 ms；主路径成功 799.904/s 但 P95/P99 162/448 ms。等待/SQL/逐秒记录支持数据库事务与 WAL 排队共同影响；尚缺 GC、输出阻塞与生成器调度停顿的独立跟踪，不能把所有 drop 单独归因于服务端或纯 VU 不足。

补充对照证据：观察者在 code 对照开始后约 0–30 秒取得的 fresh generic plan 使用 idx_oauth_refresh_families_contract，仅 Index Cond tenant_id=$1，随后 Filter token_family_id=$2；之后取得的计划使用 pk_oauth_refresh_families，复合 Index Cond 同时命中两列。这是已确认的观察者会话冷计划选择，不是应用连接实际缓存计划。延长预热的正式吞吐达到 800/s、零 drop，但 P95/P99 101/673 ms 仍 FAIL；不能将全部失败解释为只需延长预热。

新单核 FAPI 的 270 次完整操作中 199 次 >100 ms，其中 113 次没有与保留的冷登录 HTTP 区间重叠；新主路径 P95/P99 122/213 ms，FAPI 235/267.72 ms。旧点的强重叠关系不能外推成新点的唯一原因；新的 SQL/WAL 等待也必须纳入。新旧 overlap 文件保留各自时钟、完整计数和近似区间限制。

诊断材料位于 diagnostics/old 与 diagnostics/new，保留原始 SQL 身份、stats_reset、stats_since、dealloc、前后累计计数、具体等待、有效驻留计算、各主/侧载按秒开始/完成/drop/长尾及资源。formal gate 只取既有权威计数；HTTP 分步 whole-scenario 分位数含预热。forensic 样本分位数可能偏向慢请求，不能冒充全量正式分位数；溢出后的未保留部分不能补零。PGSS top-level 和 nested 分列，不相加，累计执行时间也不是数据库 CPU 时间。原配置 track_wal_io_timing=off 时为零的 WAL timing 计数不代表没有 WAL 等待或零提交成本。

## 最小修复建议及仍缺证据

1. 首先定位 crates/persistence-postgres/src/repositories/tokens.rs 的 load_family（649）、persist_refresh_token_inner（667；新家族分支约 796）、retire_families_over_cap（849）及 INSERT/DELETE/COMMIT。现有 (tenant_id, token_family_id) 主键已存在。取得应用连接实际 prepared plan 后，若证实宽行缺失查询选错索引，将新家族仅用于 is_some() 的碰撞检查改为窄 EXISTS 候选；rotation 仍读完整权威行。保留 family advisory lock、tenant 谓词、碰撞 compromise、家族上限与审计事务语义。此建议未实现，不能称已修复；不凭池等待扩池或新增冗余索引。
2. 冷登录链路为 login → crates/nazoauth/src/adapters/security.rs::verify_password_blocking_limited → PasswordHash::verify_password → verify_argon2_phc。该函数已经 semaphore + spawn_blocking，不能误报为缺 offload。下一项证据应是单 CPU 线程运行/排队与 FAPI token 步骤的同时间轴剖析；尚不足以选择生产调度修复，不调整 Argon2 成本或准入来过门槛。
3. mixed rotation 限定到 load_family、family update、bounded spent-proof DELETE、COMMIT 与 nazo_persist_security_audit_event；先区分 WAL 提交等待、SQL 工作和生成器停顿。不得仅因 drop 增 VU，仅因池等待扩池，或关闭安全锁、审计、fsync/synchronous_commit。缺少设备/实际缓存计划/GC 证据的归因保留为候选或尚不能确定。

## 身份、复现和保留

应用/PG/Valkey/生成器 CPU 数分别为 single 1 / multi 16、16、1、31；预算依据本部署 .cnb.yml 的 64 CPU，ID 是本轮实际 runnable 集合。未知物理内存上限不当无限资源，进程 RSS 也不冒充物理内存。所有生产耐久性和协议参数仍按原 provenance：fsync=on、synchronous_commit=on、full_page_writes=on；连接池 32。

实际 CPU affinity、种子/session 数与内容 hash、frozen request、运行二进制和 runner 脚本 hash 在 manifest 与逐点材料保留。源码/harness 均为 a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e；生产输入与旧 3b6d8d3c 无差异，二进制 SHA-256 为 0731ed36ff88e10f0b12279ec684b6e5323626d69aaf238d3b9f33db9854c1ed。新 CNB 初始无镜像，四个缺失服务按原 compose 构建；没有本地构建、全量 Rust 测试、容量搜索或更长稳态。

本轮 initial_driver.py 为实际初始编排，SHA-256 3e07b9fb11f167e7e6f1dfaf1dc8a5f5c5257bb685f80c9be83ac12a09d0ca61。retest_driver.py 是只增加工具收尾预算的四点复现版本，仍复用原 prepare/make_point/worker/bounded_child/cleanup 与 gate。修复前尝试和旧记录保留，未据此修改真实服务失败。

复现应先保存第一次执行的 UTC 开始时间，再把报告提交中的 retest_driver.py 和 post_measurement.py 复制到 checkout 外，随后冻结普通 checkout 到 a4a818d9（不建 worktree）。在 CNB 中执行：

~~~sh
git checkout a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e
docker compose -f docker-compose.perf.yml -p nazoauth-perf build --build-arg SOURCE_SHA=a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e nazoauth perf keyset audit-receiver
python3 /tmp/retest_driver.py --started-at "$TASK_STARTED_AT" --cpu-budget 64 --output "$PWD/perf-results/failed-point-retest-NEW"
~~~

只构建缺失或身份不匹配的服务；工具会逐文件验证实际 runner，不能仅改标签。对照/补无效点脚本是本轮原始时钟记录，复现新任务时应沿用新任务自己的原始时钟；不得照搬旧 UTC 延长预算。

manifest.json、summary.json、原生点、工具 INVALID 尝试及确认点 journal 均保存到容器外的私有归档，并校验 archive/inventory/逐文件 SHA-256。evidence-sha256.json 记录归档身份与本地校验，公开 Git 只保留脱敏 SQL、等待、按秒投影和报告，没有私钥、凭据、token 或完整未经审查日志。

被测 a4a818d9 的 CI 在 11:07:07Z 有 11 success、2 skipped，所有当时 registered checks completed，详见 source-ci.json。最终报告提交 CI 在 PR 回复中记录新 SHA 的实际快照；不得借用源码 CI 或将 pending 写成 success，也不等待全量 CI 而超出截止。

这些结果仅是记录条件下的失败点补测，没有可靠容量失败上界或同环境旧代码对照，不宣称最大容量、速度提升或生产问题已解决。
