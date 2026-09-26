# PR #222 性能证据与最短请求链路审查

审查日期：2026-09-26。目标为 [PR #222](https://github.com/nazozero/NazoAuth/pull/222) 的 `perf/db-hotpath-minimal-0c70d746` 分支；接手基线为 `da2899161a1e4a9989a3641cd0d1f94ebb59f68f`，本轮代码修改逐项提交至 `2af5e69ae1106bfc2f15b3c52eaa8e0381d0e961`。历史证据按原 source/binary 归属，验证状态见第 9 节。本报告复核仓库保存的历史原始数据、测量脚本和源码，不是当前候选版本的新压测报告，不追溯修改历史报告的 PASS / FAIL / INVALID。未合并、未部署。

**主要结论：优先处理数据库请求链路中的重复写入与无效回收，以及后台回收能力不足；同时修正验收口径，否则会把完成迭代当成成功吞吐，把短时容量当成长时稳定性。** 最强证据是历史 formal 运行的百万级过期 issuance 积压、refresh contract 删除 98.10% 无效，以及受控 pool 24/32 实验中的排队变化。SCIM 共享鉴权写入有源码机制与扩容失效现象支持，但没有足够的锁采样把全部损失定量归因于某一行锁。累计 SQL 时间不能换算为端到端延迟损失，更不能据此宣布当前代码已提升某个百分比。

## 1. 证据范围与可信边界

| 证据 | 原始来源 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- |
| Formal 3000、30 分钟 R2 | [window](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/load/cap-cap-mixed.window.json)、[PGSS pre](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/pgss-pre.json)、[PGSS post](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/pgss-post.json)、[ledger post](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/ledger-post.txt) | 指定历史运行的成功数、数据库工作量与结束时积压 | 当前分支性能、整个项目所有协议流的稳态容量 |
| Pool 24/32 A/B | [完整归档](../business-pool-24-vs-32/evidence/evidence.tar.gz)、[manifest](../business-pool-24-vs-32/manifest.json) | 同一历史二进制、指定 mixed 负载下，24 个连接构成额外排队限制 | 任意部署都应使用 32；当前候选严格 3000/s 稳态通过 |
| SCIM / Device / CIBA 梯度 | [原始 ladder 目录](../2026-09-18-capacity-endurance/evidence/ladder/)、[来源说明](../2026-09-18-capacity-endurance/report.md) | 特定历史版本、共享主机上的并发扩展形态 | 当前代码绝对容量、特定 SQL 锁占全部损失的比例 |
| Audit batching A/B | [verdict](../audit-batch-persistence/evidence/audit-batch-verdict.json)、[二进制 manifest](../audit-batch-persistence/evidence/audit-batch-manifest.json) | 已保留汇总中的队列丢弃消失、实际批处理与吞吐非退化 | 从仓库独立重建全部原始四点时序；普遍吞吐提升幅度 |
| 当前修改 | Git 提交及本报告第 8 节所列源码 | 冗余链路已在代码中移除，测量契约已修改 | 未在相同数据库环境重新运行前的实际收益 |

Formal 的 [manifest](../formal3000-30m-harness-repair/manifest.json) 记录 `base_sha=1e758edcc9faa8ea07085d1fce11b82eef3bb891`、`harness_sha=ebbfa79727063d69895125f0d7c9e1e150da8cf8`，应用镜像 `hr2-app:a2dd5f13`，镜像/运行进程/预期 binary SHA256 均为 `046c7d40861b63bdb8b75303d36b3b89d7ad0ad1cd50d86d7cec253020bba60a`。但 [provenance.json](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/provenance.json) 的 `source_sha` 为 `unknown`。二进制三方一致不等于证明该二进制来自当前源码。应保留这个可追溯性限制。

仓库保留了 formal 主负载的 window、summary、k6 summary、错误和日志，但未保留可在本地完整重放全部主负载分析的 series / residency / soak 原始时序。因此本报告可以重算保留字段、校验 PGSS 差分、核对结束 ledger；不能补造逐分钟清理年龄曲线。SCIM 等 2026-09-18 结果来自 `3ff5030e038ca5de16226c74f8e5759d4ec2cd1b`，当时应用未绑核、最多可见 64 个 CPU，与当前候选不能混为一组 A/B。

## 2. P1：旧后台回收存在结构性供需缺口

### 2.1 最直接的证据是已过期的存量与年龄

Formal R2 的 [ledger-pre.txt](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/ledger-pre.txt) 中 issuance 行数、过期行数均为 0；[ledger-post.txt](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/ledger-post.txt) 的关键记录为：

| 位置 | 字段 | 值 |
| --- | --- | --- |
| 第 3 行 | `META sampled_at` | `2026-09-25 05:25:40.136724` |
| 第 252 行 | `ROW_COUNTS oauth_token_issuances`，精确行数 | 1,961,417 |
| 第 276 行 | `EXPIRED_BACKLOG issuances_due` | 1,128,769 |
| 第 276 行 | 最早 `retain_until` | `2026-09-25 05:18:51` |
| 第 10 行 | relation 累计插入 / 删除 | 4,957,370 / 2,995,953 |

计算：

```text
过期存量占比 = 1,128,769 / 1,961,417 = 57.5486%
ledger 开始时间 - 最早 retain_until = 409.136724 秒
```

`META sampled_at` 早于后续 backlog SQL，409.137 秒是该次采集下的诊断年龄下界，不是同语句时钟计算的精确即时年龄。即便如此，最旧过期行已等待超过 6 个正常 60 秒周期，不能用“周期清理自然会暂时有 due 行”解释为充分稳定。第 10 行的 `n_live_tup=1,964,715` 是估计量，不能替代第 252 行的精确行数。

### 2.2 源码给出可证明的旧吞吐上限

在 `da28991:crates/nazoauth/src/jobs/security_state.rs` 第 14–21、50–67 行，旧 worker 每轮最多 512 批，批内回收 issuance 最多 256 行，随后固定休眠 60 秒；还受 30 秒连续工作预算限制。因此，在单 worker 下，即使忽略所有执行时间：

```text
旧 issuance 回收长期上限 ≤ 512 × 256 / 60 = 2,184.533 行/秒
```

这只是乐观上界，实际批次耗时、其他类别维护和预算到期只会降低吞吐。该上界不是 HTTP 容量：一次请求可能不产生 issuance，也可能负载旁路产生额外 issuance。源码链路见 [worker](../../../../crates/nazoauth/src/jobs/security_state.rs)、[维护仓储](../../../../crates/persistence-postgres/src/repositories/security_state.rs) 与 [初始 bounded cleanup 定义](../../../../migrations/20260805000500_token_issuance_saga/up.sql)。历史实现一直保留到本轮 worker 修改前；这是持久机制证据，不冒充当前 HEAD 的实测。

同一 formal 的 PGSS 可以提供同窗工作量交叉检查：

```text
pre.ts  = 1790312068.525355
post.ts = 1790313942.1984613
span    = 1,873.673106 秒
Fresh INSERT rows + SingleUse INSERT rows
        = 4,076,388 + 880,982 = 4,957,370
整个 PGSS 区间平均插入率 = 4,957,370 / 1,873.673106 = 2,645.803 行/秒
```

该分母来自实际 PGSS pre/post，不使用 `point.load` 的约 1,821.1 秒，也不使用主负载的 1,785 秒测量窗。它包含预热、旁路和收尾，是全区间平均值，不能冒充成熟稳态的逐秒到期率。对于保持相同生产率、保留期有限且最终均到期的长期运行，旧回收上限低于生产率；结束时百万过期行是已经发生的实证。

[perf/env.yaml](../../../../perf/env.yaml) 第 28 行的 access-token TTL 为 300 秒，但 [token_issuance.rs](../../../../crates/persistence-postgres/src/repositories/token_issuance.rs) 第 366–387 行把 `retain_until` 设为 access-token 有效期加 clock skew，并在 SingleUse 时取与 grant deadline 的较大值。因此不能仅凭 TTL=300 声称所有 issuance 都在 300 秒或固定 360 秒成熟。应按实际场景最大保留期声明成熟观察窗。

### 2.3 当前代码与剩余风险

当前 worker 已移除 512 批总数上限；饱和运行达到 30 秒调度预算后，按该轮实际工作时间休息；排空或失败时休息 60 秒。仍保留每类别、每批次行数限制、批间 yield 与错误后的正常等待。其意义是消除固定行数/60 秒造成的结构性天花板，同时避免无限连续抢占。**这不证明数据库实际清理能力已经超过生产率。** 在途批次允许完成，30 秒是批次调度预算，不是单条 SQL 的硬超时。

验收已扩展为 [issuance-maintenance-evidence.md](../../issuance-maintenance-evidence.md)：运行前声明实际最大 retention 和最大过期年龄目标；从 `measurement_start + retention` 开始至少观察 180 秒，使用同语句数据库时间采样最旧 due 行，并验证覆盖、时钟和计数器 reset。非零或短暂上升的 due 数自然可能来自清理锯齿，不能只看一个终点；另一方面，旧 refresh-family / spent-proof invariant 通过不能证明 issuance 清理通过。新 PASS 只证明该运行成熟窗口内的采样年龄目标，不是无限稳态证明。

## 3. P1：同步数据库工作放大了关键请求链路

### 3.1 PGSS 差分的正确归因范围

[pgss-pre.json](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/pgss-pre.json) 与 [pgss-post.json](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/pgss-post.json) 的 `stats_reset` 都是 `1790312068.521715`。pre 仅有两条 postgres observer/reset 语句。按 `(dbid, userid, toplevel, queryid)` 对齐，并核对 reset 相等后，下表 runtime 顶层查询的 post 值可作为该区间增量。

| `pgss-post.json` 位置 / queryid | 顶层 runtime 查询 | calls | rows | 累计 `total_exec_time` ms |
| --- | --- | ---: | ---: | ---: |
| 第 41–50 行；`7937354421020446243` | 持久化 required security audit | 7,595,860 | 7,595,860 | 1,228,831.750 |
| 第 185–194 行；`-2887139335912015367` | Fresh issuance INSERT | 4,076,388 | 4,076,388 | 498,049.505 |
| 第 197–206 行；`-6838157736527928436` | shared privilege preflight | 3,678,979 | 3,678,979 | 438,253.786 |
| 第 317–326 行；`-5288884251522700385` | 每次 refresh 的 spent-proof prune | 1,863,025 | 1,670,307 | 363,765.115 |
| 第 473–482 行；`7644058008137761304` | 按 contract 主键尝试删除 orphan | 862,130 | 16,361 | 540,028.255 |

最后一项按唯一主键一次最多删除一行，所以可精确推导：

```text
无删除调用比例 = (862,130 - 16,361) / 862,130 = 98.1023%
```

这不是“删了一些行所以大部分有用”，而是绝大多数同步尝试没有回收任何对象。安全决策需要即时退休 refresh family、维护 replay/ownership 证据并原子记录 required audit；对无引用、过了保护期的 contract 做物理回收，不需要每次发 token 都尝试。`abf9449` 已把这部分回收交给维护任务并补充引用索引，属于减少请求必经链路的直接修复。

shared privilege preflight 也有数百万调用。`05f0deb` 让最终 Required append 在适用路径负责静态 writer 权限检查，避免在同一必定追加路径提前重复查询。不能由此删除动态 readiness、撤销/租户隔离检查、审计持久化或事务原子性；append 是安全决策的最终拥有者，失败必须使业务提交失败。Device / CIBA 等具体分支应以源码路径和故障测试确认，不能把某一 mixed 结果推广到全部协议。

### 3.2 不应使用的推导

累计 SQL 执行时间包含并发会话的工作时间，不是 wall-clock，也不等同 CPU 时间。表中 540,028 ms 不能直接除以整段运行时长后称为“端到端性能损失”，也不能承诺移除后提升相应百分比。必要的安全持久化本身耗时高，不意味着可删除。

本次 PGSS 全部 calls 为 164,372,310，其中 nested 为 77,978,705，runtime 顶层为 85,868,387。主负载 HTTP 数为 7,800,382，而包含旁路负载的总 HTTP 数为 9,956,017。把全角色、含 nested 的 SQL 除以主负载 HTTP 得到约 21 次“SQL/request”，混合了执行层级和工作负载；它不是一次请求经过 21 次串行网络 RTT 的证明。连接池 acquire 还可能包含后台任务，除以主负载成功数也不能得出单个业务的准确 checkout 数。最短链路应通过具体成功/失败分支源码顺序确认，再用同窗计数交叉验证。

## 4. P1：formal 3000 的历史 PASS 不等于成功吞吐达到目标

[window.json](../formal3000-30m-harness-repair/evidence/formal3000-30m-r2/F3000-30M-R2/load/cap-cap-mixed.window.json) 第 61–78 行 `measurement_cohort`：

| 项目 | 数值 |
| --- | ---: |
| window start / end | 1790312099.163 / 1790313884.163 |
| 精确窗口长度 | 1,785 秒 |
| started / completed | 5,355,005 / 5,355,005 |
| success | 5,314,987 |
| expected_rejection | 885 |
| local_no_request | 39,133 |
| 测量窗 dropped | 0 |

```text
完成迭代率 = 5,355,005 / 1,785 = 3,000.003 /秒
成功操作率 = 5,314,987 / 1,785 = 2,977.584 /秒
成功 / completed = 99.2527%
当前 successful-ops-v1 的 3000/s × 99.5% 下限 = 2,985 /秒
```

按当前成功吞吐契约，这组历史计数未达到 2,985/s 下限。`local_no_request` 没有实际完成目标服务工作；协议正确拒绝也不能混入成功 numerator。完整迭代 P95/P99 为 41/135 ms、操作 P99 为 134 ms，这些低延迟与上述吞吐不足及回收积压可以同时存在，不能相互代替。

原始 [manifest](../formal3000-30m-harness-repair/manifest.json) 因 `diag_overflow` 标记 INVALID，后续 [reeval-verdict](../formal-evidence-contract-repair/evidence/F3000-30M-R2.reeval-verdict.json) 在区分 forensic 诊断溢出与容量核心证据后有原契约判定。这里保留其历史语义，并明确新旧 numerator 差异，不把事后重算包装成新运行，也不为了让旧 PASS 保留而调整新门槛。

该 formal 的主 mixed 配方是 userinfo 30%、client credentials 25%、authorization code 15%、refresh 15%、token exchange 15%，另有 refresh 600/s、Argon2 登录 8/s、metadata 200/s、FAPI 30/s 旁路。它不是 SCIM、Device、CIBA、所有 Fresh / single-use / mTLS 分支的全覆盖。

### 4.1 PR #222 的后续进度是另一组证据

[PR #222 进度评论](https://github.com/nazozero/NazoAuth/pull/222#issuecomment-5844672554) 发布于 `2026-09-26T08:39:32Z`，报告针对 `da289916` 候选的 600 秒容量结果：baseline 2400/s PASS、P99 53 ms；head 3200/s PASS、P99 239 ms，即报告容量增加约 33%。评论还报告 1800/s、pre/max VU 均 2048、120 秒 warmup + 120 秒 measurement 的 ABBA pair A 全部 PASS；其中一个 B 的 P99 136 ms 对比 A 最小值 96 ms 被标记，WAL 约 4956 → 4494 B/op。pairs B–E、故障点及 3 × 1800 秒 steady 后续验证尚未形成可在本轮复核的完整归档。

这些是前任运行者提供的进度，而非本次独立复验结果；base/head 的完整来源、实际 outcome/window、所有 A/B 点及故障/长期结果应在恢复连接后以原始 manifest 核对。它们与 2026-09-25 的旧 formal3000 不是同一个运行，**不能用旧 formal 的成功吞吐重算直接否定前任 3200/s 结果**，也不能把前任结果推广到后来新增修复后的 `2af5e69`。600 秒容量点不能独立证明长期稳定；3200/s 的 P99 239 ms 距 250 ms 门仅 11 ms，需按运行前既定 gate 检验其复现性，不能事后放宽门槛消除真实退化。本报告对这组进度保留“已报告、待独立核验”的状态。

## 5. Pool 24/32：受控实验比“WAL 占比高所以不能加连接”的猜测更有力

原始 [evidence.tar.gz](../business-pool-24-vs-32/evidence/evidence.tar.gz) 的成员为：

```text
pool24v32/mixed/{A1,A2,B1,B2}/point.json
pool24v32/mixed/{A1,A2,B1,B2}/residency.jsonl
```

下表直接取各 `point.json.metrics` 的 `successful_ops_per_s`、`op_p99_ms`、`wait_per_acq_ms`；队列均值来自各 residency 的测量窗样本（每点 420 个）。

| 点 | pool | 成功操作/s | 操作 P99 ms | wait/acquire ms | checked-out 均值 | waiting 均值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1 | 24 | 2613.333 | 1256 | 75.325 | 24.000 | 1267.974 |
| A2 | 24 | 2744.333 | 1148 | 68.002 | 24.000 | 1195.195 |
| B1 | 32 | 2952.876 | 144 | 1.590 | 25.895 | 29.833 |
| B2 | 32 | 2953.990 | 101 | 1.039 | 25.033 | 18.848 |

A 均值 2678.833/s，B 均值 2953.433/s，历史实验提高约 10.25%。24 时连接借满、千级队列；32 时平均借出约 25–26 个、队列显著缩小。这支持“24 的限制额外阻塞了该负载”，而非单凭 PG WAL wait share 推断增大 pool 必然更差。

该实验的 WAL active-sample share A1/A2 为 41.1%/45.5%，B1/B2 为 49.9%/45.4%。吞吐改善与 WAL 活跃样本占比提高并不矛盾；share 是采样构成，不是某个请求的等待预算。`commit_delay=0`，durability 没有降低；此前 group-commit 候选失败不能通过换个口径宣布成功。PG 进程 RSS 相加包含共享页重复计算，不能作为物理内存增量。

[manifest](../business-pool-24-vs-32/manifest.json) 记录同一应用 binary `046c7d40...`、唯一变量为 pool env override；当时生产默认已是 32，实验是把基准配置对齐，而非新的生产默认优化。四点只有短窗，且 B1/B2 的真实成功吞吐都低于当前 2985/s 下限，所以历史 pool32 PASS 应理解为该实验的选择结论，不能替代当前成功吞吐契约下的 strict 3000 / 30m 通过。

## 6. SCIM、Device、CIBA：辨别流程单位与扩容形态

### 6.1 SCIM：并发增加没有增加吞吐，共用鉴权路径是优先排查对象

原始文件分别为 [c4](../2026-09-18-capacity-endurance/evidence/ladder/cap_scim_reads-c4/capacity-cap-scim-reads.k6.json)、[c8](../2026-09-18-capacity-endurance/evidence/ladder/cap_scim_reads-c8/capacity-cap-scim-reads.k6.json)、[c16](../2026-09-18-capacity-endurance/evidence/ladder/cap_scim_reads-c16/capacity-cap-scim-reads.k6.json)。读取 `metrics.iterations` / `http_reqs` / `http_req_duration` / `cap_measure_ops`：

| 并发 | 全运行 HTTP=迭代/s | 全运行 HTTP P99 ms | cap_measure_ops count | k6 原始 cap_measure_ops rate |
| --- | ---: | ---: | ---: | ---: |
| 4 | 505.158 | 22.172 | 16,725 | 371.587 |
| 8 | 521.340 | 78.330 | 17,447 | 387.567 |
| 16 | 504.913 | 185.008 | 16,751 | 371.968 |

各点 pool wait 约 0.002 ms。全运行吞吐约 505–521/s 不再上升，P99 由 22 ms 增至 185 ms，证明该历史 SCIM workload 的扩容失效不是明显的 pool checkout 等待。旧鉴权每次请求对同一 credential 写 last-used，并开专用事务/持久化专用使用证据；即使业务读取 schema、metadata，也经过该公共写路径。这是符合现象的序列化机制。

`f2c3b67` 已移除冗余 credential-use 写路径，保留有效 credential 查询、scope、租户、expiry/revocation 检查、统一审计及必要 deny audit。仍需用同 credential 与多 credential 对照，查看行锁与事务耗时，证明实际收益；历史没有 SCIM 锁采样，不能宣布全部平台瓶颈都是这一行 UPDATE。

特别注意：历史标题中的 371–388 “ops/s”来自 post-warmup `cap_measure_ops.count` 除以约 45 秒的全运行时长。该 numerator/window 不一致，不能当作精确稳态容量。原始文件缺少可恢复精确测量 cohort 的对应时序，本报告保留原值及定义，不猜一个“修正后容量”。全运行 HTTP rate 使用同窗 count/rate，可以说明相对扩容形态，但也不是成功稳态验收值。

### 6.2 Device / CIBA：一次业务包含多次 HTTP

Device 原始 [c4](../2026-09-18-capacity-endurance/evidence/ladder/cap_device_flow-c4/capacity-cap-device-flow.k6.json)、[c8](../2026-09-18-capacity-endurance/evidence/ladder/cap_device_flow-c8/capacity-cap-device-flow.k6.json)：全运行分别约 298.207、472.932 flow/s，对应 1192.827、1891.727 HTTP/s，HTTP 约为逻辑流程的 4 倍。c8 的 23 个 `cap_measure_errors` 除以同口径 14,786 `cap_measure_ops` 为 0.15555%；若错误地除以全运行 85,152 HTTP，则只得到 0.02701%，掩盖流程错误比例。该数据不足以将错误唯一归因于某个 rate limiter。

CIBA 原始 [ladder](../2026-09-18-capacity-endurance/evidence/ladder/) 中 `cap_ciba_flow-c{4,8,16,32,64}/capacity-cap-ciba-flow.k6.json` 的全运行 flow/s 依次为 187.833、389.522、692.041、1221.494、1454.269；c64 为 5817.076 HTTP/s。历史 1063.723 “ops/s”是 47,896 post-warmup count 的全时长 rate，同样有分母问题。c32/c64 pool wait 约 0.028/0.642 ms，不能据此证明 DPoP 是唯一瓶颈；需要把签名/校验、数据库和轮询语义区分。历史 private-key poll r60/r120 因轮询语义不正确而被排除，不可回收为有效容量证据。

当前 static writer preflight 合并覆盖部分 Device / CIBA 路径，但本轮没有对应的新数据库性能数据。应先验证协议、安全失败与事务语义，然后做代表性的短链路对照，不从 mixed 一项直接推断这些 flow 已提速。

## 7. Audit batching：已证明的是避免丢弃与非退化

[audit-batch-verdict.json](../audit-batch-persistence/evidence/audit-batch-verdict.json) 的 `points.*.audit_queue`、`successful_ops_per_s`、`op_p99_ms`：

| 点 | dropped | persisted events | persist batches | max batch | 成功操作/s | P99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1 | 42,435 | 6,797 | 6,797 | 1 | 2351.400 | 1375 |
| A2 | 44,906 | 7,309 | 7,309 | 1 | 2480.571 | 1240 |
| B1 | 0 | 50,764 | 2,227 | 64 | 2474.933 | 1206 |
| B2 | 0 | 52,381 | 2,207 | 62 | 2497.419 | 1212 |

该实验使用 common 应用 `bec5ff72` 与 batch 应用 `d4f5c734`，harness `30c7f556`，二进制不同且来源保留在 [manifest](../audit-batch-persistence/manifest.json)。B 实际持久化更多事件，队列丢弃归零，批量落库确实发生；`B_min/A_max - 1 = -0.227%`，满足当时 97% 非退化下限。不能称为显著吞吐提升，也不能因为 B 完成了更多原来被丢弃的审计而把 WAL/op 上升直接视为劣化。

仓库仅保留这组 verdict、manifest、budget 等汇总证据，缺少四个完整 point 的原始时序，独立重算能力弱于 pool 归档。该问题属于此前已测的审计队列修复，不应在 PR #222 里重复计为新的收益。

## 8. 本轮已实现内容与未完成验收

下表区分已经实现的源码变更与仍待完成的验收；审查期间的工作区修改已在交付前提交，不把“代码已经修改”写成“性能已经改善”。

| 状态 | 变更 | 最短链路与安全边界 | 待验证 |
| --- | --- | --- | --- |
| 已提交 `da28991` | refresh rotation 使用 commit-owned writer gate | 必要审计与状态写入由最终提交路径负责 | 同环境 A/B；Required append 故障语义 |
| 已提交 `abf9449` | retired refresh contract 转入维护回收，补引用索引 | family cap / replay / required retirement audit 保持即时；物理 orphan 删除离开签发路径 | 引用与并发集成；跨 1 小时 grace 的回收与扫描成本 |
| 已提交 `f2c3b67` | 移除 SCIM 冗余 credential-use 事务与写入 | 保留真实鉴权、撤销检查、统一审计和 deny audit | 同 credential 扩容/锁等待对照 |
| 已提交 `05f0deb` | 适用路径取消重复静态 writer preflight | 最终 Required append 继续负责必要检查；动态 readiness 不得省略 | Device/CIBA 等各分支安全失败与查询数 |
| 已提交 `1861749` | signing header 与签名绑定同一 key generation | 防止轮换时 header/signature 不一致 | 这是正确性修复，没有单独的性能提升证据 |
| 已提交 `0af1aaf` | 修正 SCIM 测试 executor | 修复测试编译依赖 | CI 状态见下节 |
| 已提交 `6da30a2` | successful-ops、producer/outcome、PG 时钟、成熟清理证据 | 消除错误成功统计和采样年龄伪精度 | 与真实 k6/PG 数据对接及新 A/B |
| 已提交 `ba25019` | SCIM poll receipts 批处理并避免空事务 | 相同结果的持久化批次合并；保留确认语义 | 真实 PG receipt 行为与查询数 |
| 已提交 `3c962fa` | OID4VCI transaction-code 校验移出数据库连接占用 | 高成本校验不占用 lease；提交阶段仍需权威状态校验 | 并发消费/撤销及无效码路径 |
| 已提交 `3c1043a` | OID4VC request trust policy 使用单次快照 | 合并请求内重复获取，保留信任与授权边界 | 相关数据库集成与 query-count 验证 |
| 已提交 `2af5e69` | GC 自适应休息、移除 512 批上限、周期摘要日志 | 保留每类别每批行数限制、错误退避、批间 yield | 成熟窗口年龄、请求尾延迟、实际清理率 |
| 已提交 `2af5e69` | OpenID4VCI 过期清理转维护、索引与引用保护 | 前台只保留当前对象的必要校验；子对象独立到期，grant 不得提前级联删除 | 真实 PG 迁移、并发、保留期、查询计划 |

实现入口：[worker](../../../../crates/nazoauth/src/jobs/security_state.rs)、[maintenance port](../../../../crates/persistence/src/maintenance.rs)、[PG maintenance](../../../../crates/persistence-postgres/src/repositories/security_state.rs)、[OID4VC offer store](../../../../crates/persistence-postgres/src/repositories/openid4vc_issuance_store/offer.rs)、[tenant resources](../../../../crates/persistence-postgres/src/repositories/tenant_resources.rs)、[新增保留期索引](../../../../migrations/20260927000400_openid4vci_retention_indexes/up.sql)。

`3c962fa` 的关键并非简单把 transaction-code Argon 校验放到异步函数：旧路径在 `SELECT ... FOR UPDATE` 的事务与连接占用期间做昂贵校验；新路径先读取快照、归还连接，再通过注入的共享有界 `SecretVerifyPort` / `LoginPasswordVerifier` 校验，避免为每个请求新增无界密码计算任务。只有校验成功才重新借连接，以一条条件 UPDATE 消费。条件比较 tenant/id、未消费状态、pre-authorized code hash、transaction-code hash、subject、credential configurations 和原 expiry 等授权字段；快照改变或竞争者先消费则不返回授权。校验排队期间可能过期，因此消费时重新使用数据库 `clock_timestamp()` 与调用方 `now` 的较大值检查 expiry，返回的授权期限也受 offer expiry 限制。这样减少昂贵计算时的连接/行锁占用，同时保留单赢家与不消费失效快照的语义。pool-release、锁、快照变化与过载测试已添加；真实 PG 执行仍待完成。

`3c1043a` 将公共 OID4VC trust-policy 读取从三次带锁查询改为单次已提交快照查询；`Unbound`、`BoundInactive`、`Active` 与不一致状态的错误语义保留，管理写事务的锁保留。它缩短读取往返，不意味着可以缓存跨请求的旧信任状态。`ba25019` 则合并 SCIM poll receipt 写入并跳过没有 receipt 的空事务，避免在没有写入工作时仍占连接执行事务。这三项当前都是源码链路改善，尚无新的同环境收益数字。

### 8.1 测量修复的意义与保留限制

本轮曾用现有 fixture/实际 JS producer 做最小复现，属于逻辑回归而非压测：旧消费者查找 `unexpected_error`，实际 producer 发送 `unexpected`，导致 SUT 非预期失败被判成 `outcome_counter_mismatch` / INVALID；另一个 9,990 success + 10 未分类 prepare_failed 的 10,000 次样本仍可能通过 99.5% 吞吐 gate。0.1% 准备失败不能因为落在吞吐容差内而自动获准。

准备阶段包含本地 fixture/signing，也可能包含真实登录、PAR、授权与 token HTTP 调用。当前 [measurement-accounting.md](../../measurement-accounting.md) 及代码将明确 SUT HTTP 失败/缺 token 归为 `prepare_sut_failed` → FAIL；请求前本地准备失败为 `prepare_local_failed` → INVALID；未知或历史 `prepare_failed` → INVALID，不强行给 SUT 或注入器定责。成功和失败准备都进入完整 `cap_iter_ms`，stream outcome 与 named counter 必须逐项一致。不能用只有操作阶段的低延迟掩盖准备耗时。

旧 observer 在 HTTP 请求前取得主机 `ts`，随后查询 PG 状态，可能出现 `state_change` 晚于 `ts`，负值再被 clamp 为 0。历史 [windowed-idle-stats.json](../business-pool-residency/evidence/windowed-idle-stats.json) 第 39–49 行保留过负的 idle age（如 idle p50 -1.294 ms、idle-in-transaction p50 -1.354 ms）。因此旧“98.7% 小于 1 ms”等微秒级解释不可靠。当前改用同查询数据库 `pg_ts - state_change`，负值/缺字段视为无效。修复后 pool 与 PG 仍是非原子采样；250 ms observer 也不是每次请求的精确 trace，`time_weighted_share` 只是按所见 age 加权，不是累计连接驻留。

### 8.2 P2 待验风险：限制删除行数不等于限制扫描量

[PG maintenance](../../../../crates/persistence-postgres/src/repositories/security_state.rs) 的 orphan contract 与 OID4VC grant 候选查询，`NOT EXISTS` 在 `LIMIT` 之前。若有大量已到期、但仍被有效 child 引用的父对象，数据库可能每个 catch-up batch 都检查大量不合格父行，最后只返回少量或零个候选。新增 FK/reference 索引缩短每次 inner probe，却不保证 outer scan 有界。

因此“每批最多 256 行”和“一个父对象带 300 个 child 的 fixture 不发生级联删除”只分别证明输出/删除量与安全语义，不证明每批扫描耗时。还需要在真实 PG 上以这类分布查看执行计划、实际扫描行数、buffer 与每批耗时，并观察批次长期占用连接时的请求 P99。30 秒调度预算不会中断已经执行的 SQL。此项暂列待验风险，不能在没有计划证据时宣布已经发生新的性能回归，也不能因有 LIMIT 就宣称成本受控。

### 8.3 迁移与真实并发仍需数据库验证

[270003 引用索引](../../../../migrations/20260927000300_refresh_contract_reference_index/up.sql) 为 refresh family 新增 `(tenant_id, contract_blake3)` 索引；[270004](../../../../migrations/20260927000400_openid4vci_retention_indexes/up.sql) 新增 notification expiry、deferred token、notification token 三个 expiry/reference 索引。它们使用普通 `CREATE INDEX`，并非并发建索引。真实库迁移前应按现有表大小与写入负载评估锁等待、构建耗时及部署窗口；本轮尚未部署。

当前还补充了并发 child INSERT 与两个 sweeper 跳过已锁对象的数据库测试，编译已通过。编译证明测试代码可构建，不证明 PostgreSQL 实际锁行为已经执行通过；该边界与性能验收分开记录。

### 8.4 尚未测量的场景候选，以及应保留的链路

下列内容按 `2af5e69` 源码核对，尚未实施。它们有额外工作机制，但缺少在目标部署中的成本占比，不能与上述百万积压等实证同级，也不能全部归因到普通 token 请求。

| 场景 | 当前机制 | 下一条必要证据与安全边界 |
| --- | --- | --- |
| 多 tenant / replica 的 runtime reconciliation | 每个已启动 tenant runtime 各起 reconciler；目标一秒周期遍历 16 个 module，正常齐备时至少逐个读取 desired 与 instance，各自 checkout；依赖检查可能继续查询。见 [tenant runtime](../../../../crates/nazoauth/src/bootstrap/startup/tenant_runtime.rs)、[reconcile](../../../../crates/runtime-capabilities/src/registry/reconcile.rs)。 | 先测活跃 tenant × replica、相关 PGSS 与 pool wait。若确有成本，可评估一次批量 snapshot 与 revision 判断；必须保留依赖和并发 revision 校验。这不是每个 HTTP 请求扫描全部 tenant。 |
| 大 PAR / consent 内容的原子消费 | [Valkey authorization](../../../../crates/state-store-valkey/src/authorization.rs) 发送完整 expected JSON；[Lua command](../../../../crates/state-store-valkey/src/command.rs) 解析 stored/expected 后递归比较并排序对象 keys。 | 需要 payload 分布、Lua CPU / slowlog。可评估原始 wire/version 比较，不能用无条件 GETDEL 代替 CAS。解析发生在一次 Lua 调用内，不能计为多次网络往返。 |
| 外层无 `client_id` 的 encrypted JAR | [authorize flow](../../../../crates/authorization-server/src/authorization/request/flow.rs) / [PAR](../../../../crates/authorization-server/src/authorization/par.rs) 先解密探测 client，再经 [JAR](../../../../crates/authorization-server/src/authorization/jar.rs) 正式校验时再次解密。 | 先测该分支占比与解密 profile。可考虑请求内携带“已解密、尚未信任”对象，但 client 的 alg/enc、签名、claims 和 replay 检查仍全部需要。外层已有 client_id 时不属于此问题。 |
| CIBA ping / logout 积压排空 | [ping 调度](../../../../crates/nazoauth/src/jobs/ciba_ping.rs) 和 [logout 调度](../../../../crates/nazoauth/src/jobs/backchannel_logout.rs) 不利用处理条数，满批后仍分别 sleep 500 ms / 5 s；当前批量为 8 / 20。 | 需要 backlog、到达率、远端耗时和 delivery P95。若满批持续饱和，可评估连续处理与空批退避，但须保留 claim lease、失败重试和远端保护，不能据此声称普通 token 吞吐受限。 |
| 默认生产日志 | [observability](../../../../crates/nazoauth/src/bootstrap/observability.rs) 默认 info；[HTTP factory](../../../../crates/nazoauth/src/bootstrap/startup/services/factory.rs) 为请求创建 span / 完成 event。性能 [env](../../../../perf/env.yaml) 实际为 warn。 | 需在真实输出端做 info/warn 对照，测格式化 CPU、字节率、背压及 OTEL 队列。当前 bench 没有证明默认日志无成本，也不能用默认 info 解释该 warn bench 的瓶颈；Required audit 是独立安全事实，不随诊断日志删减。 |

复核后不把 Device/CIBA 一概写成“重复预读”：当前 CIBA 已将 `initial` 传给 poll，正常路径不再预读，CAS conflict 才重取；Device 正常 poll 读取一次，冲突才重试，Approved 结果仍由最终 issuance fence 防重。JARM 确有 client 重读，但两次之间已提交业务状态，需先定义 client 停用或策略变更应在哪个时点生效，不能直接复用旧 snapshot。refresh 的 scope/family 锁和必要 client/user 共享锁也不能仅因耗时就删除；它们维护并发授权与撤销语义。

## 9. 最短验收路径与当前验证状态

最短路径是先闭合已知证据缺口，再验证直接移除的链路，不重新铺开所有历史容量矩阵：

1. **固定来源与规则。** 在运行前冻结 baseline/candidate source、镜像与 runtime binary SHA、migration head、硬件/绑核、pool、数据规模、旁路、VU 供应与时长；双方使用同一修正后的 harness。保持 durability。预先声明成功吞吐、完整迭代 P95/P99、错误、审计和成熟清理门槛，任何 offline re-evaluation 都另列版本与原因，不能看到结果后换 gate 掩盖退化。
2. **先完成真实数据库正确性验证。** 重点是 required audit 失败回滚、refresh replay/ownership、contract 引用保护、SCIM 撤销与审计、OID4VC child retention/并发以及新索引迁移。纯逻辑测试与 DB test 编译都不能替代真实 PG 执行。
3. **一次受控 A/B 检验短链路。** 用相同负载做交错 A/B；PGSS reset identity 与 pre/post span 必须匹配，分别报告 runtime 顶层、nested、background。预期证据是同步 orphan DELETE 和重复 preflight/SCIM UPDATE 消失，以及同成功吞吐下 SQL/WAL/CPU/尾延迟的变化；不能只挑吞吐最好的一点。
4. **专门覆盖成熟回收。** 同一 soak 用预声明最大 retention 后至少三个正常周期的完整年龄采样、due 数和同窗 insert/delete 支持稳定性判断。单个终点与 600 秒容量点不足；fresh 30 分钟也没有跨过 refresh contract 1 小时 grace，需已有成熟对象或对应跨度，不能把 issuance 验收当成全部类别回收验收。
5. **只为剩余归因补最小场景。** SCIM 做共享/分散 credential 对照；Device/CIBA 以 flow 成功为单位核验代表性路径；grant/contract 做大量受引用父对象分布的真实执行计划。若结果已满足已声明门槛且无剩余具体风险，不再追加无目的压测。

| 验证项目 | 截至本报告状态 |
| --- | --- |
| 历史 window、PGSS、ledger、pool archive 重算 | 已完成只读审查；本报告列出数值、字段与边界 |
| `cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings` | PASS，包含数据库测试编译；追加并发 GC 测试另以 `cargo clippy --locked -p nazo-postgres --test security_state_maintenance -- -D warnings` 通过 |
| `cargo test --locked -p nazo-key-management --lib` | 72 PASS，含跨算法轮换期间 access/ID/introspection 签名一致性 |
| `python -m unittest discover -s perf/tests` | 299 项：298 PASS、1 SKIP（缺少真实 k6）；包含 Node 执行真实 JS producer 的跨语言回归，不是压测 |
| `cargo test --locked -p nazo-oauth-server --lib --test authorization_application --test cross_device_application -- --test-threads=1` | 299 + 11 + 11 = 321 PASS，含 SCIM、授权、Device/CIBA 和 Required 审计失败路径 |
| `cargo test --locked -p nazoauth --lib jobs::security_state -- --test-threads=1` | 6 PASS，含超过 512 批排空、预算耗尽休息、错误退避和关闭取消 |
| `cargo test --locked -p nazo-identity --test scim_service` / `cargo test --locked -p nazo-http-actix --test scim_transport` | 3 + 5 = 8 PASS，覆盖服务边界与 HTTP 契约 |
| 格式与静态契约 | `cargo fmt --check`、`git diff --check`、`verify_static_contracts.py --check`、`check_persistence_dependency_graph.py`、`check_crypto_boundary.py`、`check_perf_results_layout.py` 均通过；Python 脚本位于 `scripts/` |
| GitHub CI 代码提交 `2af5e69` | PENDING；早期 SCIM executor 编译问题已由 `0af1aaf` 修复 |
| PostgreSQL 18 schema / migration | CI 已通过，包含新索引迁移；本地没有可用数据库环境 |
| [真实 HTTP 安全矩阵](https://github.com/nazozero/NazoAuth/actions/runs/36243184482) | `2af5e69` PASS；含 11 项 SCIM SET black-box、四组 load/race 的 errors=0、Valkey outage 的 health/token 503 fail-closed；不是容量 A/B |
| PostgreSQL / Valkey 全工作区集成 | PENDING，由带 PostgreSQL 18、Valkey 8、隔离审计库和对象存储 fixture 的 CI 执行 |
| 远程同环境 A/B / 成熟 soak | PENDING；已知 SSH 主机名仍 DNS 解析失败，尚未恢复可执行环境 |
| 当前候选性能收益 | 未验证，不宣称已提升 |

本轮已经把性能问题从泛泛的“WAL 慢、连接少、SQL 多”收敛到可检验的工作：必要安全写入保留在提交边界，重复鉴权写入和高度无效的同步物理回收离开请求链路；后台容量必须覆盖成熟到期负载；验收只统计成功业务且覆盖真实保留期。代码修复与测量修复现已具备明确目标，项目继续推进所需的是上述真实数据库与同环境证据，而不是从旧报告推算当前收益。
