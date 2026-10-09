from pathlib import Path
import json,datetime
E=Path('/src/evidence/pr230-performance-20261009');P=E/'publish';rows=json.loads((E/'round-analysis.json').read_text());source=json.loads((E/'final-source.json').read_text())['sha']
s='''# PR #230：性能定位、最小修复与 decision 自然回收

本轮 **未达到原性能门槛，不能宣布无回退或具备全面合并标准**。已完成固定 SQL prepared statement 复用修复和真实数据库回归；已补齐目标 decision 批次自然回收终态。连接池排队的直接机制得到量化，但剩余数据库往返、驱动和调度等待尚未充分分离，不能把共享 CPU 当成全部失败的解释。

## 版本与范围

- 起始源码 A：`bbe4fb2d4078f859ffb690a83d7ac9a6f088d0ac`。
- 起始远端 HEAD / 历史报告：`298cf845c58b2caab0128ac07f5eacd3e50fb355`。
- 最终源码 B：`SOURCE`。本报告提交只包含证据及文档，报告提交 SHA 见 PR 正文。
- 所有构建、测试、故障注入和负载均在本轮授权隔离 CNB；单 checkout、单 target、单写入者。未重跑 main、旧通过矩阵或未受修改影响的完整恢复故障负载。
- 外层原有 Containerfile 空白改动已保存在 stash `f50660a4e7d487590b1ed864ce4c8d1dce85ae14` 及隔离容器备份中，未丢弃或混入 PR。
- 诊断 D1 是 A 加临时采样；D2 是候选生产修复加相同采样；D3 额外单变量设 `TOKIO_WORKER_THREADS=1`，效果不佳，未进入生产配置。诊断二进制为基线加已归档 patch，不能伪称最终 Git SHA 构建。最终正式 B 点使用 `image-candidate.json` 中的精确源码/二进制，未带临时采样。

## 判定

| 维度 | 结果 | 本轮证据范围 |
|---|---|---|
| CODE | PASS | 最终修改对应回归、nazo-postgres 全目标补齐后 511 passed、fmt、静态边界、workspace Clippy、release 构建；未重复完整 workspace suite。 |
| SECURITY | PASS | 修改触及的真实 PostgreSQL 提交/取消/断连边界及安全状态回归通过，安全语义未降低。 |
| PERFORMANCE | FAIL | 原容量门槛仍未达到，局部 prepared statement 修复不构成整体性能通过证明。无效测点另列 INVALID。 |
| STORAGE（decision 自然回收） | PASS | 43,601 条冻结批次经过最后保留期及完整自然维护周期后归零；合法未到期状态保留。 |
| STORAGE（长期/目标负载稳定） | INVALID | 短测及丢迭代条件不足以证明目标负载长期稳定或最小存储。 |
| RECOVERY | 本轮未重跑全故障负载 | 既有报告保留；本轮重测相关数据库边界，不把历史结果冒充本轮新结果。 |

## 已证实机制及修复

完整授权码业务操作约有 11 次连接借还：客户端读取 5 次、用户读取 3 次、审计权限预检 1 次、decision 提交 1 次、令牌事务提交 1 次。连接从实际获取至归还的总占用是直接瓶颈；单次令牌事务有约 16 个 SQL/事务事件，是最大持有者。D1 估算约 41.8ms 连接占用/操作，800/s 对应约 33.4 个并发占用，已超过原 pool=32；这解释排队，但并不授权扩大连接池，也未证明下层等待的最终根因。

发现四个固定函数调用使用动态 `sql_query`，不能复用 Diesel 的静态 prepared statement 身份。修复仅为现有调用定义私有 QueryFragment/QueryId，复用原连接自己的 statement cache：审计权限预检、单事件 append、decision commit、refresh contract ensure/reference。无结果缓存、权限缓存、额外队列、恢复层或数据库迁移。

调用的 SQL 函数、参数顺序和类型不变；append/decision 仍 drain `load()` 到语句结束；事务所有者仍等待 COMMIT；取消时连接丢弃、contract 引用锁、消费 fence、撤销/重放/租户边界和所有 TTL 均未改变。此前有查询计划风险的 miss-heavy family presence / cardinality-sensitive capacity 查询仍保持原行为。

新增测试在 A 上成功编译并实际执行后，以“prepared shape 数量 0 而非 1”失败（exit 101）；B 上通过，且检查不同事件身份、时间和 payload、decision 冲突与一次性 grant、不同 contract 参数，避免错误缓存结果。见 cache-before/cache-negative-all/cache-regressions 及完整 package 日志。这个负向证明针对重复 prepare，不是容量失败已修复的证明。

## 修前/修后连接账本

每行均值毫秒，按固定代码位置归属，不使用用户/请求 ID 标签。SQL/事务细分采样 1/32；连接计数/获取等待/持有时间按秒汇总。业务倍数由调用链与计数交叉核对；采样窗口边界存在在途操作，不能把汇总计数强行当成精确逐请求追踪。

| 阶段 | 次/完整操作 | D1 获取等待 | D1 持有 | D2 获取等待 | D2 持有 |
|---|---:|---:|---:|---:|---:|
| client 读取 | 5 | 96.272 | 1.291 | 156.277 | 2.099 |
| user 一类读取 | 1 | 92.974 | 1.519 | 154.238 | 2.455 |
| user 另一类读取 | 2 | 94.986 | 1.257 | 155.673 | 2.123 |
| 审计权限预检 | 1 | 94.053 | 2.588 | 156.488 | 2.493 |
| decision 提交 | 1 | 94.381 | 5.467 | 159.821 | 4.950 |
| token 提交 | 1 | 96.873 | 23.242 | 159.426 | 27.651 |

令牌事务采样：D1 持有 23.762ms，其中普通 SQL 等待 19.379、COMMIT 3.668、BEGIN 0.658、其余约 0.057；D2 持有 26.982，其中普通 SQL 22.039、COMMIT 4.011、BEGIN 0.877、其余约 0.055。样本均值与全量持有均值不同，不得混用分母。

应用任务调度：issuance owner D1/D2 poll wall 为 0.229/0.230ms，wake-to-poll 为 0.260/0.660ms；decision owner 为 0.051/0.063ms、0.208/0.489ms。SQL 计时是客户端 await 墙钟，包含网络/驱动/调度；poll wall 也可能包含操作系统抢占，ready wait 与 SQL await 重叠。这不是纯应用 CPU 与纯服务端 SQL 的互斥分解。HTTP 任务及连接驱动任务未独立完成调度归因，仍是未解决项。

PG 采样按运行角色、exporter、postgres 观测角色分开。ClientRead 可同时包含空闲池连接和事务中客户端等待，不把全实例 ClientRead 算成应用借出连接。pg_stat_statements 只以 runtime + toplevel 汇总，避免 SECURITY DEFINER 嵌套 SQL 重复计算；其覆盖暖机/正式/排空，不能冒充精确正式窗或 COMMIT fsync 时间。原始角色计数和阶段账本随报告发布。

D2 中未修改的 client/user 查询持有时间也明显增长；编辑路径的部分下降不能单独归因为代码。共享 CPU 是限制，未证明它解释全部差值。D3 单线程实验也未达到门槛，已拒绝。

## 原负载、正式结果和时序

所有原门槛保持：完整操作 P95/P99 <=100/250ms、成功率 >=99.5%、drop <=0.1%。应用 Disabled anchor，pool32；PostgreSQL fsync/synchronous_commit/full_page_writes 均 on。负载来自原已归档请求，未猜参数：授权码16CPU 800/s、992VUs；撤销16CPU 960/s、992VUs；mixed1CPU 400/s、64VUs；mixed16CPU 1600/s、992VUs。mixed 保留 argon2/meta/fapi/refresh 四个侧车及原速率、主体分布、窗口；完整请求 JSON 随附。

A06 恰与已空闲的测试数据库 checkpoint 重叠，不能作干净因果对照。该数据库于 17:17:11 UTC 停止，早于 B06 负载；A06R 为排除该已知并行负载的补测。A06R 与 B06 仍有时间间隔，不把后验重复当作同期控制。四个初始 mixed 点遇到进程 affinity 初始化失败，保留 INVALID；A03R 明确观察首次绑定后仍有新子进程线程保留全部可用 CPU，第二次绑定全部落在目标集合。重复点记录最多三次原 pin 函数结果，仍要求完整绑定验证和全部侧车共同窗口，未绕过 gate。

表内 D 为诊断，A/B 为正式；INVALID 无法给出完整可信业务指标。

| 点 | 判定 | 成功 ops/s | P50/P95/P99 ms | drop 数 / 比例 | 非预期错误 | 未完成 |
|---|---|---:|---|---|---|---|
'''.replace('SOURCE',source)
for r in rows:
 if 'success_ops_s' not in r:
  s+=f"| {r['key']} | INVALID | — | — | — | {r.get('point_error',r.get('invalid_reason'))} | — |\n";continue
 l=r['latency_ms'];s+=f"| {r['key']} | {r['verdict']} | {r['success_ops_s']:.3f} | {l['p50']:.2f}/{l['p95']:.2f}/{l['p99']:.2f} | {r['dropped']} / {r['drop_fraction']*100:.4f}% | {r['unexpected_errors']} | {r['unfinished']} |\n"
s+='''
成功/错误/预期拒绝、started/completed、共同测量窗、侧车 gate 与 CPU 的完整结构见 `round-analysis.json` 和各点原始 short-result。`time-analysis.json` 用完整流的 cap_iter_ms 直方图按完成时间分组，给出 10 秒 P99 所在区间（不是精确分位数）；原每秒 series 保留 drop。全部完成数量与正式 cohort 对账。诊断原始流按尾部/周期采样，不能用其重算无偏 P99；正式 gate 仍以原 harness 完整窗口精确结果为准。有限 VUs 和高 drop 可以把 P99 截平，因此短窗 P99 平稳不能证明目标负载没有积压，也不能用较低 P99 抵消吞吐损失。

| 正式点 | WAL 字节/成功操作 | 应用/PG CPU 核 | DB 首/末/峰值 bytes | 采样跨度 s |
|---|---:|---|---|---:|
'''
for r in rows:
 if not r['key'].startswith(('A','B')) or 'storage_sampling' not in r:continue
 t=r['storage_sampling'];s+=f"| {r['key']} | {r['wal_bytes_per_success']} | `{json.dumps(r['cpu_cores'],ensure_ascii=False)}` | {t['db_first']}/{t['db_last']}/{t['db_peak']} | {t['end']-t['start']:.1f} |\n"
s+='''
DB 是各自采样跨度内物理大小，未统一到成功业务量，不能从总量低直接推断效率高。WAL 沿用原 harness 正式窗口按成功操作归一化。完整 CPU、WAL、Valkey、PG 表统计和存储时间序列均保留。

## decision 自然回收终态

D2 跟随器在最后一次应用重建后绑定实际容器 ID `693f535f4efa8dd74bdff67d3db78c77a152cc928171ad5c310dba5039c97d08`；观察期间核对实例未变化，并收集该实例最终完整维护日志。D2 带最终生产修复的诊断构建；之后最终源码只有格式/测试整理，维护仓库/job、pool 和 token transaction 的不变哈希见 chain-review，不能把这次观测称为最终无采样二进制重新压测。

冻结批次 43,601 条，记录每条 event_id、business_retain_until、exported_at、occurred_at。最后保留期到 `2026-10-08 16:47:22.945116 UTC`。行数自然从 43,601 → 38,047 → 3,887 → 0。最后完整维护周期于 `16:48:16.749989 UTC` 完成：`stop_reason="drained" batches=16 rows=3887 issuances=0 elapsed_ms=196 next_delay_ms=60000`。`16:48:18.079113 UTC` 独立 SQL 观察 remaining/eligible/retained/unexported 均 0；全部周期 decision 删除合计 43,601。

其他合法安全状态仍在：9,920 个 live family、43,601 条 issuance、992 个被引用 contract；orphan/pending/expired decision 均 0。未手工删除目标数据、缩短 TTL 或手工 vacuum。维护调度无需修改。

DB/receiver/签名 checkpoint 对齐在 121,875；新增及接收事件同为 121,875，journal 连续，无 gap/重复 sequence：decision 43,601、token_issued 43,601、capacity_retired 34,673。`token_issued_scope=reported_only_no_clean_denominator` 原证据限制仍保留，不把事件守恒包装成额外完整业务成功率证明。

结束物理数据库 115,537,599 bytes（初始 12,490,431）；audit table 24,576 bytes，索引仍约 27,115,520 bytes。这是清理后的物理高水位/尚未复用空间，不能称仍有逻辑 pending。pg_stat 删除计数可能滞后最后批次，直接行数和完成周期是终态依据。未证明无限导出故障下 Optional/Disabled 磁盘有界，也未证明原目标负载长期拉平。

## 实际质量命令与失败保留

所有命令在授权容器执行；各 `*-exit.json` 保存实际子进程退出码，外层 SSH 脚本成功不代替 cargo 成功。

'''
for f in sorted(E.glob('*-exit.json')):
 x=json.loads(f.read_text());s+=f"- `{' '.join(x['command'])}` → **{x['exit']}**；`{f.name}`。\n"
s+='''
初次 package suite 缺 NAZO_AUDIT_TEST_DATABASE_URL，后续指定数据库又触发 audit_test 名称保护，原 exit101 均保留，不计通过。修正隔离夹具后补跑受影响目标，最终逐 target 对账为 511 passed、0 failed；不是声称最初那条命令 exit0。最终相关真实 PG 测试覆盖晚期提交错误、取消可能已提交、断连、独立连接看到旧 backend 消失及替换连接可用。DataRow 后错误不得返回确认成功。详见 `commit-boundaries-fixture-completion.log`；部分取消 durable_changed=true，未强行断言回滚。

各压测 setup/point 完整命令及退出码见 `formal-commands.jsonl`；exit2 对应 FAIL 或 INVALID，须看原始 verdict，不能互换。各物理测点均受原单点十分钟上限约束。多次实验累计时长不冒充单次时长。

## 剩余问题与证据索引

1. 原容量门槛尚未通过。prepared statement 缺失已修，尚无可靠证据证明总体吞吐提升；不承诺无回退，不建议据本报告宣布合并标准已满足。
2. 下一个有区分力的诊断应分开连接驱动任务调度、套接字往返、事务内 server 执行与提交同步等待；当前 SQL await 与 owner poll 不能完全分离它们。不能先增池、删锁/提交确认或归咎共享 CPU。
3. 若 mixed 重复仍 INVALID，缺失的是完整绑定/共同负载窗口，不能通过源码审查替代实测。
4. 本轮 decision 目标批次回收已闭环；不扩展为全库清空、目标负载长期稳态或无限导出故障存储上界。

`artifact-index.json` 列出原始及发布文件 hash/size。容量原始流只保留 cap_*、dropped_iterations、iterations、vus/vus_max 原行，省略可能携带请求 URL 的 HTTP 细节；过滤规则和计数明确记录，未改原指标。签名 journal 大文件留在隔离证据中，发布其 hash、事件数量和 checkpoint 对账；不发布私钥、运行凭据和原始审计 payload。完整配置请求、PG 角色序列、存储 CSV、连接账本、GC cohort、维护日志及命令证据随报告保存。历史报告未覆盖。
'''
s+='\n## mixed 侧车结果（保留原独立门槛）\n\n| 点 | 主链路 | 侧车 | 判定 | 成功 ops/s | P95/P99 ms | drop |\n|---|---|---|---|---:|---|---:|\n'
for r in rows:
 for name,gate in r.get('sidecar_gates',{}).items():
  m=gate['metrics'];l=m.get('complete_operation_latency_ms') or {};w=m.get('measure') or {}
  s+=f"| {r['key']} | {r.get('main_verdict')} | {name} | {gate['verdict']} | {m.get('rate_for_gate')} | {l.get('p95')}/{l.get('p99')} | {w.get('measure_drop_fraction')} |\n"
(P/'README.md').write_text(s);print('report generated',len(s))
