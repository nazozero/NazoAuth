# PR #230 继续修订验收：连接占用、审计查询与存储收敛

本报告延续 [前轮报告](../../publish/README.md)，保留所有失败和无效证据，不把执行结束等同于验收通过。最终合并到 main 由仓库所有者执行。

## 版本、整合和边界

- BASE_SHA / A：`67f836f2b616e811ce9a20bb857a01ea9517b42b`。
- 应用镜像 TEST_SOURCE_SHA / H：`6b1e40f05d4d93eedc330a8d76eb441c826627b1`；同一原分支正常提交、推送。
- 二进制 SHA256：`9d20a450c5e828016af3965d3a08d71d30c45d4cd72d99be64d75e481172f6a6`；镜像：`sha256:a0c0bf6fe70c1063025b918558eef031950c75fb04ed9e88cf82e844c466ebbc`。
- 本轮唯一开放 PR 为 #230。#222–#228、#231–#235 均已关闭为被替代项；逐个 `git merge-base --is-ancestor <PR_HEAD> HEAD` 均 exit 0，证明其完整 HEAD 被包含，见 [consolidation.json](consolidation.json)。没有合并 PR 或部署。
- 所有主动构建、测试、压测和数据分析使用已有授权 CNB 隔离容器、唯一 `/src` 与 `/src/target`；没有第二 checkout、worktree、生产数据库或宿主进程探测。共享 CPU 的 affinity 不代表独占物理核心。
- Rust 1.99.0、压测/控制器 Python 3.14.8、PostgreSQL 18.6、Valkey 9.1.2；新 runner 保留系统 Python 3.13.5 用于环境脚本，最终静态/依赖/加密/压测工具门禁使用 Python 3.14.8 并单独记录。PG `fsync`、`synchronous_commit`、`full_page_writes` 保持 on。性能池 32，原负载、VUs、主体、成功定义及 100/250ms P95/P99、99.5% 成功和 0.1% drop 门槛均保留。
- 报告提交只增加证据/文档；其最终 PR HEAD 在 PR 评论单独给出，不冒充被测源码 SHA。旧工作树 stash 的对象保留在 refs/stash，且有独立恢复 bundle；恢复元数据见 resume-provenance.json。

最终源码与测试 SHA 为 `ec4d98e13ff652b2039fb3a3da393b27bbcbda82`，包含最后的压测夹具修复。该提交与 H 的 crates、migrations、Cargo 输入差异为空；此前 A/B 和持续负载采用上面的 H。新 CNB 的最终故障点重新编译 I，二进制 SHA256 `0b61ace5f8f6c61c3e88e15aab776081bba4840b88b3ada517c72a0ed952bfc7`，镜像 `sha256:992f6f09cc7450f5c4e3bc0507dcb954c0495cf2e75c0bb93f67b917cf1a4b1a`；详情见 [image-I.json](image-I.json)。完整套件针对最终源码运行，性能镜像身份与夹具身份分别记录，见 [fixture-equivalence.json](fixture-equivalence.json)。

## 确认的根因与最短修复

1. **回收反复排队取连接。** 一个有界 cleanup batch 原先七次向同一个池申请连接。在饱和流量下，每次等待约 180–340ms，30 秒工作预算被重复排队消耗。真实 PG 单连接池回归让清理先获准、后续借用者持有连接：旧实现失败（exit 101），新实现能在后者释放前完成。现在一个批次持有同一现有连接，七类清理仍各自保留原事务、cutoff、游标和 256 行边界；取消/失败仍由既有 DiscardOnDrop 丢弃连接。没有新增池、队列、重试或外层事务。
2. **审计导出查询读取放大。** F2 后段真实 SQL 统计出现 ACK 成员校验每批约 10 万次缓冲区访问、约 70ms，链追加也放大。F2 性能总点因收集超时仍为 INVALID；独立 SQL 序列仅用于诊断。随后真实函数回归在过期统计下处理 256 个事件，旧 ACK 读取 207,325 个共享缓冲区块并失败，新实现约 6,500 个并通过。新增迁移让 stage 先按唯一 ID 锁定一行再检查导出状态；ACK 先物化有界序列成员，再逐个查唯一 ID。额外第 257 项与原 DELETE 精确计数保留越界/损坏拒绝。
3. **控制面取消测试的观察竞争。** 生产提交/锁语义未变。测试在取消前取得独立 peer，在原三秒范围内等待服务端释放 advisory lock，避免把异步断连尚未处理的一瞬间当作泄漏；不通过取消后的池借用触发清理。定向模块与重复取消测试均保留。

4. **压测 EC 密钥编码。** `perf/seed.py` 对 P-256 的 x/y/d 误用了 RSA 最短整数编码，固定测试密钥复现 31 字节公钥坐标。现在保留固定 32 字节及前导零，RSA 不变，回归先失败再通过。p03-H1 的 FAPI sidecar 有 270 次意外 DPoP 错误，该点不用于完整业务性能比较；原密钥已正常清理，无法直接证明其就是该轮原因，因此保留推断边界，并使用修正夹具补 p03-H2。没有放宽服务端 DPoP 校验。

新增 SQL 不改变函数身份、owner、ACL、SECURITY 模式、search_path、generation fencing、部署检查、签名回执、提交屏障或安全保留期限。迁移 down/up 往返比较这些属性及完整函数定义。孤儿 contract 的宽限删除仍由前轮真实引用竞争证明，当前完整维护测试继续覆盖。详见 [第二次链路复核](chain-review.md)。

## 实际质量与故障命令

完整命令、退出码、源码、日志 hash 和测试计数见 [commands.json](commands.json)，原记录见 [commands.jsonl](commands.jsonl)。

| 检查 | 结果 |
| --- | --- |
| 最终 static contracts / persistence dependency graph / fmt | 见最终逐项 exit 0 日志 |
| 最终 workspace/all-targets/all-features Clippy，`-D warnings` | 见最终 exit 0 日志 |
| 新 bounded-read 回归与迁移身份/权限往返 | 1 通过，exit 0 |
| 真实 PG `audit_commit_boundary` | 4 通过，含 18 个晚期错误/取消/断连子场景，exit 0 |
| PG preflight roles / audit ledger | 1 / 19 通过，exit 0；含 1,500 万条 pending 规模和自然 autovacuum |
| 最终完整 workspace suite | exit 0；3658 passed / 0 failed / 4 ignored；179 个测试结果块（运行结果汇总，不将忽略项算作通过） |
| 最终 I release build / receiver build | 均 exit 0；见 prepare-release.log、prepare-receiver.log 与 [image-I.json](image-I.json) |
| 最终 I 的 GitHub checks | 12 SUCCESS / 2 条件 SKIPPED，CLEAN / MERGEABLE；[快照](I-github-checks.json) |
| Python 3.14.8 压测工具 / 加密守卫 | 425 / 23 tests，均 exit 0 |

首个完整套件因新建数据库漏跑迁移而 17 项失败；补齐后发现并修复取消观察竞争。原失败日志全部保留，最终完整套件单独记录，不能用定向重跑冒充整套 exit 0。最初新增迁移 checksum 未登记也被静态门禁拒绝；随后用仓库 append-migration 命令登记。初次静态检查日志路径被后续调用复用，commands.json 明确标记，并保存当时终端错误；没有将后次日志 hash 当成初次失败证据。ignored 项仍是外部/显式入口，不计为通过。新控制器运行 dependency guard 曾因不含 cargo 而退出 1；该守卫随后在具备锁定 Rust 与 Python 3.14.8 的 runner 上 exit 0，最终源码的 GitHub 门禁也通过。两次执行各自记录，不把环境失败删除或改为成功。新 CNB 第一轮全套有 5 项因独立 audit 夹具名称缺少 audit_test 标识而被安全保护拒绝，另 2 项因受限角色测试要求 oauth 库而在授权准备时失败；将两个数据库名称完整对齐 CI 后，启用 CI 必需夹具检查并重跑完整套件。该次失败日志与退出码仍在 commands.json。

Required 单条、已有两条和 64 条批次在不推进虚拟时钟时即开始写入，最多 64 条；提交屏障未解除不得成功。批次失败使全部等待者失败，不重试该批，后续正常调用仍可提交；满队列、关闭、取消和 worker 停止均有覆盖。Telemetry 保持原 10ms 凑批、4096 队列与同一批次/event_id，Required 队列不受其退避阻塞；Optional/Disabled 原策略保留。exporter 的实际 repository 调用测试结合签名 HTTP receipt，覆盖连续 ACK、首次 observe、重启、空闲心跳、过期/未来观察时间、deployment 变化、永久拒绝、重复回执与 ACK 失败。

真实 PG 证据包含：第一行 DataRow=true 后 SQLSTATE 23514、独立连接无持久事件；晚期取消或断连后的物理 backend 消失与替换；ACK 实际提交但 ReadyForQuery 确认丢失时调用失败、旧连接丢弃、已有 checkpoint 收敛、过期 generation 被拒绝。取消可能已提交，未把不确定结果写成必然回滚。mTLS bundle 的真实 HTTP 路径在 PG 延迟提交失败时返回 503、无附件、无事件；恢复后返回 200 且恰好一条 Required 事件。数据库可写但 Required anchor 不健康时也返回 503、无附件、无追加事件；独立提交屏障与 anchor 准入分别覆盖。此前原始证明在前轮报告的 focused-round4-2.log，本轮完整套件继续执行该 mTLS 模块。

## A/B 原始性能

四个优先点使用原 Disabled anchor 配置；框架 `audit_mode=required` 表示真实外部导出与对账，不等于应用 Required anchor。持续/故障点显式核实应用 Required。A 没有重跑 main；A2 为同一固定 PR 基线。授权码、撤销的 A2 早于 H，窗口间隔和共享 CPU 都限制因果归因。mixed A2/H 接近交错执行。原始时间戳、完整 cohort、sidecars、CPU 和 SQL 均在各点目录。

| 点 | 版本 | 原容量门槛 | 成功 ops/s | P50 / P95 / P99 ms | 正式 drop | WAL bytes/成功 | App / PG 核数 |
| --- | --- | --- | ---: | --- | ---: | ---: | --- |
| p06-A2 | A | FAIL | 629.050 | 1313.00 / 2545.00 / 2901.00 | 10255 | 11256.89 | 1.93 / 3.61 |
| p06-H1 | H | FAIL | 515.233 | 1867.00 / 2370.00 / 2441.87 | 17086 | 10986.38 | 1.51 / 3.44 |
| p10-A2 | A | FAIL | 543.400 | 1665.00 / 2654.00 / 2874.00 | 24995 | 10948.09 | 1.98 / 3.71 |
| p10-H1 | H | FAIL | 474.767 | 2083.00 / 2385.00 / 2474.00 | 29114 | 10852.37 | 1.55 / 3.08 |
| p03-A2 | A | FAIL | 400.000 | 18.00 / 100.00 / 144.00 | 0 | 3202.96 | 0.67 / 1.02 |
| p03-H2 | H | FAIL | 400.000 | 23.00 / 134.00 / 206.00 | 0 | 3159.53 | 0.67 / 1.07 |
| p04-A2 | A | FAIL | 1447.117 | 356.00 / 1719.00 / 2116.00 | 9173 | 3553.65 | 3.06 / 3.87 |
| p04-H1 | H | FAIL | 1157.983 | 639.00 / 2267.00 / 2501.22 | 26519 | 3263.68 | 1.97 / 2.76 |
| sustained-A2 | A | FAIL | 396.150 | 2419.00 / 3522.00 / 3798.00 | 101493 | 10947.60 | 1.48 / 3.13 |
| sustained-H2 | H | FAIL | 414.206 | 2400.00 / 2773.00 / 2910.44 | 98244 | 10963.64 | 1.50 / 3.04 |
| sustained-H1 | H | FAIL | 381.900 | 2587.00 / 3078.00 / 3271.00 | 190774 | 11905.99 | 1.39 / 2.88 |

授权码/撤销 15 秒预热+60 秒正式；mixed 保留原 60 秒预热+60 秒正式与 sidecars。sustained-A2/H2 正式 180 秒，H1 正式 330 秒；每点运行和清理有独立回执。E 的全池 TRACE 点只作诊断；G 和 F 的中间结果保留在 ab-analysis.json，不重标为最终 H。

**不能只按 P99 判断。** 有界 VUs 加上大量 drop 本身就可能把尾延迟限制在固定范围；这不是承载了全部目标流量。报告分别保留吞吐、丢弃、CPU/WAL、周期回收与 P99 分段。完整每秒直方图可复核，10 秒分段的 quantile 上界不是精确 P99。可选 diag 流经过抽样，不能用于恢复整个人群的精确分段 P99；尝试时发现 847/24000 数量不符，已拒绝该分析，见 trend-evidence-boundary.json。

[H2-app-schedstat.json](H2-app-schedstat.json) 只读取应用容器的 `/proc/1/task`：约 30.9 秒内，34 个相同线程累计运行 45.43 秒、可运行但等待 CPU 166.98 秒。它证明存在显著调度等待，不能解释为 SQL/network 睡眠；不能据此识别其他租户或唯一分离配额、拓扑、运行时和外部竞争。没有探测宿主。后续指定点相同采样另附原始记录。

按原门槛，四个优先点均为 FAIL。授权码成功吞吐约下降 18.1%，撤销约下降 12.6%，mixed16 约下降 20.0%；mixed1 吞吐保持 400/s，但 P95/P99 从 100/144ms 到 134/206ms。这些实测退步全部保留，不能宣称已经统计证明无回退。与此同时，ACK 单批耗时显著下降，observe 次数从接近每批一次降为心跳所需，低流量 Required 的 P95/P99 由约 40.65/46.87ms 降至 27.05/37.12ms。新版本还实际执行了此前积压的清理工作，PG 每操作成本包括这部分必要工作。应用进程的 runnable 调度等待证明确实受到 CPU 服务不足影响，但不能唯一证明全部差异来自其他租户。第二次链路复核未发现剩余代码缺陷，因此按照用户明确认可的共享资源例外，可将容量失败与代码合并判断分开；该例外不修改测量状态，也不证明生产容量达标。

## 实际 exporter SQL 与低流量 Required

以下来自 pg_stat_statements 前后差值，窗口含预热、正式及排空；不是仅正式 60 秒。调用次数与窗口长度一起给出。

| 点 | SQL 窗口秒 | ACK 次数 / 每秒 | observe 次数 / 每秒 | ACK 平均 ms | finalize 平均 ms | 导出事件数 |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| p06-A2 | 114.48 | 614 / 5.363 | 632 / 5.521 | 24.730 | 22.786 | 127806 |
| p06-H1 | 102.89 | 1697 / 16.493 | 14 / 0.136 | 5.659 | 4.586 | 114753 |
| p10-A2 | 116.90 | 621 / 5.312 | 636 / 5.441 | 45.395 | 28.508 | 115998 |
| p10-H1 | 107.87 | 1581 / 14.657 | 16 / 0.148 | 5.399 | 4.373 | 107226 |
| sustained-A2 | 308.72 | 3786 / 12.264 | 3843 / 12.448 | 6.716 | 5.068 | 233283 |
| sustained-H1 | 410.74 | 7426 / 18.080 | 34 / 0.083 | 4.758 | 3.688 | 397899 |
| sustained-H2 | 323.42 | 4759 / 14.714 | 65 / 0.201 | 4.295 | 3.452 | 242250 |

observe 的减少有实际 SQL 调用支撑，未关闭首次绑定校验或空闲心跳。Required 持续点每操作健康读取仍存在；其运行时健康查询总耗时均值 A2 0.344ms、H2 0.288ms，不意味着所有场景都零成本。回执签名、deployment、generation 与前缀/hash 校验由完整套件及真实故障后的数据库/receiver checkpoint 对账分别验证。

低流量 mTLS trust-bundle 导出 A/H 各 30 次，全部 HTTP 200 且有附件，两端最终各对账到 30 个事件。A 的 P50/P95/P99 为 20.93/40.65/46.87ms，H 为 8.14/27.05/37.12ms；原始逐次时间与对账见 [A](p06-A2/low-required.json)、[H](p06-H1/low-required.json)。30 次短探针不能替代尾延迟容量分布。


CPU 取正式测量窗口内进程 jiffies 增量的采样均值。下表再除以同窗口成功完整操作速率，是近似成本（原核数已四舍五入），包括背景清理及 mixed sidecars，不是某个 HTTP handler 的纯执行时间。

| 点 | App CPU ms/成功操作（约） | PG CPU ms/成功操作（约） |
| --- | ---: | ---: |
| p06-A2 | 3.07 | 5.74 |
| p06-H1 | 2.93 | 6.68 |
| p10-A2 | 3.64 | 6.83 |
| p10-H1 | 3.26 | 6.49 |
| p03-A2 | 1.68 | 2.55 |
| p03-H2 | 1.68 | 2.67 |
| p04-A2 | 2.11 | 2.67 |
| p04-H1 | 1.70 | 2.38 |
| sustained-A2 | 3.74 | 7.90 |
| sustained-H2 | 3.62 | 7.34 |

这些值将已完成工作与总 CPU 分开，但仍不能单独识别外部调度、内部并发、背景回收或 sidecar 业务量的因果占比。

## 存储增量与持续负载

| 点 | 采样秒 | 物理 DB 增量 MB | pending 峰/末 | eligible family 峰/末 | eligible decision 峰/末 | 孤儿 contract 末 | Valkey 测后 MB |
| --- | ---: | ---: | --- | --- | --- | ---: | ---: |
| p06-A2 | 98.00 | 270.680 | 8681/0 | 30210/0 | 0/0 | 992 | 18.265 |
| p06-H1 | 89.84 | 194.527 | 1513/0 | 30610/0 | 0/0 | 0 | 16.745 |
| p10-A2 | 99.22 | 211.640 | 16623/0 | 29194/0 | 0/0 | 992 | 15.823 |
| p10-H1 | 95.37 | 158.532 | 195/0 | 19838/19838 | 0/0 | 0 | 14.812 |
| p03-A2 | 172.71 | 40.927 | 635/0 | 3521/5 | 3603/1267 | 176 | 5.150 |
| p03-H2 | 182.36 | 40.305 | 833/0 | 3529/24 | 2753/2704 | 0 | 5.125 |
| p04-A2 | 178.46 | 201.720 | 983/0 | 8607/1044 | 8205/8205 | 1473 | 22.576 |
| p04-H1 | 174.65 | 145.195 | 255/0 | 6978/0 | 11792/1659 | 0 | 17.994 |
| sustained-A2 | 297.04 | 256.942 | 591/0 | 56001/0 | 39552/20550 | 992 | 22.348 |
| sustained-H2 | 308.03 | 247.128 | 209/0 | 24782/0 | 24793/12954 | 0 | 21.894 |
| sustained-H1 | 394.07 | 322.699 | 1677/0 | 24264/2459 | 24547/15460 | 0 | 26.848 |

DB 是各自实际采样期的物理分配变化，不是统一正式窗口，也不是每操作成本；WAL 已按正式成功完整操作归一化，mixed 还包含 sidecars。Valkey 是整实例内存。进程内存使用 app RSS，未将共享 cgroup 内存或 PG 共享页重复 RSS 当作私有占用。WAL I/O timing 未启用时的零值不代表实测 fsync 耗时为零。

H1 的 330 秒正式窗口，family 从首样约 6,458 到末样 411、decision 末样 556；中间有周期峰谷而不是持续单向积压。pending 峰 1,677、最老约 1.66 秒，停压归零。实际 SQL 成本序列在后段保持 ACK 成员每批约 200–274 个缓冲区访问，未重复 F2 的十万级放大。H1 的 30 秒停压窗短于清理休眠，不能单独证明下一轮回收，因此补 H2 的 90 秒停压窗。

H2 正式窗口 pending 从 36 到 21，最大年龄约 0.28 秒；eligible family 从 6,102 到 1,314，停压后归零。decision 在下一轮从约 24,793 降至 1,186，随后先前合法保留的记录到期，末值又增至 12,954，等待后续周期。没有提前删除仍在安全期内的证据，也没有宣称全部物理文件会立即缩小或每时每刻 eligible 都为零。A2 同时长正式窗口 family 约 6,720→53,548，反映旧回收持续落后；H 的周期追赶是本轮实际修复目标。 同为 180 秒的 H2 实际完成约 414.21/s，高于 A2 的 396.15/s；因此这组窗口中的追赶不能简单解释为新版本处理了更少请求。不过两者都没有承载完整 960/s 目标，不能由此推出满目标下稳定。

H2 相对同为 180 秒的 A2，WAL 约 10,947.60→10,963.64 bytes/op；H1 更长窗口涵盖更多 decision 到期回收，约 11,905.99 bytes/op，不能把不同窗口直接当作单纯追加写放大。所有原始 tables/index bytes、insert/delete、dead tuple、autovacuum、合法保留行、eligible 行、pending 年龄、CPU/Valkey 在各点 JSONL 和 storage-series.csv。

存储验收仅覆盖本轮实际接纳速率和短测窗口：健康持续写入时，pending 保持低龄，eligible family/decision 有周期下降，停压后 pending/family 收敛；其证据强于仅停压后排空。原目标负载存在大量 drop，因此不能声称服务覆盖全部目标产生速率。合法保留的 replay/SingleUse/审计证据不提前删除；物理高水位、死元组等待 vacuum、已分配页不立即缩小均单独展示。Optional/Disabled 在 exporter 长期不可用时依然允许磁盘待办增长，这是其原策略边界；本轮 Required 的故障限制不可泛化到这两种模式。

## 最终 Required 故障、恢复与排空

本节目录沿用 `fault-H1`，实际测试源码明确为 I/ec4d98e1；不能按目录名推断被测 SHA。新容器只按可用 affinity 重新映射 CPU 编号，核数、负载及故障时序不变。应用 Required，独立故障 fixture freshness/max_lag=10s，不改生产默认或安全 TTL。0–40s 健康，40–90s receiver HTTP 500，90–135s 恢复，135–185s 永久拒绝，185s 恢复并使用现有 operator unblock，240s 停止新增，观察到 400s。负载为 200 Telemetry reads/s + 1 Required bundle/s。

| 阶段 | Required 200 / 503 | Telemetry 200 | PG pending 首/末/峰 | checkpoint 首→末 |
| --- | --- | ---: | --- | --- |
| healthy | 39 / 0 | 7800 | [1, 32, 359] | [0, 7002] |
| http500_grace | 12 / 8 | 4000 | [92, 2210, 2210] | [7951, 7951] |
| http500_unhealthy | 0 / 30 | 6000 | [2210, 2210, 2210] | [7951, 7951] |
| recovery | 7 / 38 | 9000 | [2210, 65, 2210] | [7951, 10809] |
| permanent_rejection | 0 / 50 | 10000 | [64, 64, 64] | [11003, 11003] |
| recovery_after_unblock | 21 / 34 | 11000 | [64, 0, 66] | [11003, 12495] |
| stop_drain | 0 / 2 | 201 | [64, 0, 64] | [12624, 16848] |

实际队列与提交计数：

```json
{
  "telemetry_http_200": 48001,
  "required_http_200": 79,
  "worker_persisted_events": 16847,
  "telemetry_queue_full_rejections": 31233,
  "inferred_unpersisted_accepted_events": 0,
  "inference": "HTTP Telemetry reads each enqueue one event; Required 200 corresponds to one worker event; registration commits in business SQL. Counts are derived, not an internal queue gauge.",
  "sampled_inferred_max": 4160,
  "sampled_inferred_last": 0,
  "inference_timing_limit": "HTTP completion and log timestamps can straddle sampling boundaries; this is accounting, not a direct internal gauge."
}
```

计数来自 HTTP 与 durable/rejected 日志，不冒充直接 queue gauge。4096 队列+64 当前批次的机制边界另由测试证明。故障触发健康门禁后 Required 不返回附件成功，Telemetry 过量拒绝可观测；恢复仍保留旧 event_id 与 occurred_at。旧事件重新进入 PG 时可能再次触发 max_lag，恢复阶段的 503/拒绝如实保留，不绕过健康门槛以换取吞吐。原始签名接收端对账、401 个逐秒 HTTP 样本与周期性存储采样、持久化/拒绝事件提取及最后 checkpoint 在 [fault-H1](fault-H1/analysis.json)。

最终故障的全部校验通过。Telemetry HTTP 200=48001，Required HTTP 200=79，worker 持久化=16847，queue_full 拒绝=31233，推算已接受而未持久化剩余=0。最后数据库与 receiver 序列同为 16848，hash 和 deployment 也一致。HTTP500 健康门禁后、永久拒绝稳定期的 Required 成功数和 worker 新写入均为 0。排空后空闲窗口 observed_at 继续更新，证明心跳仍工作。恢复期间的 503 和过量 Telemetry 拒绝仍保留；不将其称为无损恢复。


最终故障点的实际 SQL 调用：ACK 327 次、finalize 327 次、observe 175 次、fail-batch 8 次。最后 durable append 之后，PG pending=0 且 anchor 固定于最终序列的样本中，observed_at 有 5 个不同值；该证据排除了后续 ACK 导致的更新时间，验证了空闲心跳。HTTP 共有 401 个逐秒样本，SQL 存储采样 81 个。

## 验收与合并判断

| 维度 | 状态 | 范围 |
| --- | --- | --- |
| CODE | PASS | 最终 I 完整 workspace suite exit 0：日志结果块合计 3658 passed、0 failed、4 ignored；fmt、静态边界、依赖隔离、Clippy、release 与 Python 工具门禁通过。46 个评审讨论已解决。 |
| SECURITY | PASS | Required 提交屏障、真实 PG 晚期错误/取消/断连及回收、真实 HTTP 失败关闭、签名回执/绑定/心跳、孤儿引用回收竞争通过；最终故障后数据库与 receiver checkpoint 完整匹配。 |
| PERFORMANCE | FAIL | 原绝对容量门槛未达到；相对吞吐退步如实保留，CPU 调度等待与必要清理工作限制因果归因。共享资源例外不等于性能测试通过。 |
| STORAGE | PASS | 限于实际接纳速率和短测窗口：健康持续负载有周期追赶，Required 故障门禁后后台追加停止，队列饱和可观测，恢复/停压后 pending 与已接受事件会计归零。原目标负载被丢弃的部分、Optional/Disabled 故障积压和长期稳态不在该 PASS 范围。 |

代码、安全与本轮有界存储修订达到所验收范围；按用户已经明确允许的共享 CNB 资源例外及第二次链路审查结果，建议将这个单一 PR 交由仓库所有者最终合并。该建议不是无条件的性能容量认证：PERFORMANCE 保持原门槛 FAIL，相对吞吐下降仍未被证明完全来自环境，不宣称“所有场景提升”或“已证明无回退”。如果合并政策要求全部原 SLO 变绿，则本报告不满足那项政策；本次可合并判断只使用用户本任务明确给出的例外。

保留的限制：

- 历史 15 点仍是 3 PASS、11 FAIL、1 INVALID；未复跑点不改状态。Signed PAR 仍缺有效性能证据。历史表及原口径见 [历史 PR 描述](historical-pr-body-67f836f2.md)，它不是当前候选的全矩阵认证。
- main 未重跑，不能宣称整个 PR 对 main 已作同期无回退证明。所有短测结论限于其负载、模式、时间窗和共享资源；没有长期稳定性认证。
- 内部队列 gauge 在普通性能点仍未提供；故障点有日志会计和机制测试。未把缺失值当零。mixed 热点和分散主体的独立反事实未完成时，不能唯一归因其占比。
- 总任务已超出原两小时预算。发现真实连接调度、SQL 访问放大，以及完整测试观察竞争后继续修复验证；不宣称按时完成。单点原始运行/清理超时均保留，未从实际耗时中删除。
- F2 整体 INVALID、H1 完整 FAIL 但清理子步骤超时、初期环境准备失败等均有原始记录。后续显式清理回执不改变原测量判定。

证据提交前扫描私有 fixture 值与私钥；完整凭据、token、签名密钥和审计 payload journal 不公开。manifest.json 记录公开文件 hash。最终 cleanup.json 记录本任务负载及 PG/Valkey/S3/controller 停止、源码/target 与旧 stash 保留。没有合并、force push 或部署。

公开文本中 Git 检查发现的行尾空白及 CRLF 换行已整理；数值和内容不变，原始字节另存于 verbatim-whitespace 的 gzip 文件，前后 hash 见 publication-text-normalization.json。命令原始日志 hash 对应原字节。SSH 长连接关闭与远端实际退出码的区别见 transport-note.json。
