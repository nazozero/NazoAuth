# PR #230 本轮修订验收（2026-10-08）

这是运行结果报告。任务书保留在 `docs/project/pr230-revision-acceptance.md`；本报告不将完成执行等同于通过验收。

## 版本与执行边界

- BASE_SHA / A：`67f836f2b616e811ce9a20bb857a01ea9517b42b`。
- 收到并从远端核实的修订：`77fbcbe8a34cd754023a4518ea150071a105c774`。
- A/B 性能数据的 B_SOURCE_SHA：`ac51ace4acc7449b50a4e76a3a43f714ee5ea397`（下称 C）。
- 最终 TEST_SOURCE_SHA：`7ef6f98d5988008b320468941767b96323aadc36`（下称 D）；真实故障发现 mTLS 导出缺少 anchor 准入后新增最小修复。
- 在原 PR 分支正常提交；没有 worktree、第二份测试 checkout、第二个 Cargo target、force push、合并或生产部署。
- 所有主动构建、测试、负载和分析均在授权 CNB 隔离环境；唯一源码目录 `/src`、唯一 `/src/target`。A/B 顺序构建，保存不可变二进制，恢复候选分支后串行压测。原有未提交改动已保存，未覆盖。
- CNB 为共享 CPU、独立存储。CPU affinity 仅限定可运行逻辑核，不能证明宿主独占；没有探测宿主或使用生产数据库。
- Rust 1.99.0、Python 3.14.8、PostgreSQL 18.6、Valkey 9.1.2；测试隔离 PG/独立 audit DB/Valkey/S3，`RUST_TEST_THREADS=1`。性能连接池 32；PG `fsync`、`synchronous_commit`、`full_page_writes` 均为 `on`。真实镜像和二进制完整身份见 `perf-identities.json`、逐点 `provenance.json`。
- A 二进制 SHA256：`f2f4ae9a6093395867c1ba26af68cd097feb19994d1859843dad8aa57f920006`。
- B 二进制 SHA256：`158015a12f8ca55358f341c0edf8a28f6a15c237e55277e388d7260b7a15ae90`。

## 根因、修订与真实正确性证据

1. 原修订等待完整 PG 结果流，而不是把首行 `true` 当提交确认。核对实际锁定的 Diesel-async 0.9.2 / tokio-postgres 0.7.18 后，在独立测试库加入延迟约束触发器和协议代理。`first DataRow=true` 之后出现 SQLSTATE 23514，独立连接确认无事件；调用返回失败。
2. Genesis、Observe、Singleton、三条 Batch、ACK、Fail 共六类写入，各覆盖晚期提交失败、取消、连接中断，共 18 个真实 PG 子场景。记录旧 backend PID 消失和新 PID 替换，后续写入可完成。取消属于提交结果不确定，部分取消实际已经提交；测试检查原子性与连接丢弃，未假称取消必定回滚。
3. 代理在 ACK 的已提交 `ReadyForQuery(I)` 返回前断链：调用报错，原连接丢弃；数据库已提交 checkpoint 经现有流程恢复，陈旧 generation 被拒绝，后续批次 ACK 成功。批次原子性、同内容幂等、异内容冲突和业务 fresh-append 冲突回滚均保留验证。
4. 真实 HTTP mTLS bundle 导出：PG 延迟提交错误得到 503、无附件、无事件；恢复提交后得到 200、附件且恰好一条 Required 事件。
5. Required 单条、已有两条、64 条，在不推进虚拟时钟时即开始持久化；提交屏障未释放不能成功。失败关闭、队列满/关闭、取消、worker 停止、后续正常提交均有测试。Telemetry 保持 10ms 凑批和原有 4096 有界队列，六种健康失败保持同一批次及 event_id，饱和拒绝后恢复；Required 独立队列不被阻塞。Optional/Disabled 原策略保留。
6. exporter 实际 mock repository 调用配合真实签名 HTTP receipt：连续五次 ACK 仅首次 observe，重启增加一次 observe 而不补发 ACK；覆盖 Empty/Busy/Blocked、心跳、缺失/过旧/未来 observed_at、部署变更、永久拒绝、重复 receipt 和 ACK 失败。运行 SQL 计数另见 A/B 结果，未只测试时间判断函数。
7. 对全部生产 contract 创建/引用路径交叉核对，并用真实 PG 覆盖 writer-first、cleaner-first、提交/回滚/取消/断连、游标跳锁及最终收敛后，移除一小时人为宽限。保留同事务 contract+family、引用 KEY SHARE、清理 UPDATE SKIP LOCKED、固定 cutoff、READ COMMITTED 新快照二次 NOT EXISTS、外键与有界游标。未增加 tombstone、队列或恢复层；未缩短 spent-proof/fence/PAR 安全保留期。
8. 全套检查暴露的两项测试问题均保留原测试并修复：旧回收断言仍要求一小时宽限，改为验证新鲜孤儿可回收、活引用不被删；授权码故障 fixture 固定 client_id 与前次遗留 grant 冲突，改为每次唯一 client_id，不删除 grant 来掩盖冲突。

提交：`591405c6c32e36a39f05d506e46d59162729681d`（真实故障/竞争测试和孤儿回收）、`aaa5070f070dc9c21a897df5601a5cbfe2a9c294`（保留原回归测试并更新断言）、`ac51ace4acc7449b50a4e76a3a43f714ee5ea397`（可重复 fixture）。后两次只改测试；B 生产二进制字节相同。

## 命令、退出码与质量门禁

完整实际命令、SHA、时间、退出码、日志 SHA256 和测试计数在 `commands.json`。包括调试阶段失败记录，不筛掉失败运行。

| 检查 | 实际结果 |
| --- | --- |
| static contracts / persistence dependency graph | 均 exit 0 |
| C 的 `cargo fmt --check` | exit 0 |
| C 的全 workspace/all-targets/all-features Clippy，`-D warnings` | exit 0 |
| PG audit ledger 单元 / migration / audit ledger 集成 / preflight roles | 6 / 1 / 19 / 1 通过，exit 0 |
| security state maintenance / token issuance atomicity / authorization decisions | 26 / 15 / 4 通过，exit 0 |
| `audit_commit_boundary` | 4 测试通过，含 18 子场景，exit 0 |
| 宿主 `--lib adapters::audit` | 90 通过，包含 audit_anchor，exit 0；没有对 test=false binary 跑空测试 |
| Required bundle HTTP 定向测试 | 1 通过，exit 0 |
| `refresh_family_capacity` 更新后原模块 | 10 通过，exit 0 |
| 全 workspace/all-features/locked/no-fail-fast | 第二轮 3654 通过、1 失败、4 ignored，exit 101；失败为上述固定 client_id 的 fixture 准备冲突 |
| C 的 authorization decision 模块 | 修复后 16 项连续两次通过，exit 0；全部业务断言保留 |
| A/B release build | 均 exit 0 |

没有把全 workspace 的 exit 101 改写为 exit 0；它的唯一失败已在C 上修复并重跑整个受影响模块两次。未把 ignored 或全部 filtered 计为通过。四项 ignored 涉及 S3 子进程测试入口、在线官方 UI 初始化、外部 controller wire 输入、显式运行的 FAPI PAR 特殊入口；它们不作为本轮通过证据。完整 suite 的其他目标及真实故障测试在与 C 字节相同的生产实现上执行。最终报告提交只含证据/文档，TEST_SOURCE_SHA 与报告 HEAD 分别记录。

真实故障输出：`exact-591405c6-10.log`；真实引用/回收竞争：`exact-591405c6-7.log`；真实 Required HTTP：`focused-round4-2.log`。

## 性能和存储口径

A/B 只比较修订前 PR HEAD 与最终候选，不重跑 main。授权码 800/s、撤销 960/s、mixed 单核 400/s、mixed 16 核 1600/s；连接池、VUs、主体数量、sidecar 负载、成功定义、100/250ms P95/P99、成功比例 99.5% 和 drop 比例 0.1% 门槛均不降低。授权码/撤销 15 秒预热+60 秒正式；mixed 保留原 60 秒预热+60 秒正式及 sidecars。

吞吐是成功完整操作，不是 endpoint RPS。WAL 为正式窗口采样插值后每成功完整操作字节；mixed 包含并行 sidecars 的成本。DB 物理增量覆盖各自完整采样期，不与正式窗口混用；CPU 为平均占用核数。10 秒延迟趋势来自原始每秒直方图，分桶上界不是精确 P99，首尾边界秒不用于冒充完整 cohort 计数。

`blackbox-db-v1` 不提供连接获取等待和进程内队列 gauge；这些字段是 UNVERIFIED/null，未以 PG 排空替代内存队列证明。PG 等待采样、SQL 次数与耗时、进程内存和测试中的有界队列证明分别列出。共享 CPU 不是自动豁免；没有证据时不把变化归因于 CNB。

Telemetry 在 Optional/Disabled 模式仍可在 exporter 故障时持续生成磁盘待办，本轮未将其改为 Required，也未增加全局行数/字节硬配额。误路由 Required 的既有告警不是持久性确认；本轮 Required HTTP 证据来自实际等待独立队列提交的调用链，不能推广为任意未等待的 audit 调用都具有 Required 保证。

## 真实故障发现的追加修复与最终版本边界

C 的真实 receiver HTTP 500 / 永久拒绝期间，Telemetry 在健康门槛触发后停止继续写 PG，但 mTLS bundle 请求仍返回 200。根因是该 read-only disclosure 仅等待 Required 审计提交，没有复用 Required anchor 准入检查。提交 `7ef6f98d5988008b320468941767b96323aadc36` 在读取 bundle 前复用 `require_transactional_audit_or_unavailable()`，后面的 `audit_event_required().await` 提交屏障保留；没有新增状态/缓存/队列。

D 的 `cargo fmt --check`、全 workspace Clippy 均 exit 0；真实 PostgreSQL/Valkey 的整个 mTLS 模块 7 项通过（另含隔离子进程的 unhealthy Required anchor HTTP 回归），release build exit 0。PG 可写但 anchor 不健康时，新增回归要求 503、无附件、无追加事件；原延迟提交失败及恢复成功断言仍全部通过。最终二进制 SHA256 为 `e6d526f5076a8a52a70b8faf0f04d341595cf6240a9d05884e291c120140ee97`，完整身份在 `final-image.json`、`build-D.json`。

四组 A/B 和 180s 持续负载发生于 C。D 的生产 diff 仅为上述 mTLS handler 的准入调用，授权码/撤销/mixed、audit worker、PG repository 和清理路径源码未改。**它们不是 D 二进制的重新容量验收**；最终版本完整四点性能证据仍未补齐，不得把 C 的结果重新标成 D 的测试结果。D 仅追加受影响 mTLS 模块、最终构建与真实故障/恢复负载复测。C 的 CI 快照 12 SUCCESS / 2 SKIPPED 不作为 D 的 CI 结论。


## A/B 原始指标与绝对门槛

| 点 | 版本 | 判定 | 成功 ops/s | P50/P95/P99 ms | 正式 drop | WAL bytes/成功操作 | App/PG 核数 |
| --- | --- | --- | ---: | --- | ---: | ---: | --- |
| p03-A1 | A | FAIL | 400.017 | 6.00/38.00/73.00 | 0 | 3129.45 | 0.66/0.88 |
| p03-B1 | B | FAIL | 400.000 | 27.00/156.00/213.00 | 0 | 3245.68 | 0.64/1.03 |
| p04-A1 | A | FAIL | 1508.433 | 434.00/1615.00/1795.00 | 5491 | 3403.37 | 2.76/3.69 |
| p04-B1 | B | FAIL | 1562.117 | 363.00/1418.00/1674.00 | 2273 | 3537.83 | 3.00/3.94 |
| p06-A1 | A | PASS | 800.000 | 16.00/32.00/60.00 | 0 | 10702.88 | 2.43/4.44 |
| p06-B1 | B | PASS | 800.000 | 21.00/95.00/127.00 | 0 | 10901.36 | 2.38/5.84 |
| p10-A1 | A | FAIL | 959.983 | 43.00/120.00/163.00 | 0 | 10910.65 | 3.01/6.45 |
| p10-B1 | B | FAIL | 960.017 | 36.00/104.00/158.00 | 0 | 10690.57 | 3.05/6.09 |
| sustained-B1 | B | FAIL | 307.128 | 3264.00/3916.00/4289.18 | 117510 | 11151.67 | 1.17/2.58 |

四个原配置 B 点为 **1 PASS、3 FAIL**。p03-A 主链路本身通过，但 FAPI sidecar P95 129ms，整点仍 FAIL。完整 sidecar 指标和全部成功/错误/未完成计数见逐点 short-result 与 summary；上述点的已发起正式操作均完成，业务意外错误为 0，drop 是未获执行的计划操作，不能因此说无损失。

**配置边界：** 原 A/B 的 `audit_mode=required` 是压测框架要求真实外部导出/对账，不等于应用 `AUDIT_ANCHOR_MODE=required`。实际原配置未设置后者，应用为 Disabled。保留原 A/B 配置没有降低已有门槛，但这些点不能证明 Required anchor 下新增 Telemetry health 读取的净成本。独立 Required 提交屏障仍然有效；sustained/fault 补测显式启用应用 Required，并保存实际容器配置。

sustained-B1 是额外 Required 模式稳定性测试：960/s、992 VUs、16 app CPU、15s 预热、180s 正式、80s 停压观察；不与 Disabled 模式的 A 直接作代码回退归因。完整操作 P95/P99 为 3916/4289.18ms，正式 drop 117510，目标容量失败。没有同期 Required A，模式净成本归因仍 INVALID。

低流量真正等待 Required 的 HTTP 导出各 30 次均成功、附件与审计数一致：A P50/P95/P99 19.2325/21.6550/28.1462ms，B 7.5357/9.6395/16.1977ms。

相对结论：撤销和 mixed 16 吞吐/长尾改善，但绝对门槛仍失败。授权码 P99 60→127ms、mixed 单核 73→213ms，不能宣称全面无回退；单次共享 CPU 对照不足以唯一归因。授权码吞吐固定 800/s 且无 drop，B 前段尾延迟较高、后段降低；mixed 16 B 最后两个 10s 桶 drop 为 0，P99 直方图上界由 2000 降到 1000ms，但整窗仍不达标。不能仅因一个 P99 更高判定代码变差，也不能因末段趋平抹去整窗失败。

## 存储增量与时间序列

| 点 | 采样秒 | 物理 DB 增量 MB（十进制） | pending 峰值/末值 | 可回收 family 峰值/末值 | 孤儿 contract 末值 | 可回收 decision 末值 | Valkey 测后 MB |
| --- | ---: | ---: | --- | --- | ---: | ---: | ---: |
| p03-A1 | 169.72 | 48.382 | 803/0 | 3622/0 | 175 | 692 | 5.130 |
| p03-B1 | 178.03 | 37.986 | 341/0 | 3548/10 | 0 | 1851 | 5.152 |
| p04-A1 | 178.79 | 209.076 | 635/0 | 11955/512 | 1434 | 6848 | 21.033 |
| p04-B1 | 179.57 | 226.107 | 2132/0 | 12770/404 | 0 | 6255 | 23.563 |
| p06-A1 | 88.57 | 281.068 | 3269/0 | 38101/7697 | 992 | 0 | 23.787 |
| p06-B1 | 89.88 | 290.701 | 3695/0 | 44607/0 | 0 | 0 | 23.800 |
| p10-A1 | 90.00 | 322.748 | 5721/0 | 40040/40040 | 0 | 0 | 27.894 |
| p10-B1 | 89.70 | 304.325 | 4187/0 | 42081/42081 | 0 | 0 | 27.881 |
| sustained-B1 | 301.95 | 207.053 | 383/0 | 42656/0 | 0 | 1716 | 18.223 |

逐次原始采样在 `storage-series.csv` 和逐点 `revision-storage.jsonl`；其中含合法保留 decision/spent、表/索引字节、insert/delete 计数、死元组、autovacuum、pending 年龄、等待事件。`soak-metrics.jsonl`、`proc-detail.jsonl` 包含 CPU/内存/checkpoint/WAL。物理大小受预分配与 vacuum 影响，不能直接等同于活数据；Valkey 不是磁盘大小。

B 的孤儿 contract 末值全部为 0；A 授权码和 mixed 的孤儿仍保留，说明移除宽限确实让无引用状态回收。安全保留内的 decision/spent 继续存在，未通过删除防重放证据缩小表。WAL 并非全面下降：授权码约 +1.85%，撤销约 −2.02%，mixed 单核约 +3.71%，mixed 16 约 +3.95%。mixed WAL 包含全部 sidecars，不能把主操作单位成本与它们完全分离。

**STORAGE 未达到完整验收：** Required 持续负载的 pending 峰值仅 383、最老 0.512s，结束为 0，180960 条审计与 receiver 连续对账一致；但持续负载期间 eligible family 从约 3935 增至 41612，decision 同样累积。停压后 family 峰值 42656 降至 0，decision 峰值 24417 周期回收，最后仍有 1716 eligible；物理 DB 峰值 239.704MB 降至 219.568MB。该证据证明可以追赶，不能证明持续目标负载下不积压；甚至该轮只服务约 307/s。

## SQL 调用与链路复核

| 点 | ACK 调用 | observe 调用 | 导出事件/批次 | 平均导出批次大小 | SQL 观察秒 |
| --- | ---: | ---: | --- | ---: | ---: |
| p03-A1 | 3015 | 3077 | 54997/3015 | 18.24 | 179.43 |
| p03-B1 | 2268 | 38 | 55155/2268 | 24.32 | 194.54 |
| p04-A1 | 1584 | 1605 | 210597/1584 | 132.95 | 197.17 |
| p04-B1 | 1897 | 22 | 229630/1897 | 121.05 | 200.14 |
| p06-A1 | 2108 | 2128 | 171072/2110 | 81.08 | 102.18 |
| p06-B1 | 1307 | 17 | 171075/1311 | 130.49 | 102.12 |
| p10-A1 | 1287 | 1306 | 216003/1287 | 167.83 | 101.70 |
| p10-B1 | 1833 | 17 | 216003/1833 | 117.84 | 101.26 |
| sustained-B1 | 1721 | 62 | 180960/1721 | 105.15 | 320.87 |

表内 SQL 观察期含预热/正式/排空，不冒充正式 60 秒速率；实际 append/ACK/observe/health 调用、总耗时、均值、角色和全期 calls/s 均保存在 `ab-analysis.json`，原始 `pgss-pre/post.json` 可复核。Required sustained 的 runtime health 180960 次，平均 SQL 执行 0.503ms；这既不包含连接获取等待，也不能独自解释 4.29s 操作长尾。

复核 scope/family 的 advisory 锁键仍绑定现有主体与授权范围；回收用同键 try-lock、行锁 SKIP LOCKED、新快照引用检查。主场景 992 个主体，而 mixed refresh sidecar 仅 64 个主体，在 600/s 下可能成为热点；本轮未执行分散主体反事实对照，所以热点与共享 CPU 的因果占比未被证明。5s PG 快照未捕获 Lock 等待不等于没有短时竞争；已有 SQL 累计等待/耗时增加也不证明由某一个锁独占引起。

维护循环保留 256 行批次、30s catch-up 工作预算、工作量对应休息和排空后 60s 间隔。持续窗口出现可回收积压，停压可追赶，根因可能涉及数据库连接服务/维护调度竞争；缺少连接获取等待证据，未直接删除锁、延长预算或新增专用池来掩盖问题。错误后的连接丢弃和替换已由真实 PG 故障证明；正常 A/B 无意外错误，未测得可量化的故障重连性能成本。


## 最终 Required 模式真实故障、恢复与排空

最终代码 D 使用真实 PG/Valkey、外部签名 receiver，应用 Required 模式，故障专用 freshness/max_lag=10s；200 Telemetry reads/s + 1 Required bundle/s。0–40s 健康，40–90s HTTP 500，90–135s 恢复，135–185s 永久拒绝，185s 恢复并调用现有 operator unblock，240s 停止新增，观察到 400s。生产默认与安全 TTL 未改。最终单点运行 513.89s，exit 0；这个退出码只表示驱动执行结束，验收以下列断言为准。

| 阶段 | Required 200 / 503 | Telemetry 200 | PG pending 首/末/峰 | checkpoint 首→末 |
| --- | --- | ---: | --- | --- |
| healthy 0–40s | 39 / 0 | 7800 | 1/169/325 | 0→6868 |
| http500_grace 40–60s | 12 / 8 | 3999 | 156/2207/2207 | 7886→7886 |
| http500_unhealthy 60–90s | 0 / 30 | 6001 | 2207/2207/2207 | 7886→7886 |
| recovery 90–135s | 9 / 36 | 8999 | 2207/65/2207 | 7886→10746 |
| permanent_rejection 135–185s | 1 / 49 | 10001 | 0/65/65 | 10940→10940 |
| recovery_after_unblock 185–240s | 18 / 37 | 11000 | 65/64/65 | 10940→12558 |
| stop_drain 240–401s | 1 / 1 | 200 | 65/0/65 | 12687→16912 |

阶段按采样秒划分，切换边界包含刚完成的在途请求；永久拒绝刚开始的 1 次 200 不代表已进入 blocked 后仍成功。155–185s 的 30 次 Required 全部 503。HTTP 500 的健康门槛触发后（60–90s）30 次 Required 全部 503，同时 pending 固定 2207；Telemetry 的查询可继续 200，但超过有界队列的审计明确拒绝。

完整计数：Telemetry HTTP 200 = 48000，Required HTTP 200 = 80；worker durable events = 16911，Telemetry queue_full = 31169。`48000 + 80 - 16911 - 31169 = 0`，对应已接受但未持久化的推算剩余为 0。每秒推算峰值 4160，与 4096 队列 + 64 当前批次一致；HTTP 完成与日志边界可能有毫秒错位，这不是直接 queue gauge，机制上限另由定向单元测试证明。

最后 PG pending=0、DB/receiver checkpoint 同为 16912，其中另有 1 条动态注册的业务事务事件；Required 80 条均计入持久事实。应用 RSS 由 41236 KiB 到 51404 KiB、峰值 51520 KiB；不把共享 cgroup memory 当成该进程独占内存。本窗口未见无界内存增长，不能推广为任意负载的字节硬上限。

**恢复速度边界：** 在持续 200/s 新流量下，恢复期仍有 Required 503 和 Telemetry 拒绝；旧事件带着原 occurred_at 返回 PG 后仍会触发 max_lag，批次交替追加/导出。恢复后的出口约数十事件/s，低于新请求的生成速率；停压到后段才全部收敛。没有通过改 event_id、刷新 occurred_at、绕过健康门槛或删除已持久 Required 事实掩盖这段恢复过程。此项证明故障有界和最终追赶，不是持续负载下无损恢复的 PASS。

原始 HTTP/存储序列：`fault-D1/fault-storage-http.jsonl.gz`；持久化/拒绝日志提取：`fault-D1/audit-persistence-events.jsonl.gz`；逐秒推算：`fault-D1/queue-accounting-series.json`；存储 CSV、RSS、SQL 与最终核对：`fault-D1/`。仅压缩和移除 ANSI/无关日志，没有改原始数值。

## 无效尝试与证据修正

- 首次授权码 A 的 helper image digest 不存在，尚未发压，记 INVALID；修正为已有实际镜像后 A/B 使用同一 helper。
- mixed B 两次因新生 generator 子进程未完整继承 affinity 被原校验判 INVALID。外部测试包装器做最多三次实际 repin，仍要求所有 task 掩码精确相等；最终所有 pin 均早于各 sidecar/主链正式窗口，见 `affinity-timing.json`。没有降低门槛或把无效窗口补成有效。
- 故障夹具两次在造数阶段被运行时 DCR 模块/租户派生 initial-access token 拒绝，分别为 404、401，未进入故障负载。修正 fixture 后 C 真实运行发现 bundle 200 缺口；D 已修复并复测。
- C 故障尝试自定义日志被随后 named-volume sampler 复制的旧文件覆盖，完整时间序列不能采信；保留驱动结果及当时实时观察，只作为发现问题的诊断，不计为最终完整故障 PASS。D 使用独立 run/project 标识，并在采样器同步后写最终 raw logs；401 个采样全部保留。
- 原 15 点矩阵的其他 FAIL 和 Signed PAR INVALID 本轮没有重跑，维持原状态；不能将四个优先点替代整个 PR 的容量验收。

## 验收结论与未解决项

| 维度 | 判定 | 边界 |
| --- | --- | --- |
| CODE | PASS | 本轮源码修复、CNB 实际门禁及最终受影响模块通过；全套 exit 101 的 fixture 失败及后续修复/定向通过均保留。远端最终代码 CI 未全部结束，不能称所有 required checks 已绿。 |
| SECURITY | PASS | 本轮 Required 提交屏障、真实 PG 晚期失败/取消/断连/连接回收、HTTP 失败关闭、签名回执/身份/心跳、引用回收竞争均有证据；不是对整个产品所有安全面的无限范围认证。 |
| PERFORMANCE | FAIL | C 四点 1 PASS / 3 FAIL，Required sustained 大量 drop；D 完整四点容量未复跑，最终二进制全套性能证明不足；Required 模式新增 health 成本缺少同期 A，因果归因 INVALID。 |
| STORAGE | FAIL | 新鲜孤儿安全回收和故障有界/停压追赶通过；健康持续负载时 eligible family/decision 上升，未证明目标负载服务速率覆盖产生速率。 |

**整体验收 FAIL，当前不建议按任务书标准合并。** 已修复可确认的最短代码缺口，没有为了满足容量门槛降低负载、放宽成功定义、绕过持久性或删除重放/撤销证据。共享 CPU 可能参与抖动，但本轮没有独立证据把失败完全归因于 CNB。

尚未解决：Required 模式目标 960/s 的容量与连接等待归因；持续回收为什么落后于产生速度；热点与分散主体的反事实对照；最终 D 四点精确二进制容量证据；整个 PR 的旧 FAIL/INVALID 项；远端最终代码 required CI 的完成状态。连接获取等待仍为 UNVERIFIED，不能用未采到 PG Lock 等待替代。

本轮已超过用户先前要求的两小时总预算。失败 fixture 调试、全量检查暴露的修复，以及真实故障发现的安全缺口导致追加验证；不能把超时包装为按时完成。各正式短测与故障观察窗口保持有界，最终故障点含清理约 8.56 分钟；失败启动和重试的累计耗时另见命令记录，未从总耗时中抹去。

## 复核入口与清理

`commands.json`：实际构建/测试命令、SHA、退出码和日志 hash；`perf-commands.jsonl` / `extra-commands.jsonl`：实际 Docker 执行与退出码；`configurations.json` / `instrumentation/`：公开配置与测试包装器；`manifest.json`：提交证据文件的 SHA256。测试密钥、会话、initial-access token、完整审计 payload journal 留在私有隔离 fixture，不随报告提交；journal hash 与对账结果保留。

`cleanup.json` 记录本轮所有项目标签下容器为 0、单元 PG/Valkey/S3 已停止、性能 controller 已停止。原授权源码/target 执行容器保留空闲，以保留工作目录和证据；未部署、未合并、未 force push。

最终源代码为上述 TEST_SOURCE_SHA；承载本报告的最终 PR HEAD 通过正常报告提交生成，完整提交号在 PR 评论中给出。报告提交只含证据及任务书的报告链接，不修改运行时代码。
