# PR #230 独立恢复验收（2026-10-08）

本报告区分源码正确性、实际恢复、容量门槛与短测存储。四个原失败容量点仍为 FAIL，不能宣称本 PR 已达到全面合并标准。共享 CPU 仅限制差异归因，不更改测试结果。

## 版本与范围

- 用户修订：`bea8a7e0dd608b91b94000003fe5370508979d99`。
- 本轮直接 A：`e13fcfd1292283f135906a31de987b533f002de8`。
- 最终源码 B：`bbe4fb2d4078f859ffb690a83d7ac9a6f088d0ac`。
- 报告 SHA：承载本报告的提交（PR 评论补充完整 SHA，避免自引用哈希）。报告提交仅包含文档和证据。
- 历史 `67f836f2b616e811ce9a20bb857a01ea9517b42b` 的证据原样保留，未重跑 main、旧通过点或全矩阵。
- 原分支、单一 `/src` checkout、单一 target、单一写入者；构建、测试、分析和负载均在授权隔离 CNB 内。仅观察自有应用容器，未探测宿主。

A 使用此前在 `ec4d98e13ff652b2039fb3a3da393b27bbcbda82` 编译的二进制；独立核对该提交至 A 的差异仅文档/证据，生产源码与构建输入相同。没有声称重新编译 A。B 在本轮源码上编译。完整镜像、二进制 SHA256、请求配置和来源见 `images.json`、各点 `provenance.json`、`requests/`。A/B 使用相同修正后的 P-256 夹具。

## 发现与最短修正

初始候选只按年龄裁剪未尝试写库的 Telemetry，仍存在真实恢复缺陷：排队事件在接近 10 秒边界时写入，随即成为超龄 pending，反复关闭 Required 门禁。原故障时序下，90–135 秒只有 2 次 Required 成功、43 次 503；185–240 秒只有 6 次成功、49 次 503。最终停压排空不能替代恢复成功。

修复只改变现有 best-effort 裁剪边界：**从未尝试 append、无 Required completion、allowlist 明确为 Telemetry** 的事件，在 Required 导出门禁不健康时直接舍弃，独立计为 `unavailable_export_unattempted_telemetry`。年龄过期计数继续单列。Required-class、未知事件、带 completion、已经尝试且提交结果不确定的批次均不进入此路径。没有增加队列、恢复层、等待、TTL 豁免或回执旁路。

Required 立即进入既有 append 并等待提交确认，10ms 合批仍仅适用于 Telemetry。Optional/Disabled 在 worker 入口过滤掉 Required preflight，因此不增加其健康查询，也不改变原无限导出故障下可持续磁盘增长的语义。

用户修订中的四个清理 count SELECT 读取完整结果以消费隐式提交终态，SQL、批次上限、游标、租户条件、事务与安全保留期未改变。一批仍使用一个 guarded 连接。详见 `chain-review.md` 和 `closed-export-repair.patch.gz`。

## 负向证明与真实数据库边界

在同一 checkout 切换到 A，只覆盖新增回归测试与必要测试挂载，没有移植生产修复：

- recovery worker：退出 101，2 PASS / 4 FAIL；失败为运行时行为断言/超时，非编译或缺夹具。没有运行 A 不具备的新纯辅助方法测试。
- `security_state_commit_boundary`：退出 101，0 PASS / 1 FAIL；旧实现把返回首行误认为已提交的清理成功。
- 在初始 B 新增“新鲜但未尝试 Telemetry 遇到不健康导出”的测试，修复前退出 101，实际超时；修复后通过。

候选真实 PG 用独立临时子库注入晚期约束错误、取消、断连；观察连接先证明旧 backend 已消失，再借替换连接。未来 nonce 保留。取消可能已提交，日志中确实存在 durable_changed=true；测试没有强行要求回滚。审计提交确认丢失仍保留事件身份和完整批次，不当作可丢弃数据。

定向执行曾在复用的单元测试数据库出现 maintenance 25 PASS / 2 FAIL；失败日志保留。换独立新夹具后 27/27 通过。这是隔离状态影响的证据，不据此声称已证明两个原失败的唯一根因。最终完整门禁使用保留原数据库和 Valkey 快照后建立的新测试夹具。

## 实际故障恢复与计数

原时序完整保留：0–40 秒健康、40–90 秒 HTTP500、90–135 秒恢复、135–185 秒永久拒绝、185 秒原 operator unblock、240 秒停压、观察至 400 秒。负载 200 Telemetry reads/s + 1 Required bundle/s，freshness/max_lag=10 秒；真实 HTTP、PostgreSQL、独立 exporter 和签名 receiver。

修复后原时序 `fault-B1-fixed`：

- 确认旧持久证据已导出且健康后的两个持续请求窗口分别为 **25 秒/25 次 Required 200、50 秒/50 次 Required 200，均无 503**。故障解除后的初始重试等待另计，没有包装成即时恢复。
- Telemetry HTTP200=47998，Required HTTP200=136。门禁关闭舍弃=21169，过期舍弃=0，队列拒绝=0；worker 确认持久化=26965，其中 Telemetry=26829、Required=136。另有业务注册事务事件 1 条，receiver 唯一事件=26966。
- 尚在途=0，事件重复=0，重复 envelope 请求=1；HTTP 压测计划漏调度=3，不能混作服务端队列拒绝。
- SQL 实际 append 调用=8011（包含业务单写）；ACK=601、observe=170。精确 pre/post 与身份、时戳、payload hash、签名 checkpoint 校验见分析和原始数据。
- 最终 DB/receiver/anchor 序列及哈希一致，pending=0。Telemetry HTTP200 不作为持久回执。

重复故障 `fault-B2` 的最终恢复持续请求 **50 秒/50 次 Required 200，无 503**，最终 pending=0、身份及计数一致。该轮第一恢复子窗口在保守确认健康后仅剩 15 秒，**不能独立算作两个 freshness 周期通过**；分析中的 `sustained_recovery=false` 原样保留。原时序两个窗口和重复故障的最后窗口提供所需持续恢复证据，不以较短子窗口替代它们。

新舍弃原因与 expiry、queue rejection 分开记账，不能用任何舍弃计数解释 Required 证据缺失。初始失败与修复后的原始时间序列都保留。

## 性能口径

四点应用 anchor 均为 **Disabled**；框架 `audit_mode=required` 是外部审计收集设置。Required-only 修复不是四点性能通过证据。

| 场景 | 主体/预分配 VUs | 目标 ops/s | 预热/正式窗口 | 附加负载 |
|---|---:|---:|---:|---|
| 授权码16 CPU | 992/992 | 800 | 15/60 秒 | 原配置 |
| 撤销16 CPU | 992/992 | 960 | 15/60 秒 | 原配置 |
| mixed1 CPU | 64/64 | 400 | 60/60 秒 | argon2 1、meta 13、FAPI 2、refresh 38/s |
| mixed16 CPU | 992/992 | 1600 | 60/60 秒 | argon2 8、meta 200、FAPI 30、refresh 600/s |

mixed sidecars 保持原 150 秒、VUs 8/16/32/64 和对应主体。相同应用/PG/Valkey/辅助 CPU 绑定、池大小32、fsync/synchronous_commit/full_page_writes=on。交错顺序 p06 A→B、p10 B→A、p03 A→B、p04 B→A。原完整操作 P95/P99=100/250ms、成功率99.5%、drop0.1% 未放宽。

| 场景/版本 | 成功 ops/s | P50/P95/P99 ms | drop 数 / 比例 | 结果 |
|---|---:|---|---|---|
| p06-A | 529.800 | 1911.00/2565.00/2735.00 | 16213 / 33.7764% | FAIL |
| p06-B | 479.533 | 1978.00/2591.00/2740.00 | 19227 / 40.0571% | FAIL |
| p10-A | 407.867 | 2376.00/3297.45/3583.00 | 33128 / 57.5139% | FAIL |
| p10-B | 392.417 | 2442.00/3258.80/3615.00 | 34054 / 59.1226% | FAIL |
| p03-A | 400.000 | 19.00/112.00/148.00 | 0 / 0.0000% | FAIL |
| p03-B | 398.867 | 20.00/124.00/172.00 | 68 / 0.2833% | FAIL |
| p04-A | 1162.467 | 631.00/2213.00/2354.00 | 26250 / 27.3443% | FAIL |
| p04-B | 1129.000 | 652.00/2287.00/2477.00 | 28260 / 29.4375% | FAIL |

上述八点主操作未预期错误、预期 invalid_grant、未完成均为 0；已启动操作成功率均为 100%，计划迭代 drop 仍是真实容量失败。

| 场景/版本 | App/PG 平均核数 | WAL bytes/成功 | Valkey 测后 bytes | App RSS 最大 KiB |
|---|---|---:|---:|---:|
| p06-A | 1.53/3.45 | 10956.041 | 17118272 | 132820 |
| p06-B | 1.33/3.26 | 10949.021 | 15588880 | 120796 |
| p10-A | 1.33/2.43 | 10984.743 | 13224240 | 120128 |
| p10-B | 1.22/2.33 | 10803.754 | 12861424 | 122100 |
| p03-A | 0.65/0.91 | 3191.134 | 5143568 | 105096 |
| p03-B | 0.65/0.97 | 3241.716 | 5173816 | 106032 |
| p04-A | 1.89/2.56 | 3296.245 | 17536648 | 275880 |
| p04-B | 1.82/2.45 | 3317.641 | 17516608 | 264460 |

mixed1 A/B 的 argon2、meta、refresh 侧车 PASS，FAPI 因尾延迟 FAIL；mixed16 A/B 只有 meta PASS，其余三条侧车均因容量/尾延迟 FAIL。侧车原始成功吞吐、P50/P95/P99、drop 与 outcomes 全部保存在 `ab-analysis.json`，不能只看主操作。

诊断专用 p06 点保持800/s、992 VUs，启用池 TRACE 后测得 262908 次正式窗口连接获取，P50/P95/P99=210.710/296.336/327.825ms，最大等待者961，获取开始时可用连接均为0，失败获取0。PG 51次采样主要为 ClientRead 与 WAL 等待，采样最长事务0.087465s，未观察到长锁等待。1秒采样不能排除短锁。应用线程 runnable wait 与 pool/SQL 时段重叠，不能直接相加。诊断点有日志开销，不拿其吞吐替代正式 p06-B；仍不能唯一归因于共享CPU。详见 `pool-diagnostic-analysis.json`、`perf-diagnostic.json`。

授权码、撤销及持续负载的逐条完整操作延迟已复算，计数和分位数与正式结果一致。mixed 的有预算诊断归档只保留部分逐条延迟，不能从该子集重算正式P99；`complete-operation-latency-analysis.json` 对该附加复算保留 INVALID，原完整流式窗口统计与容量 FAIL 不变。部分原值明确以 `.partial.jsonl.gz` 命名，不冒充完整请求轨迹。

所有完整指标、预期拒绝、错误、未完成、侧车结果、CPU、WAL 和存储见 `ab-analysis.json` 及各点原始 `short-result.json`。较低尾延迟如果伴随吞吐下降/drop 增长不认定改善。调度等待只在应用容器内部测量，不能唯一归因于共享宿主；诊断重日志点单列，不替代正式容量结果。

## 持续负载、停压与存储

持续点为原撤销目标 960/s、992 VUs，应用 Required，15秒预热 +180秒正式窗口 +至少90秒停压观测。A/B实际成功速率分别为 **357.183/356.894 ops/s**，drop分别 **108507/108559（62.7934%/62.8235%）**，未预期错误、预期拒绝、未完成均为0。它们没有达到目标容量。

- 完整操作 P50/P95/P99：A=2774/3245/3739.08ms，B=2763/3565/3843ms。逐条原始延迟重新计算后，计数分别64293/64241，分位数与原结果完全一致。B最后140、150、160、170秒起的完成时间切片P99为3068、3369、3715.53、4073.39ms，不能称“始终拉平”；这段与自然回收重合，仅为相关证据。完整原值与切片见 `sustained-latency-analysis.json`、`sustained-correlated-series.json`。
- pending最大 A/B=160/1801，最老年龄最大0.321/1.848秒，末值均0；签名receiver/DB/anchor全部对齐。未观察到审计积压反复超龄，但这不是满目标负载下的长期证明。
- family eligible峰值20878/21918，末值均0；仍live的family均992。contract孤儿峰值571/583，末值均0；spent eligible及retained均0。本轮实际自然删除family69807/69847、contract2929/3419。周期性删除而非手工清空，原始5秒计数序列覆盖多个自然回收波次。
- decision eligible峰值20572/21307，末值6168/9087，末次仍受business retention保护的decision均0。**最后这批已到期decision的随后清空没有被本次观察窗口覆盖**，不能声称全体业务状态最终归零；也不能仅凭这批残留断言泄漏。
- B审计事件自然autovacuum计数5，chain entries计数4，family计数5。chain entries已无逻辑行、堆仅24576 bytes，但索引仍15679488 bytes，是物理高水位。审计事件末次n_dead_tup=3628，表示另有等待vacuum处理的版本，不能当作待导出证据。issuer记录的更长安全保留期未被短窗口覆盖，不以无删除直接认定泄漏或宣称完整存储上界。
- DB物理峰值A/B=238294719/242251455 bytes，末值222688959/190551743；WAL bytes/成功10936.931/10931.624；应用/PG平均核数1.24/2.58与1.25/2.57。Valkey测后19332664/18987664 bytes；App RSS最大120468/132952 KiB。回收时相、合法保留与物理高水位均影响体量，不能仅用末值下降宣称效率提升。
- A maintenance日志捕获完整周期；B日志跟随器附着到负载前的应用实例，应用Required重建后该跟随器退出，因此B这份日志不覆盖负载期。B的实际回收证据来自连续数据库删除计数、eligible序列、SQL调用和自然vacuum；该观测限制原样保留。额外诊断点另有完整B维护周期日志。

Optional与Disabled独立故障点中，HTTP500导出故障期间Required命名操作继续成功；Telemetry expiry/closed-export舍弃均0，所有11057个worker事件加1个业务注册事件最终与receiver11058条一致。两种模式故障期间pending增长，符合原语义；不授予无限故障磁盘有界的PASS。

**STORAGE为INVALID（全面收敛结论证据不足，非原始数据无效）**：本次已证实审计、family、spent及contract的短测收敛，并区分物理高水位；最终9087个已到期decision尚无后续清空观测，较长安全TTL及目标960/s下长期增长也未验证。无证据支持削弱TTL、删除持久Required证据或新增恢复层。详细每表删除速率、体量、死元组、vacuum及原始时间序列见 `sustained-storage-analysis.json` 和各点 `storage-series.csv` / `revision-storage.jsonl`。


只对本次短窗口给出结论。大量 drop 下的实际接纳速率不等于目标负载，180 秒观测不能证明长期稳定。合法保留、eligible 积压、死元组、物理高水位分别报告；没有手工删除/vacuum 制造平坦曲线。Optional/Disabled 不承诺无限导出故障下磁盘有界。

## 最终检查与结论

最终完整 workspace：3667 PASS / 0 FAIL / 4 ignored，退出码 0。以下全部对应最终源码 B；完整日志和环境在本目录。

| 检查 | 退出码 | 实际秒数 |
|---|---:|---:|
| `python scripts/verify_static_contracts.py --check` | 0 | 11.98 |
| `python scripts/check_persistence_dependency_graph.py` | 0 | 3.00 |
| `python scripts/check_crypto_boundary.py` | 0 | 1.53 |
| `python -m unittest discover -s scripts -p test_crypto_boundary.py` | 0 | 0.31 |
| `python scripts/check_perf_results_layout.py` | 0 | 0.03 |
| `cargo fmt --check` | 0 | 3.39 |
| `cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings` | 0 | 53.90 |
| `cargo test --all-features --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables` | 0 | 6.48 |
| `cargo test --workspace --all-features --locked --no-fail-fast` | 0 | 1397.27 |
| `python -m unittest perf.tests.test_blackbox_contract perf.tests.test_capacity_window perf.tests.test_capacity_producer perf.tests.test_stream_cohort perf.tests.test_single_instance_scaling perf.tests.test_service_affinity perf.tests.test_cnb_controller perf.tests.test_pool_size_ab perf.tests.test_issuance_maintenance perf.tests.test_evidence_contract perf.tests.test_audit_reconciliation perf.tests.test_audit_pending_schema perf.tests.test_current_capacity perf.tests.test_short_baseline perf.tests.test_checkpoint_measurement.WindowContractTest` | 1 | 1.98 |
| `python -m unittest perf.tests.test_blackbox_contract perf.tests.test_capacity_window perf.tests.test_capacity_producer perf.tests.test_stream_cohort perf.tests.test_single_instance_scaling perf.tests.test_service_affinity perf.tests.test_cnb_controller perf.tests.test_pool_size_ab perf.tests.test_issuance_maintenance perf.tests.test_evidence_contract perf.tests.test_audit_reconciliation perf.tests.test_audit_pending_schema perf.tests.test_current_capacity perf.tests.test_short_baseline perf.tests.test_checkpoint_measurement.WindowContractTest` | 0 | 10.69 |
| `python -m compileall -q scripts perf` | 0 | 0.13 |
| `python -m unittest -v perf.tests.test_blackbox_contract perf.tests.test_capacity_window perf.tests.test_capacity_producer perf.tests.test_stream_cohort perf.tests.test_single_instance_scaling perf.tests.test_service_affinity perf.tests.test_cnb_controller perf.tests.test_pool_size_ab perf.tests.test_issuance_maintenance perf.tests.test_evidence_contract perf.tests.test_audit_reconciliation perf.tests.test_audit_pending_schema perf.tests.test_current_capacity perf.tests.test_short_baseline perf.tests.test_checkpoint_measurement.WindowContractTest` | 0 | 16.66 |
| `cargo test --all-features --locked -p nazoauth --lib par_fapi2_rejects_shared_secret_client_auth_after_authentication -- --ignored --nocapture` | 0 | 1.49 |

最终 Python 性能/验收工具回归：338 项，0失败、0跳过；另有密码学边界 Python 回归。首次导入失败和缺Node/k6导致的6项跳过均保留，不算验收通过。

Rust完整套件保留4项既有ignored：S3平台信任子进程入口由其父测试显式调用；`canonicalize_controller_start_wire` 是NazoAuthCtl跨仓库驱动入口，本轮未单独提供该跨仓库输入；官方UI初始化下载测试本轮未执行；PAR FAPI2共享密钥认证拒绝测试已用真实PG/Valkey和CI=true显式 `--ignored` 补跑，1项通过、退出0。没有把ignored计入3667通过数，也没有把这次PAR功能回归当作旧signed PAR性能INVALID已闭环。

| 维度 | 结论 | 边界 |
|---|---|---|
| CODE | **PASS** | 最终源码所有指定门禁通过，Rust3667通过/4既有ignored（详列范围，PAR已另补跑通过），Python性能回归338通过/0跳过。 |
| SECURITY | **PASS** | Required立即写且提交确认后成功；真实PG晚期失败/取消/断连、物理连接回收、原TTL与引用竞争回归通过，不把取消强行等同回滚。 |
| RECOVERY | **PASS** | 原时序两次持续恢复25/50秒及重复故障最终50秒；身份/签名对账一致。补充轮首次15秒窗口单独证据不足，未包装为20秒通过。 |
| PERFORMANCE | **FAIL** | 四个Disabled原失败点全部仍FAIL；持续点实际仅约357/960ops/s，B末段P99上升；不以共享CPU自动免责。 |
| STORAGE | **INVALID** | 短测数据有效且部分状态收敛；末次9087个到期decision未覆盖后续清空，不能宣称全面收敛/目标负载长期稳定或全模式磁盘上界。 |

剩余事项：四个 Disabled 容量点仍 FAIL，差异唯一根因未证明；共享调度资源影响尚不能与代码完全分离。旧 signed PAR INVALID 仍是历史未闭环项；本轮未重测，不能算新通过。短测不提供长期满目标稳定或全模式存储硬上限证明。

最终 Python 性能工具测试首次运行缺少 CI 固定的 `orjson==3.12.0`，264 个加载/测试项中出现5个导入错误、退出1；安装相同固定版本后重跑完整指定集合。首次失败日志和复验命令均保留，不把缺依赖提前失败算通过。该夹具修正未改变源码。

`reproduction/` 中脚本以 gzip 保存原始字节，解压后再使用；`source-sha256.json` 用于核对实际脚本身份。

执行过程中校验脚本哈希不匹配在持续负载启动前阻止运行，修正实际脚本清单后恢复；原失败日志保留。容量退出码2最初导致编排提前停止，修正为保留 FAIL 后继续，未重命名为 PASS。所有命令、退出码、日志哈希见 `commands.json`；初始失败和复验均保留。

CI 仅在上述工作、报告提交和正常推送完成后检查；CI 绿色不改变本报告的容量 FAIL。未合并、未部署、未 force push。


本轮最终报告生成时间：2026-10-08T14:57:13.572632+00:00。本轮开始约2026-10-08 12:17 UTC；总执行超过原两小时预算。首次真实恢复失败后的必要修复/复验、全部短测和最终完整套件均保留，未以省略测试代替完成。
