# PR #222：2400 / 3000 / 3200 ops/s 复核与 WAL 归因

状态：**READY_FOR_REMOTE_EXECUTION，尚无本阶段实测结果。**
用户已确认历史与本轮测试在同一 CNB 容器，并要求验证当前代码在上述负载的结果。不能再假定换了机器；应逐项比较版本、应用/基础设施 affinity、pool、VU、数据规模、sidecar 和测量窗口。原七小时任务已结束；本文件定义新增阶段，不改原任务的时间或结果。

本地准备时 SSH 返回 `Could not resolve hostname cnb.space: Temporary failure in name resolution`，未执行远端负载。执行端连接：`ssh cnb-kml-1k3f9j3os-001.ebab2059-bd0f-423f-b655-1f64ea683f73-urr@cnb.space`。
准备验证：Python语法、已有4项PGSS身份/reset纯逻辑测试和diff检查通过；新增快照SQL尚待CNB的PG18最小执行验证，不把本地检查当成数据库验证或性能结果。

## 已确认的差异和数据

- A/main：`0c70d7464576138af0b3f8a39530d6615ee7a363`。
- B/当前候选生产源码：`462626b29be202c04f2e4482ade6ab5f5f6267c5`；截至本阶段准备，之后只有文档、结果及测试工具变更。开始前重新检查，不以 PR HEAD 字符串代替生产代码身份。
- 历史 `2400 -> 3200` 的候选为 `da289916`，来自 [600 秒容量进度](https://github.com/nazozero/NazoAuth/pull/222#issuecomment-5844672554)。该评论明确把 pool32 写在 ABBA 配置中；容量点实际配置仍须读原始 point/profile，不推定所有历史点都相同。
- 最近稳态是应用32逻辑CPU、pool90、主1024/s，伴随 Argon2=3/s、metadata=68/s、FAPI=10/s、refresh=205/s；main_vu_cap=512。它验证了一个有界负载点，没有探测容量上限。
- 原正式3000场景的伴随负载是 Argon2=8/s、metadata=200/s、FAPI=30/s、refresh=600/s。业务操作配比仍为 userinfo30/client_credentials25/authorization_code15/refresh15/token_exchange15。
- 旧600秒点的具体 warmup/measurement 以原始文件为准。本阶段明确采用120秒预热 + 600秒测量，避免再次把总时长误作有效时长。

最近两点的窗口数据（十进制 GB/MB）：

| 指标 | A | B |
| --- | ---: | ---: |
| 生成 WAL | 8.541604156 GB | 7.915576738 GB |
| 生成速率 | 4.745 MB/s | 4.398 MB/s |
| WAL 写操作字节 | 24.349114368 GB | 23.792345088 GB |
| 写操作速率 | 13.527 MB/s | 13.218 MB/s |
| 写操作字节 / 生成字节 | 2.851 | 3.006 |

来源为 `perf/results/diagnostics/pr222-acceptance-kmhxkb/steady-common.json`，不是本阶段的新运行。生成字节下降7.33%，写操作字节下降2.29%；比值变大不等于绝对写量增加。`pg_stat_io.write_bytes` 不是磁盘净占用或 SSD NAND 实际写量。未填满 WAL 页的重复写出是可能机制，尚未证明它解释了本轮全部差额。

## 执行边界

1. 拉取 PR #222 最新分支；不创建 worktree，不修改运行中的旧点，不删除旧证据。只在上述 CNB 构建/压测。先确认原执行进程已结束，避免并行争用；不能终止其他任务来腾资源。
2. 复用已有 A/B 二进制和 runner 镜像，核对 source/image/runtime binary 对应关系；仅文档或主机执行的 Python 工具更新不要求重建 Rust。两边共用 H=`462626b2` 加本次已记录的诊断补丁和此前容器兼容补丁。
3. 以新任务目录、新 `SIS_RESULTS` 和独占 `SIS_PROJECT` 保存新阶段，复用已验证的 pinset 和镜像。复制 CPU 计划到新目录后重新验证目标进程能使用，不能从旧项目复制 cleanup/container registry。不重建已有正确的编译依赖。
4. 只检查本部署自身进程 affinity、可见内存/压力/OOM、PG/Valkey 和任务磁盘目录；不调查宿主物理核、SMT、全局 online 或隐藏父级配额。缺少可选 CPU/RSS/PSS 诊断标 N/A，继续测试。
5. 从本阶段开始记录新 T0，最多420分钟，T0+390分钟停止新负载，留30分钟归档；失败尝试计入预算。新设 `TASK_STARTED_EPOCH`，并按新增计划设置独立 `SIS_LOAD_BUDGET_S`，不能沿用上一轮耗尽的 budget.json 或旧绝对 deadline。单点需保证完整预热、测量和合理收尾能在截止前完成。
6. 每阶段完成 commit 到同一 PR 并回复。不得合并、修改业务代码或通过调整阈值消除失败；无需再次等用户批准。兼容故障至多排查10分钟，能降级的诊断降级，继续其余独立项目。

## 冻结一组能供应高负载的共同配置

- 从 `/tmp/pr222-acceptance-kMhxkB/` 回收已验证的 task-local `point.py`、profile、CPU计划、环境启动命令和补丁。沿用[续跑文件](2026-09-27-pr222-cnb-resume.md)关于自身资源、可选诊断和权限的修订；不重新执行原宿主资源门槛。
- 用至多10分钟读取历史2400/3200点的原始配置，输出与当前配置的差异。历史文件不可得时，仍做下述新 A/B，只把“严格历史复现”标记未证实。
- 应用CPU集合和pool采用本部署已验证的共同配置，并固定到本阶段结束；实际是32/pool90则如实写32/pool90，不写成原pool32结果。换机器才基于实际可运行CPU和PG连接余量重新生成共同配置，不写死CPU编号或核数。
- 本阶段主目标是历史高负载配方：四 sidecar 固定为8/200/30/600逻辑场景执行/s，在2400/3000/3200三个主速率点保持相同。不要沿用1024测试缩小后的3/68/10/205，也不要随着候选表现单边减压。若完整配方不能供应，保留失败或发生器无效证据；缩小配方必须另建组，不能声称完成原配方验证。
- **主 VU 不得继续固定512。** 先读取历史已成功供应3200/s的实际预分配数；若适用同一runner则作为校准起点，否则按 `ceil(3200 * 0.250 * 2)` 得到1600个主 VU 起点。这个数来自目标速率、P99门槛和并发余量，不是机器固定限制。
- 所有正式点使用同一已校准的主 pre/max VU，禁止测量中动态补 VU。sidecar pre/max 也分别相等；使用已有完整迭代P99按 `ceil(2 * rate * max(0.25, p99_seconds))` 估计，缺少完整迭代数据时从已跑配置按速率比例放大，再以有界pilot检验。不能把HTTP P99代入完整场景公式。
- 先逐级提高预分配，在低到中等业务速率下验证发生器启动、seed、实际内存/压力、OOM、late-VU和终端stream，再做双方相同的高负载短pilot。最多两轮校准；只能因可证实的发生器问题共同调整资源，业务超时/失败本身不能改判为发生器不足。
- main_vu_cap/total_vu_budget 随实际验证的预分配更新；users/vector_count 用双方共同校准值，至少沿用原profile生成规则，不能增加VU却忘记数据供应。记录新profile及校准证据；内存未知可保留 `UNMEASURED_ESTIMATE`，不得平方根外推或仅删预算检查假装有资源。
- `fsync/synchronous_commit/full_page_writes=on`、审计Required、签名和Argon2成本保留。现有PG/Valkey测试配置固定；WAL压缩、commit_delay、检查点和索引变更均留待归因后另做实验。

## 最小高负载矩阵与顺序

使用共同 `point.py`，`cap_mixed`，每点重建自己项目的PG/Valkey/审计状态。以下600均指正式测量秒数，预热另加120；sidecar总持续时间为主duration+30秒。只串行执行。

| 阶段 | 顺序 | 目的 |
| --- | --- | --- |
| 固定速率短点 | A2400、B2400、B3000、A3000、A3200、B3200 | 直接回答各版本在三个指定目标下是否通过 |
| 必需候选稳态 | B3000：120+1800秒 | 验证当前版本3000/s的长期结果；已有有效业务FAIL则保留FAIL，不盲跑长点 |
| 共同负载稳态 | 从三个短点中取双方完整PASS的最高速率 R，A(R)/B(R)各120+1800秒 | 提供同压A/B及WAL对比；R=3000时复用本阶段同配置B3000，避免重复 |
| 候选3200稳态 | B3200短点完整PASS且预算足够时，120+1800秒 | 区分“3200短点通过”与“3200稳态通过”；与已运行同配置点去重 |

短点业务FAIL后仍运行其余独立的指定速率点，不据单次失败假定整条曲线；若审计安全约束失败或发生真实资源风险，则先处理相应问题，不继续提高压力。发生器/证据INVALID最多具体修复后重试一次，不当作业务容量上限。

没有共同高负载PASS时，不把原1024缩小sidecar配方的点混入本组共同负载。保留本组结果；可在同一完整sidecar配方下共同降低主速率找稳态，明确这是附加点。

只有单次短点的速率表不叫ABBA或稳定容量边界。余时只用于重现关键矛盾/临界失败，不能挤掉B3000和共同负载稳态；不平均P99。A/B仅有单次稳态时明确其重复性限制。

## 判定和数据列

沿用原任务书 `capacity_search.evaluate(... require_stream=True)`、相同 sidecar 和健康/审计门槛。主完整迭代P95≤100ms、P99≤250ms、成功≥目标99.5%、drop≤0.1%、unexpected=0、prepare_sut_failed=0。其他准备/stream问题按原分类处理。

| 目标逻辑操作/s | 既定99.5%成功下限 |
| --- | ---: |
| 2400 | 2388 |
| 3000 | 2985 |
| 3200 | 3184 |

分别报告“既定容量门槛PASS”和实际 successful/s 是否达到2400/3000/3200，不能把2985/s写成实际成功3000/s。refresh侧用自己的cap gate；其他三sidecar须原threshold通过、全程零drop及自然完成。严禁把refresh原始target_miss自动覆盖其正式窗口cap判定，或把Argon2/FAPI drop忽略。

完整分位数取 `point.json.metrics.iter_pXX_ms`，并核对 evaluator 的 `gate_p95/gate_p99`；不要再次使用 `capacity_metrics.pXX` 作为完整迭代。逐点保存精确cohort、scheduled/success/drop/unfinished、拒绝/错误分类和各sidecar速率；采样计数不能替代完整stream。

长点另复用 `single_instance_scaling.issuance_maintenance_evidence`，按[已有契约](../../issuance-maintenance-evidence.md)事前确认实际最大retention、声明过期年龄目标（本阶段120秒），检查成熟窗口至少180秒。不能把refresh expired_backlog=0当作issuance回收充分。point驱动若未自动调用该helper，应在负载结束后用保存的soak、窗口和事前声明离线调用，记录独立结果；不为这个诊断另跑一轮。

原单核组逐点PASS保留，但因A1/A2完整P99相差40.5%，比较标INCONCLUSIVE。本阶段不扩展单核矩阵。

## WAL：同一轮取证，不先改参数

本提交仅增强已有 `pgss_snapshot`：增加每条语句 `wal_bytes/wal_records/wal_fpi`、脏/写块数和 `stats_since`，保存PGSS `dealloc`，移除调用次数前800截断。均为已有前后快照中的读取，不在每个请求上采集，不改事务或存储语义。先在隔离测试PG上调用一次，确认PG18字段可用；双方共用补丁。

1. 先复算原稳态点现有的 `wal-pre/post.json`、soak、residency。生成量来自 `pg_stat_wal.wal_bytes`，写操作来自 `pg_stat_io object='wal'`，按 `(backend_type,object,context)`保留。确认同一统计reset、非负增量和窗口范围。缺少时间采集时标N/A，不能把 `track_wal_io_timing=off` 的0解读为免费I/O。
2. 新点保留窗口WAL bytes、写次数/字节、fsync次数、可得的write/fsync时间、每次写平均字节、WALWrite/WALSync等待采样、pool排队和每分钟完整迭代P99。先定位字节压力还是提交同步等待；不拿SQL累计执行时间当CPU。
3. 用新增PGSS前后快照给出按WAL排序的Top10及calls、wal_records、wal_fpi。按 `(dbid,userid,toplevel,queryid)` 连接，只对相同 `stats_since` 做差分；reset变化/淘汰或计数倒退须报告，不能默认缺失行是0。按实际源码和角色分清审计追加/确认回收、issuance、refresh、后台维护。
4. 顶层和嵌套SQL分别归因，绝不把二者相加。PGSS快照覆盖预热+负载+收尾，应使用自己的时间戳；它不是精确1800秒主测量窗，不除以该窗口主success。混合WAL还含四sidecar与后台工作，不写成单条主操作的固有成本。
5. 记录FPI数、检查点、每表/索引大小及插删更新、可得的 `pg_wal` 留存量；FPI数量不等于FPI字节占比。只有已有WAL样本可安全保留且预算允许时才用pg_waldump取样，不为归因开启无限归档、复制slot或保留整轮WAL。
6. 未满WAL页多次写出、小事务频繁flush、审计/索引写入和FPI均为候选机制；只有证据指向相应机制才给修法。不能因约3倍比值就删除审计、异步确认安全写入、关闭fsync或直接改checkpoint/commit_delay。

统计定义参考 [PG18统计](https://www.postgresql.org/docs/18/monitoring-stats.html)、[WAL配置](https://www.postgresql.org/docs/18/wal-configuration.html)、[PGSS字段](https://www.postgresql.org/docs/18/pgstatstatements.html)。

## 交付

报告写 `docs/performance/reports/special/<实际日期>-pr222-high-rate-results.md`，脱敏JSON/manifest放新的diagnostics子目录；逐点列版本、实际profile、目标/成功率、完整P50/P95/P99、main/sidecar/audit/issuance gate及WAL。旧记录不覆盖。
给出2400/3000/3200六格结果、候选3000/3200稳态状态、共同负载A/B和WAL Top10；清楚列FAIL/INVALID/未测原因，不把“至少通过某速率”说成最大容量。
原始证据保留实际可取回的归档及校验清单，不只留易失的/tmp路径；不提交token、keyset、私钥、DSN、未脱敏SQL字面量或原始审计内容。
每个checkpoint提交后在PR #222说明完成内容、实际测试、阻塞/下一步，无署名页脚。
