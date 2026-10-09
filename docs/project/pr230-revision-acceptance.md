# PR #230：审计修订与 agents 验收任务

本轮最终验证、修复与合并判断见 [2026-10-08 继续修订验收报告](../../evidence/pr230-revision-20261008/continuation/publish/README.md)。[前轮报告](../../evidence/pr230-revision-20261008/publish/README.md) 保留原失败与诊断过程。最终报告分别列出代码、安全、性能、存储结论及共享资源例外；本任务书本身不代表验收通过。

## 修订范围与证据边界

仓库：`nazozero/NazoAuth`；PR：`https://github.com/nazozero/NazoAuth/pull/230`。
分支：`refactor/authorization-decision-facts-20261001`。
本轮修订前基线：`67f836f2b616e811ce9a20bb857a01ea9517b42b`。
候选版本必须在执行时从该 PR 最新分支取得并固定完整 SHA；本文件不是测试通过报告。

本轮实现：

- 独立审计追加、单条批次、ACK、genesis、observe、fail-batch 等隐式写事务读取完整结果流，检查结果行数；结果不确定或取消时不复用连接。保留追加的幂等返回、批次 fencing、业务事务最终 COMMIT，不额外增加 BEGIN/COMMIT 往返。
- 独立 Required 队列收到第一条后只合并已排队记录，最多 64 条，不主动等 10ms；仍在持久提交后确认。Telemetry 保留原有 10ms 有界凑批，避免后台写入放大。
- exporter 启动后的首次观察仍核对数据库绑定；之后复用 ACK/heartbeat 已提交的 observed_at，只在需要时补心跳。部署身份检查、签名回执和 Required 新鲜度约束不降低。
- 仅在 **Required anchor 模式**，Telemetry 每个批次复用现有实时健康检查。不健康时保留当前有界内存批次并按既有退避重试；原有 4096 队列满时拒绝新增 Telemetry，不把故障持续转化为磁盘待办。

边界：上面的 Telemetry 限制不是全局行数/字节硬配额，不限制健康窗口内已接受的写入，不改变 Optional/Disabled 的原有策略，也不允许丢弃已经成为持久事实的 Required 证据。Optional/Disabled 在 exporter 不工作时仍可能持续积压，部署验收必须明确这一点。现有误路由 Required 的告警逻辑未重构；应检查真实调用链，不能把误路由等同于有保障的 Required 写入。

未在本轮直接修改：孤儿 refresh contract 的一小时宽限、清理预算/休眠策略、授权 scope 锁、refresh 重放证明和一次性消费凭据。没有把秒级长尾认定为已经解决。新增/修订的是单元测试；真实 PostgreSQL 故障注入、构建、完整套件和性能验收尚未运行，不得复用修订前 CI 作为本轮证据。

## 可直接交给执行 agents 的 prompt

你负责完成 PR #230 本轮修订的验证、必要的最小修复与验收。一次任务自主完成，最后统一交付，不合并 PR、不部署生产。只以实际代码、真实运行和完整 SHA 为依据，不以已有报告的结论代替证据。

### 1. 环境、版本与执行边界

先阅读 `AGENTS.md`、`docs/project/testing.md`、本文件及当前 PR 最新提交。只使用现有授权的隔离容器和已有仓库工作目录；不得探测宿主机、连接生产数据库、套用其他会话的旧 SSH 地址、另租机器、创建 worktree/第二份 checkout/第二个 CARGO_TARGET_DIR。共享目录只允许一个写入者；多个 agents 可分工审查，但不得并行改同一工作树或切分支。所有构建、测试、压测均在该隔离容器内执行。

保留用户已有改动；工作树不干净时先查明归属，不得 reset --hard、clean 或覆盖。干净后执行：

```sh
git fetch origin
git switch refactor/authorization-decision-facts-20261001
git pull --ff-only origin refactor/authorization-decision-facts-20261001
BASE_SHA=67f836f2b616e811ce9a20bb857a01ea9517b42b
CANDIDATE_SHA=$(git rev-parse HEAD)
git merge-base --is-ancestor "$BASE_SHA" "$CANDIDATE_SHA"
git diff --stat "$BASE_SHA" "$CANDIDATE_SHA"
```

记录 Rust/Python、PostgreSQL/Valkey、runner 镜像 digest、容器 CPU/内存限额、连接池、数据库持久性设置与测试配置。工具链和 fixtures 以仓库锁定版本及 `.github/workflows/code-quality.yml` 为准。数据库、独立 audit 测试库、Valkey、S3 fixture 必须隔离；缺失环境应记 BLOCKED/INVALID，不能提前 return 后记 PASS。

### 2. 先完成定向正确性检查及必要的最小修复

检查并运行本轮修改的 audit / audit_anchor / audit_ledger 单元测试。先从 Cargo metadata 确认宿主私有单元测试所属 target；不要对 `test = false` 的二进制运行空测试后宣称通过。新增测试必须位于 `tests/`，生产 `src/` 只允许最小测试模块挂载。

必须验证：

1. Required 单条和已排队多条在不推进虚拟时钟时即发起写入，最多 64 条；提交屏障未释放时绝不能返回成功。批次失败不重试，全部等待者得到失败，后续调用仍可提交；满队列、关闭、取消与 worker 停止均不得错误成功。
2. Telemetry 的批处理与批次内/跨批次顺序不变。Required 模式下 health 不可用、过旧、积压超限、blocked、部署或 checkpoint 不匹配均不得继续把 Telemetry 写入 PG；内存队列满时拒绝新增，恢复后只恢复已接受的同一批次，不增生新 event_id。Required worker 不被 Telemetry 的退避阻塞；调用方原有 Required 准入检查仍失败关闭。Optional/Disabled 不得被无意改成 Required。
3. exporter 首次观察失败必须中止该轮；持续成功 ACK 后不再每批额外 observe；空闲时 heartbeat 仍更新；缺失、过旧、未来时间戳和部署变化不能绕过检查。覆盖 Empty、Busy、Blocked、ACK 失败、永久拒绝、duplicate receipt 与重启恢复。应统计实际 repository/SQL 调用，而非只测试时间判断函数。
4. 对 Cargo.lock 中的实际 Diesel-async/tokio-postgres 版本核对完整结果流完成语义；不能把拿到第一行 true 当作 COMMIT ACK。

在隔离 PostgreSQL 中补齐/运行真实晚期失败测试，优先复用 `crates/persistence-postgres/tests/audit_ledger.rs` 的 fixtures：

- 单条 append 与 singleton append_batch：通过隔离测试库的延迟约束触发器、协议代理或等价可重复方法，让函数结果行出现后在事务结束阶段失败。调用不得返回 Ok；独立连接确认没有落下该事件。测试必须记录故障发生的真实阶段，普通函数开头报错不满足此项。
- append_batch 全部成功或全部回滚；相同 event_id/内容重试仍是幂等成功，不同内容冲突仍拒绝。业务内 fresh append 冲突仍回滚业务事务。
- ACK 结果不确定、取消、连接中断：不提前删证据、不错误推进本地 checkpoint；已真正提交但确认丢失可通过现有批次/回执机制收敛，generation 不匹配不能确认别人的批次。覆盖 genesis/observe/fail-batch 的晚期错误和连接回收。
- 等待结果流期间取消：原物理连接不能作为成功空闲连接复用；失败之后新的正常操作仍能完成。用连接身份或等价证据验证，不只检查错误字符串。
- HTTP 层至少覆盖一个真正依赖独立 Required 的控制面动作，例如 mTLS trust bundle 导出：审计提交失败时不得返回成功导出响应。不能用所有正常 token 都不走该独立队列来替代此项。

故障设施仅存在于测试库/测试代码，不得修改生产审计函数来迎合测试，也不得将 mock future 的失败冒充 PostgreSQL 事务结束阶段的故障。

### 3. 存储保留的条件修订与验证

孤儿 contract 的一小时宽限本轮仍保留。对 `security_state.rs::delete_orphan_refresh_contracts` 与全部生产 contract 写入/引用路径做完整交叉核对，先用真实 PG 验证：新建 contract+family 同事务、引用既有 contract 的 KEY SHARE、清理的 FOR UPDATE SKIP LOCKED、READ COMMITTED 新快照下的二次 NOT EXISTS、写入先持锁/清理先持锁、提交/回滚/取消、并发回收以及游标跳过锁定或被引用前缀后的最终收敛。

若证明确实全部由现有事务与锁保证引用安全，允许按已确定的最小方案移除 `ORPHAN_CONTRACT_GRACE_SECONDS` 及两处人为一小时 age 条件，保留每轮固定 cutoff、现有有界游标、引用检查和行锁；不增加 tombstone、恢复表、双写或新 worker。补上“新鲜但已无引用的 contract 可回收；活引用与未完成引用不会被误删”的回归测试。若无法满足证明条件，保持原实现并在报告中明确此项未解决，不能擅自删宽限或宣称存储问题全部关闭。

不得删除未过安全保留期的 refresh spent proofs、SingleUse fence、request/PAR 消费凭据；活跃 refresh family 上限不等于所有历史安全记录只有 10 行。清理预算、休眠、scope/advisory 锁仅在真实等待和吞吐证据证明必要时做局部修正，不得为缩小表而降低重放检测和撤销语义。

### 4. 集中运行质量门禁

必要的代码/测试修复完成后，先运行定向 target，再统一运行仓库门禁。格式问题直接用锁定工具链修正，不能停在“发现格式错误”。共享状态测试串行，复用同一 target 缓存。

```sh
python scripts/verify_static_contracts.py --check
python scripts/check_persistence_dependency_graph.py
cargo fmt --check
cargo test --all-features --locked -p nazo-postgres --lib repositories::audit_ledger
cargo test --all-features --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables
cargo test --all-features --locked -p nazo-postgres --test audit_ledger -- --test-threads=1
cargo test --all-features --locked -p nazo-postgres --test audit_preflight_roles -- --test-threads=1
cargo test --all-features --locked -p nazo-postgres --test security_state_maintenance -- --test-threads=1
cargo test --all-features --locked -p nazo-postgres --test token_issuance_atomicity -- --test-threads=1
cargo test --all-features --locked -p nazo-postgres --test authorization_decisions -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings
cargo test --workspace --all-features --locked --no-fail-fast
```

上述命令执行前按 workflow 配好 `NAZO_TEST_DATABASE_URL`/`DATABASE_URL`、`NAZO_AUDIT_TEST_DATABASE_URL`、Valkey、S3 等 fixtures，并设置 `RUST_TEST_THREADS=1`。具体配置以当前仓库为准，不输出密钥和凭据。不得将 skipped/ignored/filtered=全部 当作相关验证通过。最终工作树有生产/测试变更时，要提交并在最终 SHA 上重跑受影响门禁；旧 SHA 的绿色 CI 不算新 SHA 的证据。

### 5. 定向性能短测：补丁效果与原 PR 容量分开判断

不重跑整个 main，不重跑旧通过全矩阵。A 为本文件固定的修订前 PR HEAD，B 为完成必要修复后的候选 SHA。只在同一既有工作目录依次构建两个版本，复用原 target；可保存不可变二进制/镜像及 SHA，不创建第二 checkout。切换前提交全部工作，恢复候选分支后再交付。

复用 PR 现有负载生成、播种、配置与原始容量目标，不降低目标或改变成功定义。优先复测授权码 16 CPU、撤销 16 CPU、mixed 1 CPU、mixed 16 CPU；补充低流量 Required 延迟和持续审计导出吞吐对照。每点每版本预热 15 秒、正式 60 秒起步；需要复核的异常点最多做两组 A/B，单点总测试不超过 10 分钟，不先跑数小时 soak。先验收正确性再跑性能，资源不足时保留原始结果并判 INVALID，不用伪精确数据填表。

至少记录完整操作的成功 ops/s、P50/P95/P99、错误、drop、预期拒绝、未完成数；不能只报 endpoint RPS 或只看成功请求延迟。记录连接获取等待、PG 锁等待及事务耗时、Required/Telemetry 批次大小、append/ACK/observe/health 实际速率、每成功完整操作 WAL bytes、checkpoint、CPU/内存。使用低基数标签，不引入 URL/event_id 级高基数。

有延迟回退时先区分同一 tenant/user/client 热点与分散主体的锁竞争，再判断数据库写入/回收/导出负载。不能凭 10ms 定时器直接解释全部秒级长尾，也不能先删锁再找理由。比较正常流量下新增 health 读取成本与减少 observe 写入的净效果；监测错误后的物理连接丢弃是否造成额外连接压力。

使用原有 SLO 作绝对门禁；补丁相对比较另报告成功率、吞吐及尾延迟，重复可见的退步不得掩盖为通过。缺少同期 main 时只能得出 B 对 A 的结论，不能声称已证实/消除整个 PR 对 main 的回退。Signed PAR 的旧 INVALID 以及其他未复跑 FAIL 必须保留原状态；若声称整个 PR 容量通过，必须补齐它们的有效证据，不得用四个补丁测试点替代。

### 6. 持续写入与导出故障短测

在 Required 模式分别测试：健康持续负载、exporter/receiver 中断、receiver 永久拒绝、恢复导出、停止新增后的 drain。故障测试可用独立 fixture 的较短 freshness/max_lag 加快触发，但不改生产默认、安全 TTL 或性能对照配置。每种故障观察窗口不超过 10 分钟，不等待一小时来测试保留时间。

按时间序列分别记录：未导出审计、最老 pending 年龄、已符合回收条件的 family/contract/decision/spent-proof 数、实际删除与 ACK 速率、仍在合法安全保留期内的行数、表/索引物理大小及死元组、Valkey 与进程内存。区分“必要保留”“符合条件但未回收”“待导出”，不要把物理文件未立即缩小认作泄漏。

通过要求：健康目标负载下队列与可回收积压不持续正增长，服务速率覆盖产生速率；故障触发 Required 健康门禁后 Telemetry 不持续向 PG 追加，内存保持既有界限，过量拒绝可观测；Required 不错误成功且其已持久证据不被删除；恢复后现有积压在测得处理能力下收敛。只证明停压后排空不能证明持续负载稳定；短测只能证明该窗口，不能写“永不积压”。Optional/Disabled 单独列策略风险，不冒充拥有 Required 模式的约束。

### 7. 最终交付与权限限制

如需修复，只改上述问题的最短链路：不新增通用恢复层/幂等层/双重权威，不新增池/队列来遮掩锁等待，不关闭 fsync/synchronous_commit，不把 Required 改为 Optional，不删除失败测试或降低阈值，不修改无关模块，不添加 AI/agent 署名或 Co-authored-by。提交到同一 PR 分支，正常 fast-forward；远端前进时先同步处理，不 force push，不合并。

最终报告提交到仓库现有 evidence 目录的适当位置，并在 PR 评论链接。包含 BASE_SHA、最终 TEST_SOURCE_SHA、运行镜像/二进制身份、每项命令与退出码、实际测试数、故障注入阶段证据、A/B 原始指标、存储时间序列、根因与修正一一对应、未完成项及其阻塞原因。分别给出 CODE/SECURITY/PERFORMANCE/STORAGE 四项 PASS/FAIL/INVALID/BLOCKED 和整体验收意见；“完成执行”不等于“验收通过”。停止所有本任务负载及测试服务，保留必要原始证据，不泄漏凭据，不自行上线。
