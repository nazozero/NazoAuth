# PR #230：恢复期遥测与回收提交确认验收

## 任务与版本

在 `nazozero/NazoAuth` 的 PR #230 原分支
`refactor/authorization-decision-facts-20261001` 验证本轮修订。
执行前读取 `AGENTS.md`、`docs/project/testing.md`、本文件和
`docs/security/security-events.md` 的恢复边界。

- 本轮直接基线 A：`e13fcfd1292283f135906a31de987b533f002de8`。
- 历史性能基线：`67f836f2b616e811ce9a20bb857a01ea9517b42b`。
- B：包含本任务书的最新原分支提交；开始时记录完整 SHA，最终有修改则重新固定。
- 原始证据目录：`evidence/pr230-revision-20261008/continuation/publish/`。
- 本轮提交不意味着验收通过；历史 3658 测试通过、8 个工作流绿色不能替代 B。

修订解决两个已定位的代码问题：未尝试入库的超龄 Telemetry 在恢复时
反复触发 Required 门禁；独立清理计数查询未读取完整隐式提交结果。
四个 Disabled anchor 性能 FAIL 的唯一原因仍未确认，本轮不把它们改为 PASS。
Optional/Disabled 的故障放行与持久保留策略未改变，不宣称其磁盘严格有界。

## 不变量与执行约束

所有主动构建、测试、数据分析、压测只在现有授权隔离环境内执行；单一
checkout、单一 target 缓存、单一写入者。不得探测宿主、生产数据库或
额外创建 worktree/第二份 checkout；不得使用 Codex。可拆分只读审查，
但不得并行修改共享工作树或与 A/B 同时运行其他负载。

不得削弱 fsync、synchronous_commit、full_page_writes、事务原子性、
Required 失败关闭、租户绑定、消费 fence、撤销、防重放、回执验证或安全 TTL。
不得改写 occurred_at、把未知事件降为 Telemetry、删除持久证据、裁剪已尝试
写入但结果不确定的批次。不得增加恢复层、持久队列、双重权威或用放宽门槛过关。
不得删除失败记录或测试，不合并、不部署、不 force push，不添加 AI/agent 署名。
保护既有工作；必要的编译、格式或实际失败修复保持最小并正常提交原 PR。

## 第一阶段：代码与负向回归

使用仓库固定 Rust/Python 和 CI 夹具。先执行范围匹配检查，再进行最终完整门禁。
以下命令必须记录真实退出码，缺少夹具不得把提前返回算通过：

```sh
python scripts/verify_static_contracts.py --check
python scripts/check_persistence_dependency_graph.py
cargo fmt --check
cargo test --all-features --locked -p nazoauth --lib recovery_tests -- --nocapture
cargo test --all-features --locked -p nazoauth --lib adapters::audit::tests -- --nocapture
cargo test --all-features --locked -p nazo-postgres --test security_state_commit_boundary -- --nocapture
cargo test --all-features --locked -p nazo-postgres --test audit_commit_boundary -- --nocapture
cargo test --all-features --locked -p nazo-postgres --test security_state_maintenance -- --nocapture
cargo test --all-features --locked -p nazo-postgres --test audit_bounded_reads -- --nocapture
```

`NAZO_AUDIT_TEST_DATABASE_URL` 必须指向独立 audit_test 夹具并具备创建临时
子数据库的权限；完整套件的 PG/Valkey/S3、环境和串行设置按现有 CI。
新增 cleanup 故障测试只改新建子数据库；不得对应用库安装故障触发器。

负向证明：在同一 checkout 对 A 临时应用新回归测试及最小测试挂载（不移植
生产修复），证明旧行为失败；B 必须通过。A 缺少新增纯辅助方法时，不得把
编译失败当负向行为证明，可仅运行调用现有 worker 的恢复场景和独立 PG 清理
故障场景。保留补丁和失败日志，切回 B 后确认工作树和被测源码身份。

必须覆盖：

1. 130 条以上超龄 Telemetry 跨越多个批次，后接新事件；旧事件从未 append，
   新事件原 ID/时间/payload 保留，最终健康。不依赖仅返回常量健康的 fake。
2. 全过期批次无 SQL append；健康查询失败时也可释放确定未尝试的过期遥测。
   等待健康查询期间过期的记录，在首次 append 前再次按真实时钟判断。
3. Required-class、未知名称及带 Required completion 的事件绝不裁剪；
   commit barrier 前等待者不得成功； Required 人工 10ms 等待不得恢复。
4. 首次 append 返回错误后，即使批次变老，重试也保持完整相同成员和身份。
   真实 PG 的已提交但确认丢失不能被归类成“未入库可丢弃”。
5. expiry 使用同一 age/max_lag 边界：等于门槛、超过门槛、未来时间；
   Optional/Disabled 原有无健康门禁行为保持。仅既有 allowlist 的 Telemetry 可丢。
6. 清理最终 credential count 的延迟约束错误、取消、断连不返回成功计数；
   独立连接确认物理 backend 消失后再借替换连接，未来 nonce 仍保留。
   取消可已提交，不强行断言回滚。核对四个 count SELECT 均消费完整结果，
   SQL/批次上限/原事务/游标/保留期未变，一批仍只借一次池连接。

## 第二阶段：真实恢复可用性与计数

复用旧故障夹具和实际 HTTP、PostgreSQL、独立 exporter、签名 receiver：
应用 Required、freshness/max_lag=10 秒；200 Telemetry reads/s 加 1 Required
bundle/s。沿用 0–40 秒健康、40–90 秒 HTTP500、90–135 秒恢复、135–185 秒
永久拒绝、185 秒解除并执行现有 operator unblock、240 秒停压、观察至400秒。
不得通过改小 Telemetry 流量或增加 max_lag 掩盖问题。

每个阶段保存 HTTP 原始结果、持久事件与 checkpoint、pending/最老年龄、
queue-full、expired_unattempted_telemetry 的 discarded_events、append尝试和
确认计数。必要时仅在故障点启用低基数观测，正式性能点不携带重诊断。

在恢复后继续请求，不仅看 stop/drain：确定旧持久 Required/不确定批次已完成
导出且 exporter 健康的时点，从该时点观察至少两个 freshness 周期，记录
Required 成功率、最长连续503和首次持续健康时间。不得再出现“未尝试的旧
Telemetry 被补写 -> pending 立刻超龄 -> Required 再次拒绝”的因果链。
实际必需证据尚未排空、数据库仍失败或回执不合法导致的拒绝另行分类，不能
伪装为立即恢复，也不能用新 expiry 计数解释 Required 丢失。

计数应能对齐：产生数 = 队列拒绝 + 明确过期舍弃 + 确认持久化 + 尚在途数，
业务事务另写的事件单独计算；确认丢失、重试与重复投递按 event_id/checkpoint
去重，不以日志行数冒充唯一事件数。不把 telemetry HTTP200 等同于持久回执。
数据库、receiver 与签名 anchor 必须最终一致，已持久 Required 不得缺失。

补一轮持续故障与恢复，检查重复故障后仍能收敛；单故障点总时长不超过10分钟。
Required 门禁前尚在飞行的请求可以有有界尾部，不能承诺零超调或任意负载的
严格字节上限。单独验证 Optional/Disabled 行为，明确无 exporter 时仍可增长；
不将这两种模式写为“磁盘有界 PASS”。

## 第三阶段：四个失败性能点与实际存储

只先测授权码16 CPU、撤销16 CPU、mixed1 CPU、mixed16 CPU。从原证据和
任务配置提取原 rate/VUs/sidecars、主体分布、预热与测量窗口，不猜测参数。
A 为本轮直接基线、B 为最终候选，尽量 A/B/A 或交错；历史67f基线作为已存
证据列出，不重跑 main、旧通过点或全矩阵。每点总测试不超过10分钟。

固定原成功定义、完整操作 P95/P99=100/250ms、成功率99.5%、drop0.1%门槛。
同时列出成功ops/s、P50/P95/P99、error/drop/预期拒绝/未完成、侧车状态、
CPU、WAL bytes/成功。较低P99加更低吞吐/更高drop不算改善。A/B 使用同一
修正后的 P-256 夹具，镜像/二进制/Cargo/迁移/SHA 与配置分别对齐。

分清应用 AUDIT_ANCHOR_MODE 与框架 audit_mode。四个旧点应用为 Disabled，
不能把 Required-only 恢复修复当作其回退原因或性能通过证据。发现退步时只
运行短诊断，分开池获取、锁/事务、SQL执行、清理实际工作量与应用 runnable
调度等待。仅观察授权容器自身；CPU共享是限制，不是所有回退的自动免责。

存储观察与该负载同步：pending年龄/数量、eligible与仍合法保留的family、
spent proof、decision、孤儿contract、各表/索引体量、死元组、自然vacuum、
实际删除速率、WAL、Valkey、应用RSS。至少覆盖两个自然回收周期，停压观察
必须超过实际清理休眠。保留有界批次，不手工删库/vacuum制造平坦曲线。

复用180或330秒持续窗口及至少90秒停压窗口；报告实际接纳速率与目标速率，
不能在大量drop下宣称目标负载稳定；不能把物理高水位、合法保留和可清理积压
混成“泄漏”。长期容量和全模式硬上限未被短测证明，结论必须明确限定。
旧 signed PAR INVALID 保留为历史未闭环项，不冒充本轮新通过。

## 最终门禁与交付

定向回归无问题后，按测试指南完成最终 SHA 的 all-target/all-feature Clippy、
初始化迁移、完整 workspace suite、相关 Python/静态/边界门禁；记录实际命令、
退出码、passed/failed/ignored、依赖环境。若未执行或夹具不可用，写 BLOCKED，
不拿历史日志或仅编译成功当通过。必要修改后重新验证受影响部分。

在原 PR 提交报告并评论，明确最终源码 SHA、报告 SHA、镜像和原始证据路径。
分别给 CODE、SECURITY、RECOVERY、PERFORMANCE、STORAGE 的
PASS/FAIL/INVALID/BLOCKED，逐项列明范围、失败、缺证与残余策略限制。
容量门槛不通过仍为 FAIL；共享资源例外只影响所有者是否接受风险，不改测试
结论。执行完成、代码提交、CI绿色和安全/性能/存储验收是四件不同的事。
