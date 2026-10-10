# 模型、存储及回收修订验收（2026-10-09）

基础源码：`4b4fdc33b6a570aa270b17f5785e1f3188f3fc84`。未提交候选以 patch SHA-256 `8057cd5e01e3f6a45ee7fdb239a77090ac73bcb98722d0d6ddf776bb7a59c744` 标识。没有新提交 SHA；没有提交、推送、合并或部署。

## 本轮最终判定

**整体 INCOMPLETE，不能按全面验收通过处理。**

|项目|判定|边界|
|---|---|---|
|CODE|PASS|最终源码格式、Clippy、静态/边界、真实数据库回归、完整 workspace 3707 passed/0 failed/4 ignored；另显式补跑其中 FAPI PAR 用例通过|
|SECURITY|PASS|本轮修改涉及的消费、ACK、保留、引用及租户边界；两项持续负载的签名审计对账均 PASS|
|RECOVERY|PASS|本轮相关真实 PG 晚期提交失败、取消、断连、连接回收与引用锁竞争；不冒充重跑历史全故障矩阵|
|PERFORMANCE|FAIL|撤销超时延门槛；mixed FAPI 延迟及 refresh drop 超标|
|STORAGE|INVALID|压缩及独立自然回收证明通过，但两个原持续点的完整自然清理终态证据不足|

## 结论边界

本轮覆盖全部 58 张目录表的存储归属和 23 个至少 20 个直接字段的生产结构体分类；不是全部类型每个字段的穷尽正确性证明。模型分类见 `state-model-review.md` 和 `state-storage-lifecycle.md`。短测不代表长期稳态，也不保证所有存储已达到数学最小值。

## 实际修改

- RefreshToken 复用 RefreshContract，区分原始授权与当前令牌；DCR Prepared 模型复用 CreateClientRequest，消除重复字段声明和转换。HTTP 协议字段不变，Rust 内部公开结构形状发生变化。分组本身不作为字节节省证据。
- 已消费 VCI offer 在同一条件 UPDATE 中清空不再读取的 grants 密文及 TX-code hash；保留消费事实、原截止和授权元数据。负向测试实测旧消费行 368 字节，新版 184 字节（消费前 360），仅是测试夹具逻辑行大小，不是全库空间下降 50%。
- ACK 后压缩 decision 载荷，仍保留消费 fence 和 business_retain_until；ACK 晚期提交失败不得部分压缩。单次消费回执在读取时按原截止过滤。
- 协议安全状态仍每 60 秒有界回收；180 天保留的 SCIM 历史在完整清理后每小时检查，失败/未排空不会被推迟一小时。已撤销 10 秒轮询方案。没有新增 worker、队列或权威副本。历史内部扫描减少，不声称所有数据库往返减少。
- 独立短期流程已由 KV TTL 管理，请求局部值在内存。不能仅因期限短便移动已确认消费、撤销和 Required 证据。VCI offer 消费与 grant 写入实际上是两个提交；grant 无 offer 身份防线，故不把可能恢复旧未消费值的 KV 当等价替换。

## 失败证据和修正

- offer-negative2：旧 UPDATE 能编译并实际执行，断言失败退出 101；候选并发单次消费、过期及连接归还验证通过。早先编译失败的 offer-negative 不算负向证明。
- large_family_reclaim：加入 17000 条独立历史夹具后，旧全局 saturated 完成条件退出 101，尽管 11000 条目标 proof 已全部回收；改为跟踪目标 cohort，44 批回收并保留无关 backlog 的真实 saturated。原先没有分类日志的偶发失败不能据此全部归因。
- 全量测试 fresh_retired_contract 首次失败：单批扫描 256 条，却假设目标新 contract 一批必达。实测库 347 条；修正测试为完整有界游标扫描，每批验证 live 引用保护，354 条初始数据中目标第 2 批回收，10 项回归通过。没有修改生产清理额度、TTL 或锁。历史失败保留在 quality-round1/ 和 quality-round2/。

## 最终质量门禁

|命令|退出码|秒|
|---|---:|---:|
|`cargo fmt --all -- --check`|0|2.44|
|`python3 scripts/verify_static_contracts.py --check`|0|5.15|
|`python3 scripts/check_persistence_dependency_graph.py`|0|2.50|
|`cargo test --locked --all-features -p nazo-postgres --test security_state_maintenance --test security_state_commit_boundary --test migrations --test openid4vc -- --nocapture`|0|34.55|
|`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`|0|0.95|
|`cargo test --workspace --all-features --locked`|0|864.01|
|`cargo build --release --locked -p nazoauth`|0|162.66|
|`cargo test --locked --all-features -p nazoauth par_fapi2_rejects_shared_secret_client_auth_after_authentication -- --ignored --nocapture`|0|84.96|

完整 suite：3707 passed，0 failed，4 ignored；188 个结果块。Ignored 不计入通过。

全部构建、真实 PG/Valkey 测试及压测在授权 CNB 的单 checkout、单 target 内串行执行。小时调度以虚拟时钟测试、真实 PG scope 验证覆盖，不冒充完整一小时墙钟负载。真实晚期提交失败、取消、断连及孤儿引用锁竞争日志见 final-pg.log。

## 原负载短测与历史对照

A 为已有 `b5b0f4246d8a443466a1c256429a76f88bf2c6e0` 基线证据。已核对与基础 SHA 的差异仅三份测试文件，生产代码、迁移和压测配置相同（baseline-equivalence.json）。A/B 非同期，CNB 共享 CPU；数值差异不能全部归因于代码。本轮不重跑 main。

REV360：16 CPU，960 ops/s，992 VUs/主体，15 秒预热+360 秒正式窗口。MIX300：16 CPU，1600 ops/s，992 VUs/主体，60 秒预热+300 秒正式窗口；保留 Argon2、metadata、FAPI、refresh 原侧车。应用 Disabled anchor，独立 exporter 和签名 receiver。原门槛 P95/P99 100/250ms、成功率 99.5%、drop 0.1%，未放宽。

|场景/版本|成功 ops/s|P50/P95/P99 ms|原判定|DB 活跃峰值 MiB|WAL B/成功|Valkey 峰值 MiB|
|---|---:|---|---|---:|---:|---:|
|REV360 A|960.0|{"p50": 13.0, "p95": 25.0, "p99": 45.0}|PASS|754.53|11519.77|82.16|
|REV360 B|960.0|{"p50": 38.0, "p95": 127.0, "p99": 485.0}|FAIL|604.64|11033.55|82.34|
|MIX300 A|1599.973|{"p50": 3.0, "p95": 12.0, "p99": 20.0}|PASS|314.11|4585.43|48.31|
|MIX300 B|1599.99|{"p50": 8.0, "p95": 51.0, "p99": 146.0}|FAIL|292.81|4513.41|48.39|

完整成功/预期拒绝/错误/drop/未完成、侧车原门槛、CPU、30 秒分桶延迟及存储指标见 comparison.json 和各点 investigation-analysis.json。桶内分位数是 histogram 区间，不是精确 P99。较低 P99 若伴随降吞吐或增 drop 不能写成改善。

## 自然回收与存储解释

跟随最终重建的实际 app 实例，记录维护周期；固定目标 cohort 为停压时已产生的 decision。等待其最后 business_retain_until 后的自然清理，保留未到期安全状态。不手工删除、缩短 TTL 或手工 vacuum 使压测 cohort 归零。普通数据库回归中已有 vacuum 测试与此是不同证据。

DB 物理文件高水位并不等于活记录 backlog，删除后也不一定缩小文件。存储时间序列同时保留 live/eligible/oldest_due/dead tuples/物理大小及 Valkey TTL 分类。必要的 live 状态约受到达率×保留窗口影响；不要求全库归零。Optional/Disabled 在无限导出故障下不承诺磁盘有界。

各点 target-cohort.json、natural-tail.jsonl、natural-final.json、maintenance 日志和 storage-series.csv 是自然回收证据；最终结论须结合终态，不以固定停压 90 秒替代。

## 剩余边界

- 不声称短测可证明长期稳态、不再发生 P99 上升，或共享 CPU 自动免责。任何仍失败的原门槛保留 FAIL。
- 00600 更换清理函数签名，应用与迁移需匹配；没有为旧 worker 添加兼容层。本轮没有执行部署。
- 公开 Rust 数据结构变化需要调用方同步；HTTP 形状和安全保留规则不变。
- 没有把这份有限范围模型审查描述为全仓库逐字段穷尽完成。

## 性能失败的实际证据

撤销 345600/345600 个正式操作成功，0 drop、0 意外错误、0 未完成，但 P50/P95/P99=38/127/485ms，仍是 FAIL。历史对应值为13/25/45ms。mixed 主链路有4个预期拒绝，0 drop、0 意外错误；主链路 P95/P99=51/146ms 通过，整点因为 FAPI 157/432.02ms 和 refresh 1192/225000（0.5298%）drop 失败。refresh 成功596.821/s，不得仅凭其 P99=96ms 宣称改善。

30秒桶显示可恢复的间歇尖峰，没有证明 P99 随时间持续单调上升，也不代表长期不存在积压。撤销导出 pending 曾短暂达到5401个、最老1.864秒，此后归零，不能描述为从未积压。周期重叠的1秒桶 P99 落在500–1000ms，其他桶在200–500ms；这是时间相关性，不是逐请求因果归属。应用角色 WALWrite 连接采样135→264，idle-in-transaction ClientRead 7→109；exporter单列，未将所有ClientRead混成应用池排队。见 latency-diagnostic.json 和 role-wait-comparison.json。维护外也变慢，不能认定全部由维护造成。

应用/PG CPU占用核数：撤销2.48/4.44→4.79/7.02，mixed3.31/3.79→6.08/6.61。构建命令和原配置已核对；本轮未新增前台数据库往返、扩大池或撤掉提交确认。尚未证明这个性能差值由哪段代码或共享资源造成，不能用CNB共享CPU自动免责。根因和性能修复验收仍未完成。撤销逐请求 forensic 输出发生截断，不能用它声称完整连接阶段账本；正式cohort精确计数和分桶计数校验仍通过。

## 存储收益及必要保留

decision 稳态平均行约1240→280字节，约减少77.4%；不是把有效记录提前删除。撤销DB活跃物理峰值754.53→604.64MiB，约减少19.9%；mixed314.11→292.81MiB，约减少6.8%。对应WAL/成功操作11519.77→11033.55和4585.43→4513.41。物理采样起始值不同，故完整初值/末值/峰值均保留，不能将峰值差当精确每操作逻辑节省。mixed WAL口径包含侧车，侧车成功量不同也限制归因。

Valkey峰值约82.16→82.34MiB、48.31→48.39MiB，基本持平，并未证明进一步压缩。撤销峰值主要是229822个JAR replay标记，样本80个占26240字节（平均328字节）；不能将抽样总字节当全量内存。mixed包括JAR、DPoP、client assertion和合法session。JAR使用原JWT绝对expires_at，Valkey原子TIME+SET NX EXAT，不是每次重放续期。标记值已经是单字符1；键仍有namespace和散列编码开销，本轮没有通过改变键身份忽略旧防重放标记，也不声称达到全局最小内存。

## 自然回收终态与观察器修正

原观察器在目标行变为0时就结束，可能早于该维护周期的最后日志；不足以满足“最后保留期后的完整周期”这一严格结束条件。已在独立point-observer-cycle.py修正为同时满足目标归零与完整周期记录，原观察器和原始结果不覆盖。

- REV360：停压目标100968条→0，但最后截止14:01:37 UTC之后缺完整周期结束日志；此点严格周期证明 INVALID。
- MIX300：停压目标26874条→72条（均已到期、已导出）；截止时未覆盖下一自然周期，不能写成归零或判定清理器卡死。此点严格终态 INVALID。
- COHORT60：独立回收验证，保持960/s、992 VUs、原安全配置及TTL；生成窗口仅75秒（含15秒预热），不作原360秒容量验收。停压目标72000条→0；最后保留期14:16:20.619723 UTC，完整后续自然周期14:17:24.647343→14:17:24.721343 UTC，stop_reason=drained。没有手工删除、提前到期或手工vacuum。该批次自然回收 PASS，但不替换上述两个持续点的缺失终态。

两个持续点的cleanup在585秒预算内未清完已退出的keyset辅助容器，命令退出3。已按原任务标签核对并清理这两个残留辅助容器，见 cleanup-followup.json；没有隐藏最初的退出码，也没有将补清理改写成原命令成功。单点总运行均低于600秒。表内判定独立于清理命令退出码。

COHORT60 控制器退出码为2，耗时302.91秒，辅助容器清理完成。它的原容量判定同样为FAIL（P95/P99=135/236ms），自然回收子项PASS与容量判定分开。此短窗口的6个采样中过期decision数量峰值为0；因此尾延迟超标并不以过期decision大量积压为必要前提，但不能据此排除其他维护/WAL竞争。审计216000事件与签名checkpoint、receiver journal一致，无序列缺口或重复。
