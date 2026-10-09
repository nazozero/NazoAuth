# PR #230：数据模型收敛与验收

最终源码：`b5b0f4246d8a443466a1c256429a76f88bf2c6e0`。最终报告提交为包含本文件的提交；PR 正文和评论记录其完整 SHA。#236、#237 的提交历史已正常归入 #230，保留历史报告，没有合并到 main。

本轮不再重复既有性能诊断：此前已证明并修复的连接持有生命周期缺陷保留。工作重点是完成全仓库模型审查、落实必要收敛，并验证这些改动没有破坏安全、性能或自然回收。

## 结论

| 维度 | 结果 | 范围 |
| --- | --- | --- |
| CODE | PASS | 全仓库模型收敛、3,701 个 workspace 用例、显式 FAPI、格式/Clippy/静态门禁 |
| SECURITY | PASS | 原安全不变量、真实 PG/Valkey 回归和负向行为证明 |
| RECOVERY | PASS | 晚期提交/取消/断连/连接回收及现有审计恢复回归；未重复无关历史故障负载 |
| PERFORMANCE | PASS | 四个原点全部通过原负载及门槛；不等于每项成本都改善 |
| STORAGE | PASS（短测范围） | 60,000 条 decision 跨最后保留期和完整自然周期归零，四点审计排空与签名 checkpoint 一致 |
| 长期存储平台/无限期故障磁盘上限 | INVALID / 未测 | 短测不作长期推断 |

模型审查覆盖 562 个 Rust 源文件、1,716 个声明、7,239 个成员，另核对四种宏生成身份 ID、独立 receiver 的 12 个声明，以及真实 PostgreSQL 的 58 张表、608 列、824 条约束。类型别名、错误枚举和装配对象也在清单中；这些数量不是“1,716 个数据库实体”。

完整职责、字段保留理由、交叉模型关系、宽模型分析和规范依据见 [模型审查](model-review.md)，字段声明见 [models.json](models.json)，读写位置导航见 [member-reference-index.json](member-reference-index.json)。文本引用索引不等于类型解析或正确性证明。102 个旧成员条目消失、36 个新条目出现、15 个类型变化包含文件归属移动，不能包装成“删除 102 个业务字段”。

## 修改与不变量

- Claim 完整请求成为唯一权威；名称按需派生，UserInfo/ID Token、scope/显式 claim 仍然独立。
- 删除死 AuthenticationContext/UserRow；实际 SessionRecord 拒绝空白 AMR，不把未知 AMR 擅自解释为 MFA。
- 已验证 PKCE 和签名 sender binding 不再使用可矛盾的独立字段组合；raw 协议输入继续原有拒绝规则。
- Passkey ID/count 由 PG 列与原子 CAS 负责，领域持有类型化 credential，新 JSON 不再重复保存；旧副本必须一致。
- nonce 留在首次签发，当前 SID 属于刷新代际；原始认证上下文、不可变 contract 身份、撤销/重放 fence 保留。刷新数组类型化，编码、摘要和存储加密归适配器。
- VP response_mode 保留请求内唯一表达；迁移对矛盾历史值失败关闭。DeferredCredential 不再把明文 JSON 命名为 ciphertext。
- MFA keyring 移至 PG 边界，删除无消费者的 split read/CAS API，保留真正原子 verify-and-consume。敏感 Debug 脱敏，删除无消费者字段和冗余 Consent/Code issued_at。
- avatar 阶段收敛、durable consumption receipt、客户端策略、审计字节权威及安全 TTL 保持原有约束。

没有扩大连接池、增加通用恢复层或新队列，没有放宽容量门槛。Required 写入仍须等待提交确认；取消不能被解释为必然回滚。审计 hash 绑定原始已确定字节，不重新规范化历史 JSON 或重算 contract key。

## 命令、回归与真实故障证据

| 实际命令 | 退出码 / 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 |
| `cargo test --workspace --all-features --locked --no-fail-fast -- --nocapture` | 0；3,701 passed / 0 failed / 4 ignored |
| `cargo test --locked --all-features -p nazoauth --lib http::authorization::par::tests::par_fapi2_rejects_shared_secret_client_auth_after_authentication -- --exact --ignored --nocapture` | 0；1 passed |
| `cargo build --release --locked -p nazoauth` | 0 |
| `python scripts/verify_static_contracts.py --check` | 0 |
| `python scripts/check_persistence_dependency_graph.py` | 0 |
| `python scripts/check_crypto_boundary.py` | 0 |
| `python -m unittest discover -s scripts -p test_crypto_boundary.py` | 0；23 passed |
| `python scripts/check_perf_results_layout.py` | 0 |
| `python -m unittest discover -s scripts -p test_data_model_inventory.py` | 0；7 passed |

完整 workspace 实际测试提交为 `705f28714c3d2e0509d801cd487775511ad07c76`。随后仅追加 `tests/contracts/migrations.sha256` 的四条新迁移校验值；Rust、SQL、测试、Cargo 输入和运行配置没有变化。最终提交重新通过格式、Clippy、静态门禁、显式 FAPI 和 release 构建。[源码等价性](source-equivalence.json) 记录准确差异，未冒充在新 SHA 上重跑过完整 suite。

[命令与汇总](verification-summary.json)、[原始日志及校验值](quality-files.json) 保留每次命令和退出码，包括编译错误、错误包名、迁移编号冲突和首次静态清单失败。它们不是负向行为证明。

有效负向证明分别为：恢复旧空白 AMR 判断后的真实断言失败（行为回退实验，并非完整旧 checkout）；旧 resource verifier 拒绝标准访问令牌且接受缺少 iat 的令牌；旧 Passkey mapper 接受与 CAS 列冲突的 counter。三个负向测试均实际运行并以 101 退出，候选对应回归和完整 suite 通过。见 `quality/session-negative.log`、`quality/resource-profile-negative.log`、`quality/passkey-negative.log`。

真实 PostgreSQL 测试覆盖晚期提交错误、取消、断连、独立观察旧 backend 消失及替换连接。日志同时记录取消后 durable_changed=true 和 false，不强行断言回滚。七条读路径在查询完成后、调用者恢复调度前归还连接，取消的阻塞读不会复用旧连接。相关日志在 `quality/final-workspace.log`。

本轮没有修改 Telemetry 恢复算法或 exporter ACK/签名回执协议；完整 suite 重新执行其回归，既有真实 exporter 故障负载保留在[历史恢复报告](https://github.com/nazozero/NazoAuth/tree/298cf845c58b2caab0128ac07f5eacd3e50fb355/evidence/pr230-recovery-20261008/publish)，不宣称本轮重跑了那些外部故障负载。

## 原门槛性能

只重跑四个受影响旧点，不重跑 main 或旧通过全矩阵。请求逐字段对照仅改变候选身份、镜像、运行名称，原负载、VUs、pool32、主体分布、侧车、正式窗口和 Disabled anchor 均保持。[配置等价性](request-equivalence.json) 与每点 requests 保留原始参数。

门槛：完整操作 P95/P99 ≤100/250ms，成功率 ≥99.5%，drop ≤0.1%；正式窗口 60 秒，所有已开始操作均核对完成。原先通过版本 `ef89417c9377ea765878b24d7b034a189638dee3` 的已有结果仅作历史回归参考，不是本轮同期 A，不把差值全部归因于代码。更早 e13/67f 基线及失败证据仍在历史报告，本轮未重测。

| 场景 / 目标 ops/s | VUs | 成功 ops/s | 完整 P50/P95/P99 ms | 历史 P50/P95/P99 ms | drop | 错误/预期拒绝/未完成 |
| --- | ---: | ---: | --- | --- | ---: | --- |
| 授权码 16 CPU / 800 | 992 | 800 | 11/18/29 | 10/18/34 | 0 | 0/0/0 |
| 撤销 16 CPU / 960 | 992 | 960 | 15/36/82 | 12/22/39 | 0 | 0/0/0 |
| mixed 1 CPU / 400 | 64 | 400 | 3/12/21 | 2/12/24 | 0 | 0/0/0 |
| mixed 16 CPU / 1600 | 992 | 1600 | 3/12/20 | 3/13/23 | 0 | 0/0/0 |

四点成功率均为 100%，不存在以吞吐下降或 drop 增多换取较低 P99。mixed 的原侧车门槛、过期积压检查、族容量和 proof 上限均通过。单点包含收集/清理的总执行时间分别为 309.8、160.4、243.7、239.6 秒，均低于 10 分钟。

撤销的整体 P99 为 82ms，高于历史 39ms；PG 占用由 4.19 增至 7.29 核。真实 PG 统计把差异定位到一次/操作的 current-digest family lookup：历史平均 0.0172ms，本轮 2.1294ms。已复核该函数和唯一索引迁移字节完全未变，应用运行角色总语句次数也基本相同；没有捕获这两个正式点的实际计划与 I/O 时序，因此不能确定是计划/缓存/I/O、共享 CPU 还是其他时序因素。见 [成本对照](revoke-cost-comparison.json) 与 [链路代码复核](revoke-code-review.json)。这不是成本全面改善的证据，也不足以支持盲目改 SQL、扩池或删锁。

撤销早段有一个 10 秒桶 P99 落在 100–200ms，后半段三个桶回到 20–50ms；最大单操作 268ms。其余点的后段桶也没有持续抬升，四点均无 drop 和未完成，短窗口未见不断累积的请求尾延迟。直方图按一秒输入分桶，负的首桶标记来自相对小数秒窗口起点的取整，是已核对正式 cohort 的部分边界桶，不是额外 warmup 请求。不能把这些短窗口写成长期恒定延迟。

原始成功/预期拒绝/错误/未完成/drop、CPU、WAL、侧车与审计状态见 [acceptance-metrics.json](acceptance-metrics.json) 和各点 `short-result.json`。全量正式 cohort 的秒级直方图汇总为 10 秒时间桶，保留 P99 区间、最大值及完成量。它们是直方图区间，不冒充精确分位数；抽样诊断流不用于推断无偏 P99。[round-analysis.json](round-analysis.json) 记录这些边界。共享 CPU 只限制因果归因，不替代门槛。

## 存储与自然回收

| 场景 | 物理 DB 增量 MiB：历史→本轮 | WAL 字节/成功：历史→本轮 | app/PG 核数：历史→本轮 | Valkey 测后 MiB：历史→本轮 |
| --- | --- | --- | --- | --- |
| 授权码 16 CPU | 217.20 → 204.45 | 10379.5 → 10554.9 | 1.66/3.65 → 1.66/4.11 | 22.65 → 22.65 |
| 撤销 16 CPU | 275.05 → 290.34 | 10473.5 → 10641.9 | 2.40/4.19 → 2.51/7.29 | 26.56 → 26.56 |
| mixed 1 CPU | 48.05 → 49.21 | 3250.0 → 3241.9 | 0.46/0.63 → 0.47/0.66 | 4.87 → 4.89 |
| mixed 16 CPU | 187.72 → 215.71 | 4333.5 → 4321.8 | 3.31/3.88 → 3.27/3.76 | 26.06 → 26.02 |

目标批次 60,000 条 decision 的最后 `business_retain_until` 为 `2026-10-09T07:18:34.809623+00:00`。实际自然维护周期于 `2026-10-09T07:19:34.543568Z` 以 `stop_reason="drained"` 完成，最后一批删除 235 条；`2026-10-09T07:19:38.106248+00:00` 的独立行数观察确认 remaining/eligible/retained/unexported 均为 0。维护日志累计自然删除恰好 60,000 条，最终实例身份一致。见 [自然回收终态](MODEL02/decision-natural-reclamation.json)、`MODEL02/decision-cohort-series.jsonl`、冻结身份批次压缩文件及实际维护日志。

该点数据库、receiver 和签名 checkpoint 对齐到 171,072 个事件；其余三点分别为 216,003、55,205、299,194，均无序号缺口或重复。仍有效的 9,920 条 refresh family 保留，未要求全库归零。没有手动 DELETE、缩短 TTL 或手动 vacuum 参与这项自然回收证明；workspace 的合成大数据夹具清理与此压测数据库相互隔离。

数据库采样期增长覆盖发压及相应观察期，不统一等于正式 60 秒，不能与 WAL/成功操作或 CPU 占用核数混为一谈。物理高水位不等于未处理积压；`storage.jsonl` 同时保留 eligibility、合法保留、dead tuple、autovacuum、表/索引体量和 pending 年龄。PG 连接采样按运行角色、application_name 和等待状态区分，未把全部 ClientRead 当作应用池。

采样覆盖时间（历史→本轮）：授权码 16 CPU 217.3→232.5秒；撤销 16 CPU 82.6→81.3秒；mixed 1 CPU 163.4→160.4秒；mixed 16 CPU 166.4→159.0秒。

四点观测到的最老 pending 峰值分别为 1.092s、0.562s、2.000s、0.547s，最终均排空。授权码物理高水位 239.80 MiB，回收观察末为 216.40 MiB；目标 decision 已清零但审计表/索引仍有已分配空间，且 token receipt、有效 family 仍合法保留。n_dead_tup 是统计估计，不用它代替精确目标行数。

授权码/撤销的 WAL 每成功操作分别比历史增加约 1.69%/1.61%，mixed 两点略降。撤销、mixed16 的物理采样增量更高；它们不能被包装成“最小存储已证明”或每操作物理成本回退的确定结论。保留、自然清理、autovacuum 和采样跨度都会改变物理增长；完整时间序列和表/索引明细保留在各点 `storage.jsonl`、`storage-series.csv`。

## 边界和交付

所有构建、测试和负载均在授权隔离容器，单 checkout、单 target、单写入者。未探测宿主、使用生产库、force push、合并 main 或部署。真实模型修复及回归已进入原 PR；临时重写脚本和自动应用脚本未作为生产机制保留。

压测只证明所列短窗口及目标批次自然回收；目标负载下长期存储平台、无限期故障下磁盘上限不在本轮证据内，保持 INVALID/未测。Optional/Disabled 原语义不变，不声称无限期 exporter 故障下磁盘有界。未运行的外部 conformance 组合和独立 controller 联调不能由本地 suite 代替。

最终报告提交后的 CI 单独检查并记录到 PR；CI 不能替代以上性能、存储和真实故障证据。最终 main 合并由仓库所有者决定。
