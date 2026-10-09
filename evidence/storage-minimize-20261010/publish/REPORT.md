# PR #238：存储回收与模型精简验证（2026-10-10）

受测最终源码：`088afcd5d9b22dd915438d19fbea85c3add71ecd`。本轮起点：`c733618056235dd7fadbbbc76a6a719844465b00`。新增源码提交为 `e91884919cccc085e1e3c9623327fc5167e27d5d` 和上述最终源码；报告提交以包含本文件的 Git 提交为准，不把文档提交冒充新一轮源码验证。

所有编译、数据库测试、负载均在用户授权的 CNB 隔离容器内，沿用一个 checkout 和一个 target 缓存。没有重跑 main，没有生产数据库、第二份 checkout 或 worktree。负载自然回收观察没有缩短 TTL、手工删除目标批次或手工 vacuum；完整 workspace 的既有尺度夹具内部 vacuum 不作为自然回收证据。共享服务器限制性能归因，不豁免容量门槛。

## 当前验收结论

| 项目 | 结果 | 证据边界 |
| --- | --- | --- |
| CODE | PASS | 最终源码格式、Clippy、边界检查、3713 个完整套件测试 |
| SECURITY | PASS | 本轮修改相关租户、代际、一次消费、审计回滚、原安全期限 |
| RECOVERY | PASS | 本轮相关真实 PG 提交失败、取消、断连、替换连接；未重复无修改的独立 exporter 故障负载 |
| PERFORMANCE | FAIL（历史长窗口仍未关闭） | 本次 mixed 60 秒正式窗口及四侧车 PASS；不能覆盖旧 mixed 300 秒 refresh drop FAIL |
| STORAGE | PASS（本轮目标范围） | 目标 decision 最后保留期后完整自然周期归零；三个确认的保留问题和同形空间测试通过。长期全负载/绝对最小未证明 |

## 根因、修改与第二轮复审

| 发现 | 最短修复 | 保留的实际约束 |
| --- | --- | --- |
| 过期 remembered-device 主要依赖该用户再次活动才回收 | 接入现有小时维护；tenant/token 原唯一身份直接作主键，删除无消费者 UUID/创建时间 | 原到期时间、用户/租户关系、user-agent 绑定、MFA 代际事务 |
| 过期 controller identity approval 没有物理回收所有者 | 原十分钟到期后按小时回收，未消费/已消费均覆盖 | 未到期单次消费；缺失仍拒绝；Required 审计独立保留 |
| 已使用 backup verifier 只改 used_at，继续保存没有业务消费者的 verifier | 在原消费和审计事务里条件 DELETE，移除 used_at/created_at | 并发只一赢家；审计失败回滚；当前已确认 TOTP 的代际关联 |
| TOTP 标签、通用创建/更新时间只写不读 | 移除三个持久字段和无用端口参数；注册 URI 仍从 issuer/account 生成 | 受保护秘密、密钥 ID、凭据代际、confirmed_at、last_used_step |
| Refresh 原始 ID Token SID 存在第二份可矛盾的表达 | 直接从 refresh_authority 读取，移除 refresh_id_token_sid | 原 SID 省略语义；签名输出与原始 RT 权限的其他必要比较 |

本轮删除七个持久字段和一个请求内重复字段；没有为数量而拆 SQL 表，没有新增队列、通用恢复层或第二权威。第二轮复审还撤掉了过严的 remembered-device 降级限制：降级仅重建无人读取的适配器元数据，保留真实凭据，不要求先删除有效凭据；备用码降级不会复活已消费 verifier。

恢复 challenge 不能套用 approval 的清理：其旧记录还有分配 nonce 防重放和完成回执重试的真实消费者。KV replay key 的现有派生形式也未在存活 marker 期间变更，以免旧标记变得不可见；没有为了少数字节引入永久双写。大模型按输入、规范化命令、业务事实、SQL 投影和响应边界审查，不能仅按几十个字段机械拆分。详见 [模型审查](../../../docs/project/state-model-review.md) 与 [存储归属](../../../docs/project/state-storage-lifecycle.md)。

256 是每类别每次事务的批量上限，不是每小时只能删除 256 条；饱和时原维护器在既有工作预算内继续批次，锁住的行后续再处理。它不是经证明的全局最优常量，不能单凭这个数字断言清理永远跟得上。

## 实际失败证明与正确性结果

- 旧行为加新断言：过期设备回收、过期审批回收、已消费备用码物理删除均实际运行到断言失败，退出 101。对应 `negative-*.log`，不是编译失败充当负向证明。
- 设备测试包含 260 条过期、2 条有效记录和独立连接锁住的记录，跨多个 256 批次，最后只保留两条有效记录。审批测试保留未到期消费 fence；实际 repository 在回收前后都拒绝过期 token。
- MFA 真实 PG 定向套件：62 passed。schema_cleanup：6 passed。up/down/up 保留凭据事实，已消费备用码不复活；故障触发器令审计写入失败时 verifier 删除回滚。
- 最终源码完整 workspace：**3713 passed、0 failed、4 ignored，退出 0，967.435 秒**。ignored 不算独立执行通过。完整套件包含实际 HTTP MFA Required 未知提交、代际并发、TOTP 重放和清理提交边界用例。
- 清理真实晚期异常、取消、断连：没有提前成功回执；独立连接观察旧 backend 退出，再验证替换连接和后续提交。取消允许提交结果不确定，不强行解释成回滚。最终完整套件再次执行该回归。
- 格式、Clippy workspace/all-targets/all-features、静态契约、持久化依赖和加密边界均退出 0。最终 release 构建退出 0，143.494 秒。
- 一条 `http::profile::mfa` 过滤命令运行 0 个测试，标记 **INVALID**；真实挂载路径 `http::profile::tests::mfa_required` 在完整套件中通过。中间 schema 声明遗漏导致的编译失败、python 命令不存在和 manifest 尚未更新也保留记录，均不当作负向行为证明。

[实际命令、退出码、计数和日志哈希](commands-and-results.json) · [最终完整测试摘要](final-workspace-summary.log)。完整原始 workspace 日志哈希固定在命令记录中；公开摘要省去测试生成凭据、秘密环境、二进制和事件 payload。公开产物不包含 fixture-env.json。

## 同形记录的实际空间测量

下面每组均在真实 PostgreSQL 中比较 10,000 条新写入的相同有效业务数据和实际前后索引形状，无手工 vacuum；不是现有表原地迁移后的即时磁盘缩小，也不是不同吞吐的整库比较。

| 模型 | 平均 tuple 字节：前 → 后 | 表和索引总字节：前 → 后 | 降幅 |
| --- | --- | --- | --- |
| remembered device | 224 → 200 | 4,300,800 → 3,751,936 | 12.76% |
| 未消费 backup verifier | 184 → 170 | 2,908,160 → 2,826,240 | 2.82% |
| TOTP credential | 213 → 165 | 3,637,248 → 3,162,112 | 13.06% |

已消费备用码现在没有保留行。固定标签/密文长度影响 TOTP 测量，不能把该百分比推广到所有账户。DROP COLUMN 不会立刻改写旧 heap tuple；索引/文件高水位也不等于仍有活跃记录。原始 SQL 与 JSON 随报告提供。

## 规范和结论边界

协议约束的是行为，不指定 PG/KV 产品。独立短流程已由 KV TTL 管理，请求内派生值留在内存；跨原子消费、撤销、审计及恢复的事实仍有原持久边界。过期在使用时判断，物理清理不负责改变授权状态。

- [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2)：已成功验证的同一 TOTP 不能再接受；last_used_step 未删除。
- [OAuth 安全 BCP 刷新保护](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) 与 [OIDC 刷新响应](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)：原刷新权限、绑定及身份语义不因模型精简而放宽。
- [PostgreSQL vacuum](https://www.postgresql.org/docs/18/routine-vacuuming.html)：逻辑删除、可复用空间和文件大小不同；本报告分别记录。

本轮关闭了已证实的设备、审批和备用码保留问题；没有证据支持宣称全仓库每一个字段均已穷尽证明，或存储达到数学意义的绝对最小。现有大模型清单是职责审查，不是每个小类型/枚举的全读写证明。Optional/Disabled 在无限期导出故障下也没有磁盘有界承诺。短测不能冒充长期目标负载稳定性。

## 最终源码负载与自然回收

沿用 mixed 16 CPU、1600 ops/s、992 VUs/主体以及原侧车 8/200/30/600 ops/s、8/16/32/64 VUs 和主体数，应用 anchor=Disabled，连接池32。保留 PG fsync/full_page_writes/synchronous_commit=on 和独立 exporter/签名 receiver。原成功定义、P95/P99 100/250ms、成功率99.5%、drop0.1% 不变；冷登录沿用其原专用延迟门槛。

这是补齐回收边界的短点：主链路60秒预热＋60秒正式测量，侧车总150秒、其原预热后正式135秒。没有降低每秒负载/VUs/安全配置，但持续时间不同于历史300秒点，不能作为同期 A/B 或替代其失败结论。包括自然观察和环境释放的实际命令退出0、343.167秒；setup 1.681秒。原请求及差异文件公开。

| 链路 | 目标 ops/s | 成功 ops/s | 完整操作 P50/P95/P99 ms | 正式 drop/计划数 | 本点 |
| --- | ---: | ---: | --- | --- | --- |
| mixed 主链路 | 1600 | 1599.983 | 3/12/16 | 0/96000 | PASS |
| 冷登录＋刷新 | 8 | 8.0 | 138.0/166.0/176.0 | 0/1080 | PASS |
| metadata/JWKS | 200 | 200.0 | 1.0/1.0/1.0 | 0/27000 | PASS |
| FAPI 已登录授权 | 30 | 30.0 | 21.0/28.0/41.0 | 0/4050 | PASS |
| refresh | 600 | 600.0 | 4.0/7.0/14.0 | 0/81000 | PASS |

主链路96000个已启动操作全部完成：95999成功、1预期拒绝（全运行共2次预期拒绝）、意外错误0、未完成0，成功率99.99896%。各侧车正式窗口成功率100%、未完成0。30秒直方图分组（含两端不足整桶的部分）P99始终在10–20ms区间；这60秒内没有P99随积压持续上升的证据，不推断长期永不积压。

应用/PG平均占用核数3.23/3.78。采样器按正式窗口插值的WAL约416,815,156字节，除以主链路95999次成功得到4341.87字节/成功操作；该WAL含同时运行的侧车成本，不是单独mixed SQL成本或本轮改动的因果收益。

独立审计对账：299527事件，DB/receiver/签名checkpoint的序号和hash一致；journal范围连续、无重复序号或缺口，最终pending0。公开原始ledger、聚合验证结果及journal SHA-256；296MB逐事件journal包含合成身份载荷，不放入公开报告。HTTP200不是持久回执。

### 目标批次终态

停压快照中仍有16100个目标decision：827已到期、15273仍保留；全部已导出。最后 business_retain_until 为 `2026-10-09T17:30:28.970596Z`。随后 `17:31:03.520408Z` 的完整自然周期结束（5批、946行、72ms、stop_reason=drained）；`17:31:05.648877Z` 独立数据库观察目标批次count/eligible/retained/unexported均0，`full_cycle_after_target_deadline=true`。

最终pending0、eligible family0、orphan contract0、eligible spent0。仍有35470条未到期issuance、10240个有效family、13952条合法保留spent proof；不要求把这些有效安全状态删除来制造全库归零。

数据库采样初值/峰值/自然终态为 **11.95/182.65/148.83 MiB**。初值是观察器进入准备/运行阶段的首个采样，不是与历史点统一的正式窗口起点，不能直接跨点计算节省比例。decision已归零而物理文件仍较大；空审计表及chain的索引高水位仍保留，最后一次删除946行后统计也出现946 dead tuples。这属于已逻辑删除等待vacuum/空间复用，不能说成946条未回收业务记录，也不能承诺文件立刻缩小。

Valkey采样峰值 **26.11 MiB**。后期保留的主要是35470 JAR、22500 DPoP、13500 client assertion marker及2194 session；完整TTL窗口没有在本短点全部结束，不把它们算泄漏，也不把未观察到最终TTL删除写成通过。真实Valkey过期/原子消费回归由完整套件覆盖，长期业务容量另属验证范围。

观察期无采样错误。环境释放时观察线程晚停止了一次，留下 `No such container`：发生在已记录的自然终态之后，task-finalization证实任务容器释放成功。该原始错误保留并单独分类，不删除或混成运行中数据库故障。

[数据库时间序列](natural-mixed/storage-series.csv) · [目标批次与维护原始日志](natural-mixed/maintenance.log) · [聚合、CPU、WAL、Valkey及延迟分桶](natural-mixed/investigation-analysis.json) · [实际负载命令与退出码](natural-mixed/commands.jsonl)。

### 历史对照与未解决项

此前相同分支历史业务源码的300秒mixed点：主链路1599.98 ops/s、P95/P99 15/70ms、drop0；refresh侧车597.181 ops/s、drop0.4698%，整点FAIL。本次短点没有复现，但不同窗口、不同共享CPU时段不能证明已修复历史容量问题。[历史原始报告](../../pr238-mixed-retest-20261009/publish/REPORT.md)保留原结论。

本轮报告不宣称主机独占、长期稳态、旧全矩阵通过或所有数据模型绝对最优。新迁移必须与对应应用版本配套；不承诺新旧应用混跑。没有合并或部署。
