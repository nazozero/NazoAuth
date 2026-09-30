# PR #222 定向验证与回归修复

本轮接手 [PR #222](https://github.com/nazozero/NazoAuth/pull/222)，所有 Rust 构建、测试和数据库操作均在指定 CNB 容器执行，未创建 worktree、启动全工作区测试、容量矩阵或 soak。GitHub 是代码事实源，CNB 只用于检出和验证。

报告生成时必要定向检查已取得有效证据；之后最终门禁发现两处测试固定密钥告警，本报告随该实际 fixture 修复补充证据。**最终 HEAD 的 CI 尚待完成**。提交本报告后的实际门禁结果追加到 PR 评论，不通过反复提交报告追逐 CI 状态。本报告是窄验证和诊断记录，不是正式全链路性能验收。

## 代码、环境与 CI 基准

- 初始 SOURCE_SHA：`442ad35c4eeba0579e2360e81830a674bd52835b`，GitHub HEAD 与交接 SHA 相同，分支为 `perf/db-hotpath-minimal-0c70d746`。
- CNB 原检出在 main，已有 `codecov.yml` 修改。先保存补丁和 scoped stash，再从 GitHub fetch、切换 PR，恢复修改。收尾补丁 SHA-256 与初始完全相同：`7711e182c4d87bfef75015c8b46bfbb83be548ba8fad5bd38439cb44f81b9d02`。本轮提交不包含该文件。另一个交付检出原有 `migrations_work/` 未跟踪内容也保留。
- Rust：`rustc 1.98.0 (88d9e12ae 2026-08-18)`，Cargo 1.98.0；使用仓库固定工具链和 `--locked`，没有升级依赖。
- 实际服务：PostgreSQL 18.6、Valkey 8.1.10。原容器没有现成数据库服务或编译产物；复用已有工具链与 registry 缓存，在同一容器启动隔离测试服务。镜像身份见 [validation.json](../../../../perf/results/diagnostics/pr222-2026-09-27/validation.json)。版本与 CI 的 major 相同，本地 tag 解析不是 CI digest 相同的声明。
- `DATABASE_URL` 与 `NAZO_TEST_DATABASE_URL` 均指向 `pr222_test`；`VALKEY_URL` 显式指向隔离 Valkey DB 15，scoped fixture 进一步分隔状态。实际 PostgreSQL 查询和 Valkey PONG 成功；持久层迁移入口执行 1 项通过，准备 90 个迁移版本。
- `CARGO_BUILD_JOBS=1`、`RUST_TEST_THREADS=1`，任一时刻只有一个 Cargo 执行链。按 workflow 配置其余适用变量，包括 state epoch、宿主端点、cookie、禁用真实邮件、签名测试配置和 federation fixture。未运行依赖 S3 的目标，不声称本地全工作区 fixture 完备。
- 已读取 AGENTS.md、testing.md、code-quality.yml 和静态后续报告第五至七节。历史发现与当前未修项分开处理。

重新查询并下载 [442ad35 Rust job 完整日志](https://github.com/nazozero/NazoAuth/actions/runs/36255785527/job/108442189371)：格式、全目标 Clippy、schema 准备通过，最终 Rust job 以 101 退出。唯一失败为 `keyctl::tests::database_operator_keyctl_roundtrip_keeps_keys_in_the_repository`；宿主 lib 为 1328 passed、1 failed、3 ignored。CodeQL 和其他适用检查通过，不能据此将该 HEAD 的 Rust 门禁记为成功。

原 `9035aa5` 的两个失败已在此完整日志中消除：consent raw-wire 测试通过，`bootstrap_password_providers_reuse_the_prepared_unknown_secret_hash` 通过。本轮对应 CNB 目标也实际执行通过，未跳过测试或放宽生产解析器。

## 必要修复

### 合法的 external key 成功路径 fixture

`c771f50ea7aef4b762fe1fa83505035bd43d7c9a` 将 keyctl 往返测试中不在 P-256 曲线上的硬编码坐标，替换为已有 ES256 fixture 生成的公钥。generation 提前准备材料时拒绝原坐标是正确行为，不能修改生产解析器迎合该输入。

CNB 修复前先列出 1 项，再实际运行该 exact target，复现相同错误（0.74 秒）。修复后 keyctl 模块 4 项通过（0.51 秒），宿主格式检查通过；`cargo clippy --locked -p nazoauth --lib --tests -- -D warnings` 通过（3m13s）。测试名虽然含 database，这个目标使用内存 repository，不构成真实 PostgreSQL 证明。

### 非法材料必须在 CAS 前拒绝

沿失败调用链确认：原注册校验只验证 JWK 外形和 metadata；repository CAS 已写入后，新的 generation 准备才拒绝不可用材料。调用返回错误却将 revision 从 1 改为 2，留下重启不能加载的 keyset。

`ece640dd058a802b663ea223441a603cec39c437` 在现有 `validate_external_registration` 中复用 generation 的 `prepared_verification`，在任何 CAS 前拒绝不可用材料。生产改动只有既有函数的 crate 可见性和一次注册校验调用，没有新增缓存、状态或运行层。

新增回归修复前实际失败（1 项，0.76 秒，Cargo 101）：注册返回 Err，但 repository revision 已改变。修复后覆盖非法 P-256 点和仅允许 sign 的 key_ops；断言 revision、public metadata、加密材料、当前 generation 指针均不变，并证明重启仍能加载。该回归 1 项、database 模块 15 项、external 4 项、model 26 项、宿主 keyctl 4 项通过。包格式、Clippy 和源码测试边界检查通过。没有降低 RSA/EC 强度、跳过验签或缓存最终授权判定。

### CodeQL 测试密钥告警

`866409a3` 的 CodeQL 分析任务成功，但随后独立的安全检查失败，报告 [533](https://github.com/nazozero/NazoAuth/security/code-scanning/533) / [534](https://github.com/nazozero/NazoAuth/security/code-scanning/534) 两条 critical hard-coded cryptographic value。两条均分类为 test，位于 OpenID4VC integration fixture；一条来自修改行上的历史固定密钥，另一条来自本 PR 新增的暂停验密 fixture，不是生产部署密钥泄漏。

仅将这两处固定数组替换为已有 rand 依赖生成的 `[u8; 32]`，不屏蔽扫描规则、不修改生产逻辑。CNB 在 `866409a3` 加该补丁时先列举、再实际运行 atomic recovery boundary 1 项（1.29 秒）和暂停验密 2 项（0.39 秒），均通过；后者保留唯一消费者、连接归还、snapshot/expiry/busy 拒绝语义。`cargo fmt -p nazo-postgres --check` 通过，`cargo clippy --locked -p nazo-postgres --test openid4vc -- -D warnings` 通过（2m20s）。详细命令和日志见 validation.json，最终扫描结果以修复提交的 CI 为准。

## 定向 Rust 执行证据

以下表格均为真实执行；每个过滤目标先 `-- --list` 核对匹配。所有列出的成功目标均 0 failed、0 ignored。完整命令、列举数量、每项名称、构建耗时、执行耗时和日志位置见 [validation.json](../../../../perf/results/diagnostics/pr222-2026-09-27/validation.json)。原始运行日志位于 CNB `/tmp/pr222-validation/<label>-run.log`，列表日志为同目录 `<label>-list.log`；不把 0 tests、仅编译或缺环境提前返回计作通过。

| 范围 / label | 实际项数 | 测试耗时 | SOURCE_SHA / 代码状态 |
| --- | ---: | ---: | --- |
| A embedded `dpop::` | 26 | 2.76 s | 442ad35 干净运行源码 |
| B `external::tests::` | 4 | 0.14 s | 442ad35 |
| B `model::tests::` | 26 | 4.33 s | 442ad35 |
| C bootstrap unknown-secret provider | 1 | 0.95 s | 442ad35 |
| C `adapters::email::tests::` | 6 | 0.05 s | 442ad35 |
| D `authorization_contract`，真实 Valkey | 9 | 0.02 s | 442ad35 |
| E `subject_and_claims::`，真实 PG / Valkey | 9 | 2.45 s | 442ad35 |
| F tenant-bound single-use/encrypted state | 1 | 0.37 s | 442ad35 |
| F recoverable issuance leases | 1 | 0.19 s | 442ad35 |
| F atomic recovery / terminal errors | 1 | 1.30 s | 442ad35 |
| persistence migration | 1 | 1.76 s | 442ad35 |
| SCIM pagination/count=0 contract | 1 | 0.23 s | 442ad35 |
| keyctl-after | 4 | 0.51 s | 442ad35 + 原样提交为 c771f50e 的 fixture patch |
| registration-after | 1 | 0.41 s | c771f50e + 原样提交为 ece640dd 的修复 patch |
| B-database-fixed | 15 | 11.43 s | 同上 |
| B-external-fixed | 4 | 0.10 s | 同上 |
| B-model-fixed | 26 | 4.19 s | 同上 |
| keyctl-final | 4 | 0.70 s | 同上 |
| grant-atomic，1 family | 1 | 0.23 s | ece640dd |
| grant-race | 1 | 0.58 s | ece640dd |
| grant-three，3 families | 1 | 0.26 s | ece640dd + 临时 fixture patch，运行后已恢复 |

修复检查编译时 checkout HEAD 仍是其上一提交，工作区包含本轮补丁；上表明确区分，不能把补丁后的通过归给同 SHA 的未修改源码。提交后已核对 CNB 源码与 GitHub 提交逐文件一致。最终合并后的精确 HEAD 由自动 CI 再验证。重复执行数量不能解释为不同的测试案例总数。

主要命令均加 `--locked`：

```sh
cargo test --locked -p nazo-resource-server --lib 'dpop::' -- --nocapture --test-threads=1
cargo test --locked -p nazo-key-management --lib 'external::tests::' -- --nocapture --test-threads=1
cargo test --locked -p nazo-key-management --lib 'model::tests::' -- --nocapture --test-threads=1
cargo test --locked -p nazo-key-management --lib 'database::tests::' -- --nocapture --test-threads=1
cargo test --locked -p nazoauth --lib 'bootstrap_password_providers_reuse_the_prepared_unknown_secret_hash' -- --nocapture --test-threads=1
cargo test --locked -p nazoauth --lib 'adapters::email::tests::' -- --nocapture --test-threads=1
cargo test --locked -p nazo-valkey --test authorization_contract -- --nocapture --test-threads=1
cargo test --locked -p nazoauth --lib 'subject_and_claims::' -- --nocapture --test-threads=1
cargo test --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables -- --nocapture --test-threads=1
cargo test --locked -p nazo-postgres --test scim_pagination tenant_pages_preserve_timestamp_ties_exact_totals_and_count_zero -- --nocapture --test-threads=1
```

F 的三个完整名称分别执行，均先列举并加 `--exact`：

```sh
cargo test --locked -p nazo-postgres --test openid4vc openid4vc_state_is_tenant_bound_and_sensitive_values_are_single_use_and_encrypted_at_rest -- --exact --nocapture --test-threads=1
cargo test --locked -p nazo-postgres --test openid4vc recoverable_issuance_leases_commit_responses_and_deferred_credentials_once -- --exact --nocapture --test-threads=1
cargo test --locked -p nazo-postgres --test openid4vc issuance_store_covers_atomic_recovery_and_terminal_error_boundaries -- --exact --nocapture --test-threads=1
```

A 覆盖回拨、精确到期、满缓存拒绝与 replay 错误优先级、clone 并发唯一胜者，以及 malformed/signature/private JWK/algorithm/curve 拒绝。它是 embedded verifier，不能归因到主服务的外部 replay store。

B 确认两个指定测试确实执行，同时覆盖 exact signing-input、替换 generation、用途、退休资格、空和错误签名。C 证明 unknown-secret hash 契约、SMTP 配置与构造；没有证明邮件投递、连接复用或取消恢复，lettre pool 仍未启用。D 的 setup 必须显式提供 VALKEY_URL；真实 Lua 覆盖合法 actions 数组、raw-wire CAS、并发替换不被删除及损坏输入 fail-closed。

E 的 setup 依赖 DATABASE_URL 和 VALKEY_URL，两者已连接且迁移完整；9 项覆盖当前账户、principal 并发停用、claims 错误与签发提交。tenant/subject prepared-snapshot 不匹配拒绝和错误审计次序也沿当前源码核对，没有将静态核对冒充所有负向场景的运行证明。F 执行 offer/VP/notification 和损坏密文路径；需要解密失败回滚的 deferred 事务没有移出事务。

## 四项窄规模证据

SQL SOURCE_SHA 为 442ad35；到 ece640dd，相关 SQL、锁代码和 migrations 没有变化。原始绑定参数、完整 EXPLAIN 节点、rows/filter/loops/buffers/WAL/耗时见 [sql-plans.json](../../../../perf/results/diagnostics/pr222-2026-09-27/sql-plans.json)，可复现探针见 [sql-probes.py](../../../../perf/results/diagnostics/pr222-2026-09-27/sql-probes.py)。探针从生产 Rust 提取 owner 和 event SQL，用 psycopg 实际绑定参数；SCIM SQL按当前 Diesel 投影与 tuple 谓词重建。

每档每个 token source 为 1,000 / 10,000 条，其中目标 owner 各 5 条、其余属于同租户其他 owner。SCIM 目录另有 N+2 个目标租户用户；event 全部有效、已 ACK、无待投递事件。ANALYZE 后只取一次计划，不做统计收益推断。所有 shared read blocks 为 0，属于热缓存样本。

| 实际执行目标 | 1,000 档：ms / shared hit | 10,000 档：ms / shared hit |
| --- | --- | --- |
| client owner read，返回 10 个 token | 0.236 / 46 | 2.601 / 480 |
| client owner VC revoke UPDATE | 0.515 / 53 | 2.200 / 365 |
| user owner read，返回 10 个 token | 0.106 / 31 | 1.069 / 302 |
| user owner VC revoke UPDATE | 0.294 / 90 | 1.013 / 374 |
| SCIM exact COUNT | 0.142 / 35 | 1.857 / 368 |
| SCIM tuple page，100 rows | 0.103 / 6 | 0.100 / 7 |
| event poll，0 pending | 0.540 / 37 | 5.899 / 390 |

### Owner 撤销

client owner 的 issuance Seq Scan 返回 5 行，1,000 / 10,000 档分别过滤 998 / 9,998 行（包含隔离库内先前少量 fixture）；VC grant 分支扫描 1,000 / 10,000 行，再与目标 client join。user owner 的 issuance 使用 `ix_oauth_token_issuances_tenant_user`，两档均取 5 行且无过滤；VC grant 仍 Seq Scan，返回 5 行，过滤 995 / 9,995 行。上述 relation scan 均 loops=1，完整游标规划另存，未把 DECLARE 规划当成实际 FETCH 耗时。

现有索引足以服务该分布的 issuance user 选择，不能覆盖 client issuance 和 VC owner 的全部选择。候选是针对实际较频繁的 owner 类型选择一条窄索引，例如 issuance `(tenant_id, client_id)` 或 active VC grants 的 `(tenant_id, client_id)` / `(tenant_id, subject_id)`。本轮没有创建候选索引，也没有测净收益；新增 issuance 索引每次签发都要维护，active VC partial index 在签发和撤销时也有写成本。最小下一步是仅选择一个真实高频路径，窄 A/B 比较读扫描与签发 WAL/延迟，而非叠加所有索引。

### SCIM COUNT 与 tuple 分页

COUNT Seq Scan 读取 1,002 / 10,002 个目标用户，各过滤 6 个其他 fixture。分页两档选择现有 `ix_users_created_at_desc`，扫描节点实际输出 101 行、过滤 1 行，顶层返回 100 行，loops=1。本分布目标租户占比很高，**没有证明新 tenant/tuple 索引被选择或具有净写入收益**。精确 COUNT 的规模成本有真实证据；`totalResults` 和 count=0 契约由 Rust 分页回归保留。最小下一步只补跨租户交错/同时间戳分布，再判断联合索引收益；不删除返回字段或引入计数投影。

### SCIM event 已确认前缀

无 pending 时仍分别 Seq Scan 1,000 / 10,000 个 events 与 receipts，相关 scan loops=1，最终 0 rows。现有 anti-join 可随已确认前缀放大，实际 SQL 扫描证据成立；没有证明它在生产中占主导，也未定义新的投递状态协议。最大 ACK 不能作为游标。任何后续方案都必须先证明乱序 ACK、晚提交和多个 receiver 的不会漏投语义。

### Grant family 锁

原始 1-family 测试、受控 3-family fixture 和 concurrent rotation target 均实际通过。日志临时启用 statement logging 并关闭参数输出，运行后恢复设置；只保留无秘密参数的 grant 撤销事务，见 [grant-sql-trace.json](../../../../perf/results/diagnostics/pr222-2026-09-27/grant-sql-trace.json)。3-family 的 [fixture patch](../../../../perf/results/diagnostics/pr222-2026-09-27/grant-three-family-fixture.patch) 没有进入运行源码提交，取证后已恢复。

两个目标分别为 `cargo test --locked -p nazo-postgres --test auth_repositories grants_upsert_cover_and_revoke_tokens_atomically -- --nocapture --test-threads=1` 和同样参数下的 `grant_revoke_waits_for_concurrent_refresh_rotation_before_revoking_family`。3-family 只改变第一个测试的输入数量和精确结果断言；保留的无上下文补丁使用 `git apply --unidiff-zero`。

1 family 为 1 次 scope advisory lock + 1 次 family advisory lock；3 families 为 1 + 3 次。实际顺序均为 BEGIN、client lookup、scope lock、按 UUID ASC 读取 family IDs、逐个 family lock、当前 family UPDATE、删除 grant、COMMIT。并发轮换测试证明撤销等待后仍覆盖已提交 successor；没有合并锁前快照或更改锁 key。本轮只证明小样本 SQL 次数和顺序，没有测大 family 数量下的锁等待分布；批量锁方案仍需独立证明顺序与锁后新快照。

SQL fixture 均在事务中；UPDATE 的 EXPLAIN ANALYZE 用 savepoint 回滚，两档完整事务最后回滚且确认测试 tenant 不存在。首次探针遗漏 client 的 realm/organization 绑定，FK 正确拒绝并已回滚；纠正 fixture 后取得以上结果，不将失败尝试算作有效计划。

## 剩余边界与下一步

本轮修复的定向运行、真实 SQL/Lua 和窄计划已完成；最终 HEAD 门禁结果以之后的 PR 评论为准。没有合并、发布、部署或署名追加。

未验证：候选索引净写入收益、冷缓存与生产数据分布、SCIM 联合索引跨租户收益、event 新投递协议、规模化 family 锁等待、真实 SMTP 投递与取消恢复、全链路吞吐/P99/稳定性。最小下一步分别是上述窄分布/单候选 A/B、安全协议证明或专门 SMTP 验证，不扩成容量矩阵。

VP nonce 第二读、mTLS 当前 anchor 查询、VC 跨 await 后的有效期检查继续保留。没有以多一次读取或验证为由删除其安全语义。req/s 与 flow/s、SQL 时间与数据库 CPU、局部计划与整体收益没有互相替代。
