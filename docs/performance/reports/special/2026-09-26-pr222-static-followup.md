# PR #222 后续静态性能审查

原始静态审查基准：`8140acc077e3cc58dabc66507b1f26fdc24b358f`；审查报告 checkpoint：`1615707`。审查开始时已核对远端 [PR #222](https://github.com/nazozero/NazoAuth/pull/222) 仍为 open，分支为 `perf/db-hotpath-minimal-0c70d746`，本地与远端一致。首次审查按“继续静态审查、确认更多问题”的要求执行，只提交调查结果，没有修改生产代码或运行测试。上一轮已完成项和历史性能证据见 [前一份报告](2026-09-26-pr222-performance-audit.md)。

**后续修复状态：**用户随后授权实施、反复复核和最小测试。本文件第一至四节保留原始发现及当时的判断，不代表当前代码仍有全部问题；第五节记录修复及保留项，第六节记录上一阶段定向验证，第七节补充 `9035aa5` 之后的 CI 失败定位、重复复核与 checkpoint。F01–F06、F08–F14、F16–F17 已实施，F07 仅处理分页查询与索引；F15、F18 尚未实施。没有新增压测、吞吐或尾延迟收益结论。

## 结论与证据边界

仍存在新的明确问题，包括连接池自阻塞、无用途的昂贵密码哈希、失效通知队列的恢复速度限制、重复全目录处理、凭证验证的全量快照复制，以及多条请求链路的串行数据库往返。另发现一处密钥缓存的退休时间边界错误，必须作为正确性问题独立处理。

以下 18 个主项均给出源码机制、适用场景和最短修法。它们不是 18 个已经测得的严重瓶颈：实际影响取决于功能启用、数据规模、并发和对象大小。尤其不能用 SCIM、Federation、OID4VC 或多租户路径的成本解释没有这些流量的 `/token` mixed 基准。SQL 次数和算法复杂度是静态推导；CPU 占比、尾延迟损失和收益百分比尚未测量。

审查覆盖授权/签发/撤销/内省、身份与 SCIM、密码与 MFA、Valkey 状态及队列、密钥/DPoP/mTLS/metadata、租户目录、审计/退出投递、外部 HTTP/SMTP、OID4VCI/VP。采用沿调用链展开及迁移/消费者交叉检索，没有声称逐行覆盖全仓全部功能。

## 一、优先修复：阻塞、资源放大和生命周期错误

### F01：Federation 唯一冲突恢复持有连接再借连接

**证据：**[federation.rs](../../../../crates/persistence-postgres/src/repositories/federation.rs) 138–188 行：`create_federated` 在 143 行取得连接，事务在 179 行结束，但连接仍在作用域内；184–186 行遇到唯一冲突时调用 `resolve_existing`，后者在 97–99 行再次从同一池借连接。

**场景与影响：**同一个外部身份并发首次登录会合法触发唯一冲突。池大小为 1 时，一个冲突恢复即可持有唯一连接并等待第二个；小池被多个冲突恢复请求占满时，也会相互等待直到池超时。这是本轮最直接的可用性问题，不需要大表或复杂负载才能成立。

**最短修法：**事务返回后、匹配结果前显式释放原连接；保留原有唯一约束和冲突恢复。无需增加重试器、备用池或超时补丁。最小验证为单连接池下重复身份的冲突恢复，以及没有对应 link 的 Conflict 分支。

### F02：无密码账户创建反复执行无消费者的 Argon2

**证据：**SCIM 创建调用 [security.rs](../../../../crates/nazoauth/src/adapters/security.rs) 38–43 行；Federation 首次建户调用 [federation_services.rs](../../../../crates/nazoauth/src/bootstrap/federation_services.rs) 13–33 行。两者都生成随机口令、运行 Argon2，随后丢弃口令，从不交付用户。它们与实际密码登录共用全局信号量；`security.rs` 48–61 行设置内存成本 19,456 KiB、time cost 2、默认并发 8、默认排队超时 100 ms。

**场景与影响：**批量 SCIM 建户或大量 Federation 首登，会占用真实登录所需的 CPU、内存和并发额度。这里的昂贵计算只用于填充一个不可知口令的合法 hash，不能解释成必须逐账户发生的真实用户密码加固。

**最短修法：**复用宿主已经在启动时准备的随机不可知口令 hash（同文件 86–96 行），保持合法 password-hash 存储格式；不产生可交付的默认密码。真实用户密码、MFA 备用码的 Argon2 保留。最小验证应覆盖 provider 返回合法 hash、密码登录不能使用已知默认口令，以及新建账户仍能按现有恢复流程设置密码；避免通过降低 Argon2 参数“解决”问题。

### F03：FAPI 验签缓存没有跨越退休时间时失效

**证据：**[resource_server.rs](../../../../crates/authorization-server/src/domain/resource_server.rs) 87–106 行只用 `Arc<KeySnapshot>` 指针判断缓存是否有效；`keys.jwks()` 只在构建时调用。[model.rs](../../../../crates/key-management/src/model.rs) 195–198、213–216 行的密钥资格却依赖当前时间，`retire_at <= now` 后不可验签。现有 [model 测试](../../../../crates/key-management/tests/unit/model.rs) 169–192 行明确要求同一个捕获快照也遵守退休时间。[key_lifecycle.rs](../../../../crates/nazoauth/src/jobs/key_lifecycle.rs) 16–49、72–87 行按固定周期刷新，没有按退休点触发；刷新失败保留旧 generation。

**判断：**这是验签资格时效不一致，不是性能提升候选。不要写成“所有旧 token 都可以超期使用”：token 的 `exp` 仍检查，自动轮换的退休点包含 token TTL 和额外保护时间，正常旧 token 通常先过期。问题在于应退休密钥仍可被缓存验证器接受，例如仍签出未到期 token 的场景。

**最短修法：**继续复用 generation 内材料，但缓存最晚在下一退休点失效，显式处理时钟回拨；JWKS 投影和退休边界使用同一时刻。无需新轮询任务。短测使用注入时间覆盖退休前/恰好/之后、刷新失败、回拨和同 kid 新 generation。处理 F13 的公钥预准备之前，必须先保证此边界。

### F04：CIBA 扫掉失效成员后，把扫描饱和误判成队列空闲

**证据：**[ciba.rs](../../../../crates/state-store-valkey/src/ciba.rs) 82–129 行按最多 8 个 ZSET 成员扫描，但只返回真正可投递的 deliveries；[worker](../../../../crates/authorization-server/src/workers/ciba_ping.rs) 46–55 行返回 deliveries 数量；[调度](../../../../crates/nazoauth/src/jobs/ciba_ping.rs) 9–19 行仅数量等于 8 才继续，否则等 500 ms。

**场景与影响：**state 在授权到期加 120 秒后自然过期，ZSET 成员不会随之删除。停机恢复或积压时，前面可有大量失效成员。全失效页每次清 8 个、再等 500 ms，静态清退上界约 16 个/秒，实际还低；N 个页头失效成员可增加约 `floor(N / 8) × 500 ms` 的无效等待，拖累后方正常通知。上轮满投递批继续处理的修改没有覆盖这个场景。

**最短修法：**同一次有界 Lua 返回扫描数和 deliveries，调度依据扫描是否饱和；不增加查询，不在 Lua 中无限循环。保留 8 并发、15 秒 lease、attempt fencing、expiry 与重试时间。短测只需前 8 个失效、第 9 个有效，以及满扫描但部分投递、真正空队列和错误退避。

### F05：租户目录每秒全量解析，缓存故障进一步放大成全目录查库

**证据：**[tenant_runtime.rs](../../../../crates/nazoauth/src/bootstrap/startup/tenant_runtime.rs) 442–479 行先 `cache.load()` 再比较 revision；[tenant_directory.rs](../../../../crates/state-store-valkey/src/tenant_directory.rs) 88–97、170–278 行 GET 完整 JSON、解析并校验每个租户。缓存 miss/error 调用 `reconcile_database_locked(true)`；517 行的 revision 快路被 `!repair_cache` 条件挡住，即使数据库与本地 revision 相等，仍在 520–534 行全量 `load_active`、重新发布。真实目录查询见 [tenancy.rs](../../../../crates/persistence-postgres/src/repositories/tenancy.rs) 263–290 行。

**场景与影响：**T 个租户、R 个副本的空闲轮询仍有 O(R×T) 传输和解析；Valkey 持续故障时，每实例每秒尝试全目录 PG 查询和缓存修复，反而向事实源施加更大压力。这不是已修复的单租户 module reconciliation 查询，属于另一个目录刷新层。

**最短方向：**先让缓存修复复用已被数据库 revision 确认的权威目录，不因 repair 标志无条件重查全目录。健康轮询可先比较已验证原始字节来省解析，但不能声称同时省了传输。若设计 revision 条件取件，必须保证 revision 与 payload 原子对应；不把 JSON 解码移进 Lua 就称作优化。保留 ahead-of-DB 拒绝、同 revision 损坏修复及刷新时效。短测聚焦缓存持续失败但数据库 revision 未变、真实变更、损坏和超前缓存。

### F06：租户目录发布时用两轮全目录查找，形成 O(T²)

**证据：**[tenant_runtime.rs](../../../../crates/nazoauth/src/bootstrap/startup/tenant_runtime.rs) 618–626 行对每个旧 runtime 遍历所有新 runtime，分别检查实例与 lifecycle 的 `Arc::ptr_eq`。

**场景与影响：**目录只改变一个租户，也会对整个目录做平方级比较；F05 的故障路径还可反复触发。单租户不敏感，多租户规模下会放大。

**最短修法：**利用已有 tenant_id 身份构建一次查找，再做相同的实例/lifecycle 判定，或一次构建保留指针集合。不要增加持久缓存。短测只验证不变、替换、移除和复用 lifecycle 时不误停任务。

### F07：SCIM 游标分页每页仍精确全量计数，排序缺少匹配联合索引

**证据：**[scim.rs](../../../../crates/persistence-postgres/src/repositories/scim.rs) 50–97 行每页先 count，再按 `(created_at,id)` 取数据；[HTTP SCIM](../../../../crates/http-actix/src/scim.rs) 205–255 行的 cursor 路径虽用 `count+1` 判断下一页，仍读取、输出精确 total。当前迁移中 users 只有独立 tenant_id、全局 created_at 等索引，没有 `(tenant_id,created_at,id)`；[管理员列表](../../../../crates/persistence-postgres/src/repositories/users.rs) 304–333 行也受排序索引缺口影响。

**场景与影响：**无过滤的 N 用户目录、每页 P 个用户，全量同步的重复精确计数具有约 N²/P 的条目检查量级；百万用户、100/页对应约 100 亿条目检查。这是逻辑工作量推导，不等同物理磁盘读取、CPU 时间或已执行计划。

**规范边界：**不能无条件删除 `totalResults`。[RFC 9865 §2](https://www.rfc-editor.org/rfc/rfc9865.html#section-2) 对 cursor 省略 total 有条件，`count=0` 仍专门请求 total；现有 index 分页和 API 精确计数契约需要保留。先评估租户/排序联合索引与 tuple cursor 的窄改动，再独立决定计数契约。短测用分页相同 timestamp、跨租户、count=0；真实大目录计划以后只针对这两条查询验证。

### F08：VP 验证每凭证复制撤销快照并重新校验完整结构

**证据：**[model.rs](../../../../crates/key-management/src/model.rs) 747–754 行返回 `Arc::new(material.public.clone())`，其 entries 是深拷贝，并非共享已有 Arc。[certificates.rs](../../../../crates/authorization-server/src/domain/openid4vc/credential_crypto/certificates.rs) 109、133、136 行两次获取材料、又复制撤销快照。[trust.rs](../../../../crates/digital-credentials/src/trust.rs) 353–354 →155–159 →126–150 行每凭证重建 BTreeSet 做结构/去重校验，362–364 →169–179 行再为每个链证书线性查条目。结构已在 generation 加载阶段校验，见 [database.rs](../../../../crates/key-management/src/database.rs) 316–319 行。

**场景与影响：**每个 SD-JWT VC 或 mdoc 验证至少产生三次条目级复制，并支付 O(N log N) 全快照结构校验及按链长度叠加的线性查询。撤销集合 N 较大或一次呈现多个凭证时，会消耗明显的内存带宽和 CPU；尚无实际占比。

**最短方向：**generation 共享已准备的公共材料、已验证且按身份索引的撤销视图；请求继续验证时间 freshness 和状态。不能直接删掉公共构造路径的结构校验，也不能缓存“证书仍有效”的最终判定。短测覆盖 snapshot 替换、损坏新快照、next_update 边界、unknown/revoked 与同证书不同 issuer 的现有冲突语义。

### F09：OID4VCI attestation 展开时复制整份声明，形成 O(K²)

**证据：**[proof_validator.rs](../../../../crates/authorization-server/src/domain/openid4vc/proof_validator.rs) 102–112 行遍历 K 个 `attested_keys`，每个结果都 `claims.clone()`，复制包括全部 K 个 key 的声明；[service.rs](../../../../crates/openid4vci/src/service.rs) 476–479 行只保留 `holder_binding`。返回值的 `proof_type`、`nonce`、`key_attestation` 没有生产消费者。

**最短修法：**移除无消费者的返回字段，保留 validator 内完整签名、nonce、时间、attestation 与 holder 绑定检查。拷贝可回到 O(K)，必要的 K 份签发保留。

**已经排除的误判：**这不是 `batch_size=10` 被绕过。[OID4VCI 1.0 §12.2.4、F.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) 中 batch_size 约束 proofs 数组大小，并建议对 attested_keys 中每个公钥签发；不能直接将展开数截断为 10。短测包括多 key、单 attestation 超过 10 个 key，以及非法签名/nonce/holder 的原拒绝路径。

## 二、确定的局部重复工作

| ID | 源码与触发场景 | 最短修法及保留边界 |
| --- | --- | --- |
| F10 | OIDC logout 双层 N+1：[logout_service.rs](../../../../crates/authorization-server-core/src/logout_service.rs) 169、260–283 行逐个 RP 查 client，hint 可能重复；[audit.rs](../../../../crates/persistence-postgres/src/repositories/audit.rs) 135–177 行名称为 batch，实际逐个 INSERT，`RETURNING id` 没有消费者，冲突还执行无效 UPDATE。 | tenant+client_ids 批量读取、请求内复用 hint；outbox 单次批量 INSERT，目标唯一键冲突保持首份 JWT，可使用 DO NOTHING。保留每 RP 独立签名、active/租户/pairwise 绑定、Required audit、全批回滚。N 个绑定 RP、M 个通知 RP 的 SQL 量由 N+M 降为固定批量数；签名次数不能据此删除。 |
| F11 | 合法 access-token 撤销仍先查两张 refresh 表：[token_service.rs](../../../../crates/authorization-server-core/src/token_service.rs) 785–809 → [tokens.rs](../../../../crates/persistence-postgres/src/repositories/tokens.rs) 238–292、856–886。已有 [query_counts 测试源码](../../../../crates/persistence-postgres/tests/query_counts.rs) 525–559 断言 3 条业务 SQL＋事务控制。 | 在已验签并确认 client 归属的应用分支，复用现成 `revoke_issued_tokens(..., None family)` 单 upsert 路径；保留 exp+skew 与 audit updated 语义。不能直接改混合底层接口的优先级：同测试569–623明确维护 raw refresh 优先于附带 JTI 的兼容契约。 |
| F12 | Encrypted JAR 的单次解密仍每请求重建固定私钥：[request_object_encryption.rs](../../../../crates/key-management/src/request_object_encryption.rs) 78–81 行 PEM→DER；[key_wrap.rs](../../../../crates/crypto/src/key_wrap.rs) 88–96 行构造 AWS-LC private/OAEP 对象。 | 在 generation 加载时准备一次 OAEP 私钥材料；请求直接复用，保留独立加密 key、kid/alg/enc/cty、tag 与轮换边界。不是上轮双重解密问题的重复计数，不缓存明文。 |
| F13 | FAPI 每个 access token 重建固定公钥：[resource-server/lib.rs](../../../../crates/resource-server/src/lib.rs) 206–218；[jwk.rs](../../../../crates/resource-server/src/jwk.rs) 33–66 先解组件做长度校验，构造器又解一次。 | immutable verifier 构造时准备 key，沿已有 generation 生命周期复用；先修 F03。保留重复 kid、unknown kid、命中损坏 key 的错误分类；不能因为预解析而让无关坏 key 导致整个 JWKS 拒绝。 |
| F14 | Remembered MFA 命中后更新无消费者的 last_used_at：[remembered_devices.rs](../../../../crates/persistence-postgres/src/repositories/mfa/remembered_devices.rs) 19–43。全库读取与过期判断均未消费此列。 | 单条 SELECT/EXISTS 保留 tenant/user/token/expiry/UA 校验，删除这次 UPDATE。可减少一次往返、行版本和 WAL。UA 的 NULL 相等语义必须保留。不要类推删除 passkey 的 last-used/counter 更新，后者有展示和 CAS 消费者。 |
| F15 | 停用 owner 的撤销查询缺匹配索引：[token_issuance.rs](../../../../crates/persistence-postgres/src/repositories/token_issuance.rs) 42–141。issuance 唯一带 client 的索引仅覆盖 single-use；VC grants 无 tenant+client/subject 索引。 | 这是需真实计划确认的结构性风险。client/user 停用与撤销同事务持锁，相关签发 FOR SHARE 会等待。先用目标 owner 小、其他 owner 大的 fixture 看计划，再选择窄索引；不能静态叠加所有宽索引、忽略签发写放大，也不能异步撤销或去掉 principal 锁。 |
| F16 | Discovery/授权服务器/资源服务器 metadata 不消费 JWKS，却每请求构建它：[domain/metadata.rs](../../../../crates/authorization-server/src/domain/metadata.rs) 52–61；[HTTP metadata](../../../../crates/http-actix/src/metadata.rs) 63–82；[jwks.rs](../../../../crates/key-management/src/jwks.rs) 9–25。 | 让真正的 `/jwks` 消费者读取 JWKS，其他 metadata 保留所需算法和模块快照。没有必要引入全局 JSON 缓存。单次成本较小，静态端点高请求量时才可能放大。 |
| F17 | Federation 每个上游步骤新建 HTTP client：[federation.rs](../../../../crates/nazoauth/src/http/auth/federation.rs) 67–76、238–260；OIDC exchange/JWKS 两次；Social token/openid/userinfo 两到三次。 | 在现有配置/宿主服务生命周期内持有 Client，保留 no_proxy、禁止 redirect、超时和响应体上限。每次 callback 拉 JWKS 也有上游 RTT，但缓存需独立保留轮换、新鲜度、失败语义及 provider 私网政策；不直接套用另一 resolver 改变网络权限。 |
| F18 | OID4VP signed request_uri POST 查询同一事务两遍再 UPDATE：[应用](../../../../crates/authorization-server/src/domain/openid4vc_endpoints/openid4vp.rs) 603–637；[仓储](../../../../crates/persistence-postgres/src/repositories/openid4vc_presentation.rs) 202–225。 | 首读保留以判断请求方法；nonce binding 用保留原谓词的条件 UPDATE…RETURNING，可从3条降为2条，并省完整JSON回传。必须先处理损坏JSON原先在UPDATE前失败的副作用边界，不能机械换成jsonb_set。 |

## 三、较小或限定场景的候选

| 项目 | 证据与处理判断 |
| --- | --- |
| MFA 备用码逐条 INSERT | [backup_codes.rs](../../../../crates/persistence-postgres/src/repositories/mfa/backup_codes.rs) 128–145、[totp.rs](../../../../crates/persistence-postgres/src/repositories/mfa/totp.rs) 260–275：通常10条事务内串行写。可单次 batch，保留空列表清空、TOTP确认、防重放和审计；Argon2已经在事务外。低频管理路径，不能称作全局主因。 |
| Refresh 纯转换占用连接 | [tokens.rs](../../../../crates/persistence-postgres/src/repositories/tokens.rs) 156–165、413–483、493–577：解析/克隆 contract 时仍持连接。可 owned row 读取后归还连接、move 转换；保留 current/spent 联合快照、missing/corrupt 错误。大 RAR/context 才更敏感。 |
| Lost-response 无效借池 | 同文件186–195先借连接，991–999才发现无DPoP/mTLS绑定并返回None。可将单一纯判断提前；最终 replay/compromise 审计不能删。 |
| 已过期 introspection 仍查询撤销库 | [token_service.rs](../../../../crates/authorization-server-core/src/token_service.rs) 740–745：可以先作已确定的expiry拒绝。只影响验签leeway内、业务时间已过期的输入；应明确 expired+存储故障改为Inactive，仍有效token继续查撤销。 |
| CIBA/Device JSON 包裹 JSON | [ciba.rs](../../../../crates/state-store-valkey/src/ciba.rs) 237–256、[device.rs](../../../../crates/state-store-valkey/src/device.rs) 139–162：Lua转义raw JSON，Rust解析包装、复制raw、再解析state。原子RESP tuple可省包装，但不能拆成非原子GET/EXPIRETIME。属于常数开销。 |
| DPoP 重复签名解码 | [dpop.rs](../../../../crates/authorization-server-core/src/dpop.rs) 389–417、521–530：第一次解码后丢弃、之后再解码；可请求内保留字节并借用header.payload，保持错误顺序。 |
| 独立 verifier 本地 replay 全表扫描 | [resource-server/dpop.rs](../../../../crates/resource-server/src/dpop.rs) 214–232：每次持全局Mutex retain HashMap。高吞吐嵌入消费者需关注；NazoAuth主服务用外部replay store，不走这条扫描，不能归因当前服务。 |
| mTLS 与外部 signer 重复准备 | [client_auth.rs](../../../../crates/authorization-server/src/token/client_auth.rs) 264–275 → [certificate.rs](../../../../crates/crypto/src/certificate.rs) 94–108 重建当前anchor verifier；[external.rs](../../../../crates/key-management/src/external.rs) 49–51重建回验公钥。可复用精确bundle/generation的准备材料，但逐请求信任、有效期和签名回验必须保留。 |
| OID4VC 同 lease 重复证书工作 | [certificates.rs](../../../../crates/authorization-server/src/domain/openid4vc/credential_crypto/certificates.rs) 82–90、152–169与[signer.rs](../../../../crates/authorization-server/src/domain/openid4vc/credential_crypto/signer.rs) 19：client ID及签名重复解析PEM、验链、编码x5c。静态材料可随generation/lease准备，时间、撤销及签名资格仍逐次检查。 |
| VCI/VP 纯计算持有连接 | [openid4vc_dataset.rs](../../../../crates/persistence-postgres/src/repositories/openid4vc_dataset.rs) 181–207读取后持连接解密/解析；[openid4vc_presentation.rs](../../../../crates/persistence-postgres/src/repositories/openid4vc_presentation.rs) 244–255先借连接再序列化/加密。可直接缩短lease；不是Argon2级成本。 |
| SD-JWT disclosure 线性匹配 | [sd_jwt.rs](../../../../crates/authorization-server/src/domain/openid4vc/credential_crypto/sd_jwt.rs) 137–145为每个披露值遍历摘要数组，D×M。可一次构建引用集合，保留重复披露/claim拒绝；小凭证优先级低。 |
| SMTP 每邮件重建 transport | [email.rs](../../../../crates/nazoauth/src/adapters/email.rs) 49、103–121。已有长寿命服务可持有transport；当前lettre未启用pool feature，不能声称仅移动构造位置就复用了SMTP连接。须保留TLS、认证、发送失败撤销语义；该路径有cooldown，不是token热路径。 |
| SCIM PUT 事件关闭仍读旧整行 | [scim.rs](../../../../crates/persistence-postgres/src/repositories/scim.rs) 192–222：旧值唯一用于可选事件的active转换，关闭事件时可能省一查。PATCH需要旧值合并，DELETE要区分状态，不能一并删。 |

## 四、明确保留的成本及实施顺序

没有找到可直接删除 issuance principal 锁、refresh family/scope 锁、密码验证后的账户重读、会话当前账户读取、Passkey counter CAS、Device/CIBA 冲突重读的依据。这些维护撤销、原子提交或并发语义。Audit append 已批量化，anchor 成功批次会立即继续，网络发送发生在 claim 事务之后；本轮不再将它们列作逐条写入或满批固定等待。

建议实施顺序：先 F01 连接归还与 F03 退休边界；随后 F02 无效 Argon2、F04 失效页继续扫描、F14 无消费者写、F11 access-only撤销及 F10 logout 批量化；再按实际部署是否启用多租户/SCIM/VC，处理对应数据规模放大。索引、SCIM total语义、上游JWKS新鲜度不得与无语义变化的小改动混成一个提交。

后续每项仍独立 checkpoint。验证优先用小池冲突、注入时间、暂停时钟、端口调用计数和现有协议负向案例；涉及真实SQL/Lua的项目只执行相应数据库/Valkey目标，服务不可用时明确记为未执行。只有选择率/计划不确定的 F07/F15 等需要窄数据分布的 EXPLAIN，不先重开全量容量或长时soak。

**原始审查结束时的状态（`1615707`）：静态审查完成，新增问题尚未实施修复；当时没有新的运行测试或性能收益结论。**

## 五、后续实施与复核

以下“已实施”指代码修改已完成；协议正确性、真实存储行为、CI 和性能实测仍分别按证据判断。修复沿用现有端口与资源生命周期，没有以去锁、降低密码强度、跳过审计或扩大缓存信任代替性能优化。每个已推送的新 checkpoint 均在 PR 中回复修改内容及验证边界。

| 项目 | 实施状态与改动 | 保留的不变量及证据边界 |
| --- | --- | --- |
| F01 | 已实施：事务返回后释放 Federation 连接，再进入唯一冲突恢复（`71f165b`）。 | 唯一约束、既有 link 恢复和 Conflict 分类不变；小池回归目标编译通过，真实 PG 未执行。 |
| F02 | 已实施：SCIM/Federation 无密码建户复用启动期准备的随机不可知口令 hash（`96f84ad`）。 | 不产生已知默认密码，不降低真实口令或 MFA 备用码 Argon2 参数；provider 定向测试通过。 |
| F03 | 已实施：FAPI 验证器缓存同时受 generation、构建时间和下一退休点约束；JWKS 使用同一时刻（`70b7c4b`）。 | 同一快照到期失效、刷新失败期间失效、时钟回拨和新 generation 均复核；5 个密钥/应用定向测试通过。 |
| F04 | 已实施：一次有界 Lua 返回扫描量和 deliveries，调度按扫描是否饱和继续（`b64168d`）。 | 保留 lease、attempt fencing、并发上限及错误退避；应用/宿主定向测试通过，真实 Valkey 脚本回归仅编译。 |
| F05 | 已实施：相同原始 wire 值复用已校验目录；缓存修复复用已由数据库 revision 确认的权威 snapshot（`e0d7283`）。 | 每次仍读 Valkey，未减少全量传输；不将未确认缓存内容当成权威目录重新发布。损坏、超前、数据库变化与缓存持续故障测试覆盖。 |
| F06 | 已实施：发布时一次构造保留 lifecycle 指针集合，删除旧 runtime 对新目录的嵌套扫描（`e0d7283`）。 | 保留不变、替换、移除及共享 lifecycle 的停启行为；与 F05 的 18 个宿主定向测试一起验证。 |
| F07 | **部分实施**：游标谓词改为 `(created_at,id)` tuple range；迁移 `20260927000600` 新增 `(tenant_id,created_at,id)` 索引（`4d35f77`）。 | 保留精确 `totalResults`、独立 tenant 索引及原有 count=0 只查总数的契约。重复全量 COUNT 成本仍在；未做真实数据 EXPLAIN，不能宣称查询计划或净写入收益已验证。普通 CREATE INDEX 的迁移会占用建索引窗口，尚未执行或部署。 |
| F08 | 已实施：generation 共享公共材料与预构建撤销索引，删除逐凭证深拷贝/结构重校验（`63298ff`）。 | 公开损坏输入仍 fail closed；freshness 逐次检查，issuer 冲突、unknown/revoked、失败替换及旧 generation 均保留。17 个撤销快照、2 个 generation 测试通过，并经独立交叉复核。 |
| F09 | 已实施：只返回被消费的 holder binding，移除每个 holder 的整份 attestation claims 拷贝（`0eed70b`）。 | 完整签名、nonce、时间和 holder 绑定仍在 validator 校验；单 attestation 展开 11 个 key 的回归通过，没有错误套用 proofs 数组 batch_size。 |
| F10 | 已实施：logout 按 tenant 批量查 client，复用 hint；outbox 单次批量 INSERT，冲突保留首份 JWT（`5d8ddff`）。 | 每 RP 独立签名、当前 active 状态、pairwise、Required audit 和全批原子性保留；9 个应用退出测试通过，PG 原子性/租户回归仅编译。 |
| F11 | 已实施：已经验签且确认归属的 access token 走现有 access-only 撤销 upsert（`718d042`）。 | 混合底层接口的 raw refresh 优先级不变；保留 expiry/skew 与审计语义。4 个 token-management 测试通过，SQL 次数回归仅编译。 |
| F12 | 已实施：generation 加载时准备 RSA-OAEP 私钥，解密复用准备材料（`8ba0d31`）。 | kid 与私钥固定在同一 generation；alg/enc/cty、CEK 长度、AAD、tag 和轮换边界不变，不缓存明文。4 个 JAR 测试及 OAEP 互操作目标通过，并经独立复核。 |
| F13 | 已实施：immutable verifier 构造时准备公钥（`47c9e85`），沿 F03 的有效期边界复用。 | 无关坏 key 不使整份 JWKS 拒绝；重复 kid、unknown kid、命中坏 key 与算法错误分类保留。40 个 verifier 过滤目标测试通过。 |
| F14 | 已实施：remembered MFA 单次查询验证 tenant/user/token/expiry/UA，删除无人读取的 last_used_at 写入（`c476e0e`）。 | NULL UA 相等语义保留；没有删除 Passkey 的计数器 CAS 或 last-used 更新。PG 目标仅编译。 |
| F15 | **未实施**：owner 撤销索引候选保留待真实执行计划确认。 | 目标 owner 选择率、其他 owner 数据量及签发写放大尚无证据；不静态堆叠宽索引，不异步撤销，不移除 principal 锁。 |
| F16 | 已实施：metadata snapshot 不再构建未消费的 JWKS，仅真正的 `/jwks` 消费者读取（`a2bb664`）。 | 当前算法/模块与 JWKS 退休资格保留；HTTP metadata 定向测试通过。 |
| F17 | 已实施：现有 Federation 配置生命周期持有并复用 HTTP client（`a72f982`）。 | 保留 no_proxy、禁止 redirect、超时及响应体限制；12 个 Federation 定向测试通过。未缓存上游 JWKS，未改变 provider 私网政策；真实网络连接复用收益未测。 |
| F18 | **未实施**：复核后保留现有 nonce binding 读取。 | 原第二次读取承担最新状态及损坏 JSON 在写入前失败的语义。直接 UPDATE RETURNING 不能保留此边界；包事务回滚又增加往返。现有端口没有 observed revision，新增跨层 CAS 契约超出这次减少一条 SQL 的窄改动。 |

较小候选的处理状态：

| 状态 | 范围与边界 |
| --- | --- |
| 已实施 | MFA 备用码 batch INSERT，保留空列表清空与原事务；SCIM PUT 在事件关闭时跳过仅为事件读取的旧值，PATCH/DELETE 所需读取保留。 |
| 已实施 | Refresh owned row 转换前归还连接；无 sender binding 的 lost-response 路径在借池前返回；仍有效 token 内省继续查撤销，已业务过期 token 先返回 Inactive。最后一项明确保留 fail-closed，但 expired token 与存储故障并存时不再返回存储错误。 |
| 已实施 | 授权服务器 DPoP 复用已解码签名与原 compact signing-input 切片；不删验签、时间或 replay 检查。 |
| 已实施 | VC dataset/VP request 解密前归还连接；VP complete 加密后借连接；SD-JWT 一次构造摘要集合，保留非法或重复 disclosure/claim 拒绝。 |
| 已实施 | CIBA/Device 的 JSON 包裹 raw JSON 改原子 RESP tuple（`4bedcf8`）；保持 raw CAS 字节、missing/无 TTL/损坏拒绝以及秒/毫秒绝对过期语义，目标仅编译。 |
| 部分实施 | external signer 回验公钥已按 generation 复用（`ed62692`）；mTLS anchor verifier 和同一 VC signing lease 重复证书处理仍保留，不能缓存信任/时间判定，见第七节。 |
| 已实施/保留 | SMTP transport 已在服务启动准备（`c4543b2`），逐封连接语义保留，未启用 pool；独立 resource-server replay 全表扫描已改到期索引（`297b04b`），不将其成本归因主服务外部 replay 基准，见第七节。 |

## 六、最小验证、CI 与剩余边界

本阶段只做静态推演、交叉复核和下列定向验证，没有重新安装数据库、开展长时 soak 或重跑全量容量矩阵。测试计数只用于描述执行范围，不能折算成性能提升，也不与历史 CI 测试数混用。

| 验证范围 | 已取得的证据 |
| --- | --- |
| 密钥/FAPI | F03 密钥快照 2、应用缓存 3；F13 verifier 过滤目标 40；F12 JAR 4、OAEP 互操作 1 通过。 |
| VC | 撤销快照 17、generation 公共材料 2、OID4VC 应用过滤目标 69、OID4VCI service contract 8 通过；覆盖 malformed/stale/unknown/revoked、holder 与 disclosure 负向案例。 |
| 调度/目录/宿主 | CIBA delivery/host replacement 6+3、宿主调度 5；目录 cache 解码 3、宿主目录 18；未知密码 provider 1；Federation 12；HTTP metadata 1 通过。 |
| 授权/退出 | logout service 9、token management 4、core DPoP 24 通过。 |
| PostgreSQL | `auth_repositories`、`identity_repositories`、`oidc_logout`、`openid4vc`、`query_counts`、`scim_pagination` 已 `--no-run` 编译通过；新增 logout 客户端边界断言后也重新编译了该目标。没有可用的真实 PG 服务，本地没有执行 SQL/锁/回滚/索引计划断言。 |
| Valkey | `ciba_device_contract`、`tenant_directory_cache_contract`、`tenant_namespace_contract` 已 `--no-run` 编译通过。真实 Lua、lease/TTL 和目录缓存集成断言尚未本地执行。 |
| 静态质量 | `80d78cc` 的受影响 11 个包通过 all-targets/all-features Clippy `-D warnings`；格式、静态兼容/迁移契约、持久层依赖隔离、crypto boundary、perf results layout 检查通过。没有添加 lint 豁免。 |
| 原始 CI Failed | 已定位两处授权回归测试中的 strict Clippy 错误，并以 `ebdf632` 修复；相应本地 Clippy 检查完成。此事实不等于后续全部提交的远端 CI 已通过。 |

复核还修正了两处新增测试质量问题（`80d78cc`）：格式与 type-complexity；原测试断言不变。查询该提交的远端工作流时，7 个均仍为 queued，不能声明远端 CI 全绿。后续文档提交将再次触发工作流，PR 评论记录每次 checkpoint 的实际验证范围。F07 的精确总数成本、F15 的计划选择、F18 的安全更新契约，以及上表尚未实施的小项仍有明确边界。**当前结论是已完成多项原则性修复并取得有限定向验证，不是所有候选均已关闭，也不是已经测得项目整体性能收益。**

构建过程中一次因可重建缓存耗尽磁盘而失败；按包清理 Cargo 缓存后重跑有效目标通过。一次未启用 jose feature 的过滤命令运行了 0 项，随后以正确 feature 执行 OAEP 互操作 1 项通过，0 项未计作验证。上述环境/命令修正没有改变生产安全语义。

## 七、最新 CI 失败定位与再次复核

本节审查起点是 `9035aa5194406ed8b82f79827e866fc7f1399cef`，仍在同一个 PR 分支。读取 [code-quality run 36251734705](https://github.com/nazozero/NazoAuth/actions/runs/36251734705) / Rust job `108430916275` 的完整日志及 run 元数据，确认运行对应该提交。它已完成并以 101 退出，不是仍在等待 runtime setup；格式、Clippy 和隔离 schema 准备成功，全量测试收集到恰好两个失败 target：

- `nazo-valkey --test authorization_contract` 的 consent raw-wire 回归把 `actions` 写成对象，触发正确的 authorization-details 校验（该 target 8 通过、1 失败）。
- `nazoauth --lib` 的旧 SCIM bootstrap 测试仍要求每次生成不同 hash，与 F02 的未知秘密预准备契约矛盾（1329 通过、1 失败、3 ignored）。新 provider 回归已通过，但旧断言未同步。

`1336a5a` 修复测试输入与契约：`actions` 改合法字符串数组，对 payment 的嵌套对象改变字段顺序，仍检查原始 wire CAS；合并重复 bootstrap 测试，保留合法 PHC、重复调用、SCIM/Federation 使用预准备 hash 和常见猜测不匹配。没有放宽生产解析器、跳过测试或修改 CI 门禁。

该次 CI 实际运行了 PostgreSQL/Valkey 测试，因此第六节“本地仅编译”的边界不能误读为从未获得远端存储执行证据；但失败 run 也不能当作全绿验收，其结果不能替代下表新增代码的执行证据。

| Checkpoint | 本轮确定修复 | 复核重点 |
| --- | --- | --- |
| `74975a9` | VP nonce bind/result、VCI offer lookup/notification response 共四处 SQL 完成后归还连接，再解密/转换 owned row。 | 不改 SQL、租户/有效期/信任谓词或 nonce 写入；需要损坏输入回滚的 deferred 事务未动。 |
| `297b04b` | embedded resource-server replay 用键集合和绝对到期桶，删除每 proof 锁内全表 retain。 | 未过期记录不驱逐；先 replay 后容量拒绝、精确到期边界、回拨乱序及 clone 原子共享保留。新增两个定向回归。 |
| `ed62692` | external signer 回验复用同 generation 的 prepared key，删除逐响应 JWK 重建。 | 四个调用点均固定 selected/snapshot generation；每次仍验证消息/算法/签名，保留 key_ops、RSA 强度与 EC point normalization。非法点在 generation 发布时提前拒绝。 |
| `f34e529` | OIDC issuance 将 prepared/owned SubjectClaims 直接移动到消费者，删除两处完整 profile clone。 | tenant/subject 校验、错误审计次序和 principal 锁不变；后续没有 prepared_subject 消费者。 |
| `c4543b2` | SMTP adapter 在服务启动准备并持有 transport，省去逐邮件构造配置/TLS 材料。 | 仍逐封独立连接；不启用 pool、不增加任务/配置/依赖。构造失败前移启动已更新配置文档；发送失败清理路径不变。 |
| `5875cb5` | embedded DPoP 借用原 compact signing-input 和 JWK Map，删除字符串重建与 JSON 深拷贝。 | 原段数/空段、签名/claims 解码次序、私钥字段和算法/曲线拒绝保持。 |

作者多轮推演后，独立审阅再次检查 replay 原子性/回拨、generation 固定、owned row 连接寿命、OIDC 所有权及 SMTP 取消路径。没有发现这些改动的新阻塞性缺陷；这不是全仓逐行证明。另重新核对了已修 CIBA/logout 的满扫描继续、并发界限、claim fencing、DNS 整体超时，以及维护流程的有界扫描，未删除协议必需等待或锁。

### 保留项与新确认的规模风险

| 范围 | 当前判断与最小后续证据 |
| --- | --- |
| F07 精确计数、F15 owner 撤销扫描 | 精确 total 是现有接口契约，owner 索引要权衡目标选择率与签发写成本。保留锁及同步撤销；需要窄数据分布的真实 EXPLAIN，不能靠静态添加宽索引宣布完成。 |
| F18 VP nonce 第二读 | 写前 JSON 校验与最新状态语义仍有消费者；直接 JSONB UPDATE 或缓存旧读结果不能等价替代。 |
| mTLS/VC 证书准备 | 当前 anchor 查询必须保留撤销时效；VC client ID 与签名之间跨存储 await，后次有效期检查不能复用先前成功判定。只共享静态 DER 需要进一步确认资源生命周期及收益，不以新跨层缓存替代当前事实源。 |
| SMTP 连接池 | 独立核对 lettre v0.11.23 的 `pool/async_impl.rs` 与 `client/async_connection.rs`：中途取消可能绕过 Err→abort，而 Drop 仍 recycle，仅靠 has_broken/NOOP 不能证明 SMTP 事务干净。故没有启用 pool；本轮没有 SMTP 握手削减结论。 |
| Grant 撤销 family 锁 | [grants.rs](../../../../crates/persistence-postgres/src/repositories/grants.rs) 的 N 个 family 仍逐个 advisory lock，存在 N 次往返。批量化必须证明相同锁 key、UUID 顺序以及锁后新快照；未在缺少真实并发证据时改动。 |
| SCIM event 已确认前缀 | [scim_events.rs](../../../../crates/persistence-postgres/src/repositories/scim_events.rs) 的 poll 从 token 创建时间起 anti-join receipts；默认 7 天保留期内，即使无未确认事件也可能反复排除大量已确认事件。这是新确认的扫描量风险，不是已测瓶颈。不能用最大 ACK 作游标：乱序 ACK、晚提交及多个 receiver 会漏投；需要单独证明投递状态/连续水位契约。 |

因此本轮收敛到“确定、可保持契约的直接冗余已继续处理；剩余项按安全契约或实测计划证据隔离”，不宣称“几乎没有性能问题”。是否存在真实热点还取决于流量组合、数据量和并发，不能把上述低频成本解释成全部项目进度的根因。

### 本轮验证边界

当前工作区没有 Cargo/rustc/rustfmt，没有重装运行时、数据库，也没有手动启动全套、容量矩阵或 soak。`git diff --check`、`verify_static_contracts.py --check`、`check_crypto_boundary.py`、`check_perf_results_layout.py` 通过；依赖图脚本调用 Cargo，因可执行文件不存在而未能运行，不能记为通过。辅助 replay 状态机对旧/新模型进行 30000 次固定种子操作对比一致；这只支持推演，不等于 Rust 测试或性能实测。

新增 Rust 回归、编译和 Clippy 由提交触发的现有远端 CI 验证。检查 `ed62692` 的 run `36255371844` 时格式、静态边界与依赖隔离已通过，Clippy 仍在运行；这些中间状态不等于最终 head 全绿。所有提交均有独立 PR 回复，最终 CI 状态以对应 head 的 Checks 为准。
