# 全仓库数据模型审查与单一 PR 收敛

本轮以 PR #230 为最终集成分支，吸收 #237 的模型权威修订和 #236 的审查工作。没有合并到 main。源码 SHA、执行结果和性能结论见同目录验收报告；清单数量描述覆盖面，不代表运行时正确性的证明。

审查范围包括 Rust 协议输入输出、领域事实、应用命令与结果、端口、配置、密钥、控制协议、PostgreSQL 表及查询投影、JSON 子文档、Valkey 值与 Lua 转移。测试夹具不作为生产模型；独立 audit receiver 的线格式和 checkpoint 另列。类型别名、错误枚举和依赖装配对象也登记，避免把所有声明都误称为持久化实体。宏生成的四种身份 ID 单独核对；两个 claim 选择器计入普通声明清单。

## 已实施的收敛

| 编号 | 原问题 | 最终权威与边界 | 验证重点 |
| --- | --- | --- | --- |
| M01 | claim 名称数组与完整请求重复保存 | 每个输出目标只保存完整 `OidcClaimRequest`；名称按需导出。UserInfo 与 ID Token 不合并 | 旧名称恢复；完整约束优先；refresh v1 读取/v2 新写；历史 contract key 不重算 |
| M02 | 未使用的 AuthenticationContext 可同时持有 methods 与 AMR；死 UserRow | 删除死模型；实际 SessionRecord 校验 AMR，保留未知方法但不推断 MFA | 空白 AMR 的真实失败/通过；会话旧数据与 Valkey |
| M03 | 原认证事实混入初始 nonce、每代 ID Token SID | nonce 只在初次签发；当前 SID 属于刷新代际；原 auth_time/AMR/ACR/会话身份保留 | 原始认证上下文、SID 缺省语义、刷新收窄、撤销竞争、旧契约 |
| M04 | 已验证 PKCE 仍能表达 challenge 与 method 矛盾 | `S256Pkce` 只表达无 PKCE 或 S256 challenge；raw 请求继续完整校验 | legacy S256 可读；缺 method/plain/双格式冲突拒绝；拒绝前不消费 code |
| M05 | 签名输入中两个独立 sender Option 可形成矛盾 | 签名边界只有 Bearer/Dpop/MutualTls 三态 | 实际签名解码及冲突拒绝；保留 RT 与 AT 约束差异 |
| M06 | resource verifier 强制私有 token_use，却未要求 iat | RFC 9068 的 typ/iat 校验；私有 token_use 可缺省、显式错误仍拒绝 | 旧行为负向证明；fractional NumericDate；缺 iat；显式非 access 类型 |
| M07 | Passkey 的 ID/counter 同时在领域字段、JSON 与列中独立存在 | 领域使用已验证 credential；PG ID/count 列权威；新 JSON 去掉重复项 | 矛盾旧 JSON 负向证明；旧格式一致性；计数 CAS；真实登录/Required |
| M08 | VP response_mode 同时在 request 与外列 | 请求内的类型化 ResponseMode 唯一权威 | migration 拒绝矛盾旧行；正常 up/down；真实 VP/VCI 回归 |
| M09 | 刷新 JSON 编码、摘要与未校验数组进入核心 | PG 拥有 encoding/hash；核心刷新 scopes/audience 为字符串数组 | malformed JSON 不再被静默过滤；历史摘要不重键；精确 source fence |
| M10 | MFA 存储加密 keyring 位于 identity 并穿过工厂 | PG 适配器持有 keyring，启动时一次注入 | 旧 key 解密、AAD 绑定、原子消费/重放/代际竞争；删除无消费者的 split read/CAS API |
| M11 | payload_canonical 名称易被理解为可重新规范化的对象 | ledger 已确定的原始 UTF-8 字节是审计链权威 | 等价 JSON 不同字节具有不同 hash；冻结 wire；不改历史链或 receipt |
| M12 | DeferredCredential 中名为 ciphertext 的字段实为明文 JSON | 领域使用 DeferredPayload；PG 独占序列化、加解密和 AAD | retained ciphertext、错 key/AAD、损坏载荷、租约与回滚 |
| M13 | secret-bearing Debug 派生、VP 整对象序列化 | 敏感模型 Debug 脱敏；VP 使用专用外部 DTO | 格式化不含凭据；保留协议 DTO 与实际密码学材料 |
| M14 | avatar 阶段混合、完成态继续携带上传材料 | 明确授权/claimed/completed；代际 fence 与绝对 expires_at 不变 | 旧 worker 不能完成新 claim；重复完成不能延长 TTL |
| M15 | 消费缓存重复 durable receipt；已验证 CIBA user-code 恒 false | Consumed 仅为缓存状态；持久 receipt 决定重放撤销；raw CIBA 仍拒绝 true | 原伪造旧 marker 夹具原样保留；真实授权码/Valkey；DCR |
| M16 | 无消费者的 capability/disclosure 字段；冗余准备时间 | 删除未使用的 HTTP 签名 capability、selectively_disclosable_claims、Consent/Code issued_at；expires_at 与 auth_time 保留 | legacy 读取与新序列化；原 deadline 不变；实际 VC 签发与元数据测试 |

没有新增通用恢复层、队列或第二套权威；没有以删除提交确认、消费 fence、租户绑定或安全保留期换取简化。

## 按职责的字段与交叉模型账本

每个字段的声明、所属文件与类型在 `models.json`。下面说明这些组内字段的生产者、消费者、生命周期与保留理由。`member-reference-index.json` 是源码导航：文本命中不是类型解析，不把零 `.field` 命中当成无消费者。序列化、解构、SQL 和 Lua 消费另行检查。

| 责任组 | 生产与消费链 | 生命周期与交叉关系判断 |
| --- | --- | --- |
| 身份、账号、profile、租户 | identity 构造/校验 → PG 用户投影 → 登录、SCIM、profile、subject claim 签发 | ID/tenant/realm/org 是不同边界；角色/admin_level/is_active 分别用于权限、层级与启用。profile 的 OIDC 地址/电话/名称字段有实际输出，不因字段多拆表。私有 revocation user_id 不能由 pairwise sub 推导 |
| Session、认证、MFA | 登录/step-up → SessionRecord/Valkey CAS → authorize/logout/profile；MFA adapter → 原子 verify-and-consume | auth_time 秒与微秒完成时刻分别用于协议和 max_age=0；raw version 是 CAS 身份。TOTP generation、last_used_step、backup used_at 与 remembered expiry 分别防跨代修改、重放和超期；不合并 |
| Passkey、federation、avatar | ceremony/provider/上传授权 → 临时状态 → 持久凭据或 profile | ceremony challenge/origin/RP、provider/state/browser binding 是不同持有者约束。OIDC provider ID 保留在交给独立 callback 的已验证配置中；不从 issuer 猜 ID。avatar 哈希、大小、媒体类型和 generation 有对象存储/并发消费者 |
| Client/DCR/metadata | raw Create/Patch/DCR → 已验证 registration → PG OAuthClientRecord → 各端点 policy | raw 缺省、显式 false、无效值必须可区分。不同 endpoint 的签名/加密 alg/enc 不能合并。client secret 只经专用明文交付/哈希边界；registration token 与 client secret 用途不同。sector URI 与已验证 host 分别是注册来源与 pairwise 依据 |
| Authorization/PAR/JAR/consent/code | raw protocol → normalized request → KV preparation → durable decision → code → issuance receipt | redirect_uri_was_supplied 承担兑换一致性；PAR URI/digest 绑定不同事实；原始请求有效期、业务 retain_until、导出 ACK 独立。consent client_name 是批准界面快照。PKCE/claim/消费 marker 已按 M01/M04/M15 收敛 |
| Token/refresh/introspection/revocation | 规范化 TokenIssue → signer → atomic commit → 当前 family/不可变 contract/spent proof | 原始 grant audiences、current audiences、AT audiences 不同；AT/RT sender binding 不一定相同。include_refresh 控制响应，现有 refresh authority 仍须进入最终事务，所以不能简单等同“是否有 family”。member_id/successor/family/key/JTI 各有身份或 fence 消费者 |
| Device/CIBA/logout delivery | 协议请求 → KV 状态机 → 用户决定 → token commit / ping 或 logout sender | poll interval/last_poll/slow-down、delivery attempts/next-attempt/lease 是不同阶段；终态、到期与重试不能互换。状态字节 CAS 与业务 ID 不重复。Lua 的 claim/generation 字段即使没有 Rust 点访问仍有消费者 |
| VCI/VP/DCQL/trust | credential offer/proof/selection → dataset/authorization → lease → signed result；VP request → wallet response → verification | offer/configuration/credential identifier/selection 不能合并；request 与签名 request_object 是不同表示且字节不可随意重建。proof_origin、authorization_id、claim_token_id 绑定不同授权/领取时刻。trust policy ID/digest 是固定信任快照，不能换成当前可变策略 |
| Resource/HTTP signatures | captured HTTP → digest/signature verification → replay store → authorization | 原始 body 与派生 digest 由不可变借用绑定；header Missing/Unique/Invalid 保留歧义拒绝。prepared key 与原 JWK 是计算快照和公开输出，不是两个可独立编辑权威 |
| SCIM/event polling | token policy → typed resource mutation → security event → subscriber receipt | 事务 ID、事件 ID、订阅者 token ID、subject URI 不同；每订阅者 receipt 与全局事件不能合并。错误描述、disposition 作为传输结果保留；普通 audit 与可投递 security event 用途不同 |
| Runtime/tenancy/operator | desired config → validated command → transaction → instance convergence → signed/encoded result | desired/transition/applied revision 各对应请求、进行中和已完成版本；raw canonical command 与 parsed operation 用于签名与执行。恢复挑战的原 key/generation/accepted-signature 和已恢复 slot 保障结果丢失后的幂等，不能取当前状态替代 |
| Key/crypto | stored public metadata + encrypted material → validated generation → pinned signer/verifier | DER 仍供 mdoc 导出，prepared key 供热路径。RSA key family 不决定 RS/PS algorithm。kid/用途/轮转状态/健康/retire_at 各有策略消费者；私钥不进入对外投影或 Debug |
| Host/config/transport | 环境配置 → validated startup → 按模块能力注入 → HTTP DTO | 配置输入可松散，启动后强校验；端点 DTO 不是数据库记录。依赖装配结构含许多服务句柄不属于“几十字段存储对象”。删除失去最后读者的 StartupConfiguration.config，不删除唯一运行时配置 |
| PostgreSQL/KV/对象存储 | 端口语义 → 适配器 query/row/JSON/Lua → 已验证领域结果 | schema/query cache/encryption/key namespace 归适配器；事务、安全期限和消费语义归领域。表列/索引重复是查询或约束投影时保留，未生成第二套可独立修改的业务事实 |
| Audit/exporter/receiver | Required/Telemetry → durable ledger → batch lease → signed receiver ACK → checkpoint/observe → maintenance | 第一次 append 已尝试的批次不能当作“未写入”裁剪。event_time、业务 retain、exported_at、observed_at 各自独立。lease generation 不能由 sequence 推导；exact payload bytes、event hash、batch digest 和 receipt 签名绑定不同层次 |

## 宽模型的具体判断

`OAuthClientRecord` 的 59 个字段由各规范端点的独立协商参数、主体边界和凭据配置组成；它在本轮保持 59 个字段。CIBA user-code 数据库列在此前迁移中已删除，本轮删除的是验证后对象里恒为 false 的派生字段。没有用“字段数量过多”作为拆出多次数据库查询的理由。DCR raw 输入必须保留无效/不支持参数以明确拒绝；已验证对象不再保留恒 false 的 user-code 标记。

`users` 的 profile 字段有 OIDC/SCIM/profile 消费者，但热路径使用窄查询；已删除未使用的大 UserRow。`ConsentPayload` 的 fields 服务请求绑定、批准界面、原认证、输出约束和安全过期；移除 claims/PKCE 重复表达与无读者 issued_at，不删除实际签发需要的 nonce。

`security_audit_events` 中的授权索引列与 payload 不是两个通用授权数据库：授权决定的唯一性和保留由同一事务建立，payload 是不可变证据。`oauth_token_issuances` 是 durable single-use/replay receipt；不能用 KV consumed marker 代替。`oauth_refresh_contracts` 的内容 key 是既存引用身份；新编码只用于新契约，旧 key 不重算。

PostgreSQL 真实 catalog（`postgres-catalog.json`）逐列核对：身份/profile、注册、MFA、授权/刷新/撤销、VCI/VP、租户/runtime/control、审计/订阅回执等独立期限和唯一性约束保留。唯一删除的外部物理冗余列是 VP response_mode；Passkey JSON 内的 id/counter 在新写入中省略，旧行读取时必须与列一致，计数更新使用原 CAS。

Valkey 的 key 与 payload 并非一概重复：租户/主体/随机事务 ID、期望 raw version、索引集合成员、TTL、绝对 deadline 和 Lua generation 分别保护查找、主体绑定、并发和生命周期。session、PAR/consent/code、Device/CIBA、nonce/replay、federation、ceremony、Native SSO、client delivery、avatar、rate/failure counters 均沿实际脚本检查。没有缩短 TTL 或手工清空状态。

宽模型字段数（本轮清单基线 → 最终）仅用于定位变化，不用作性能或设计质量评分：

| 模型 | 字段数 | 判断 |
| --- | ---: | --- |
| DynamicClientRegistrationRequest | 68 → 68 | raw 协议输入保留缺省、拒绝和协商语义 |
| ValidatedClientRegistration | 52 → 51 | 删除恒定 user-code 状态 |
| OAuthClientRecord | 59 → 59 | 当前适配器投影有端点策略消费者 |
| PublicAccountRow / SubjectClaimsRow | 33 / 31 → 33 / 31 | 身份与 claim 输出投影；另一个无消费者 UserRow 已删除 |
| ConsentPayload | 31 → 27 | 消除 claims、PKCE 重复表达和 issued_at |
| CodePayload | 24 → 20 | 同上，原有效期与认证时刻保留 |
| TokenIssue | 30 → 28 | 输出选择由类型化 claim 选择器承担 |
| RefreshToken | 19 → 20 | SID 从原认证上下文移到当前代际；并非以减字段数为目标 |

## 兼容性与规范边界

- [OIDC Core refresh response](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)：原认证时间/上下文与本代响应分开；刷新不重放初始 nonce。
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)：raw PKCE 输入继续按原策略拒绝降级，类型收敛发生在已验证/持久状态。
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)：访问令牌 typ 与 iat 为协议要求；私有 token_use 不能变成标准令牌互操作的额外必填项。
- claim 的 `essential`/`value`/`values` 不被名称覆盖；UserInfo 和 ID Token 输出目标、scope 与显式 claim 请求保持分开。
- 旧短期准备状态可读取；保留 expires_at/auth_time。旧 refresh v1 和旧 Passkey JSON 有专门读取测试。VP migration 对矛盾历史状态拒绝执行，不静默选边。
- 本轮未声称无限期导出故障下 Optional/Disabled 磁盘有界；短测、自然回收和长期容量是不同证据等级。

## 验收边界

静态审查不等于全协议组合的形式化证明，类型清单也不代替真实数据库和故障验证。逐项修复的负向证明、实际命令/退出码、最终 workspace/Clippy/static 检查、四点性能和存储时间序列由本轮验收报告记录。历史性能与故障证据保留，不覆盖、不冒充新 SHA 的结果。
