# OAuth/OIDC/FAPI 最佳实践矩阵实施任务书

Last reviewed: 2026-07-01.

## 目标

本任务书用于执行 `docs/rfc-compliance-matrix.md` 中的最佳实践矩阵。它不把
“规范名称覆盖面”当作目标，而把安全控制面、运行时 profile、metadata truth、
负向测试和可验证实现作为完成标准。

完成定义：

- README、Discovery metadata 和 profile 文档不得声明未实现能力。
- 每个公开能力必须能追溯到代码、配置、迁移、测试或外部部署边界。
- FAPI/OIDC/OAuth 安全边界不得因兼容性或 conformance 套件适配而放宽。
- 兼容例外必须是 per-client 或 per-profile，不得成为全局默认。
- 对 redirect、PKCE、PAR/JAR/JARM、DPoP、mTLS、audience、issuer、nonce、
  refresh token、JWT/JWKS、client assertion 和 metadata 的修改必须有负向测试。

## 状态定义

| 状态 | 含义 |
| --- | --- |
| 完成 | 已有实现，并有本地测试或 OIDF/FAPI conformance 证据支撑当前声明。 |
| 基本完成，需补精确测试 | 主要实现已存在，但尚缺矩阵要求的细粒度负向测试或边界测试。 |
| 部分完成 | 只实现了安全 profile 的一部分，或者只实现了 RFC/OIDC/FAPI 规范中的某个子能力。 |
| 未实现 | 不存在标准端点、grant、metadata、状态模型或签名/验证流程。 |
| 不广告 | 有相邻内部能力或 admin 能力，但不得作为标准协议能力公开声明。 |
| 外部边界 | 主要由部署、客户端、资源服务器或运行环境完成；后端只记录约束和信任边界。 |

## 已完成或可保持的控制项

| ID | 控制项 | 当前状态 | 证据位置 | 保持要求 |
| --- | --- | --- | --- | --- |
| BP-001 | OAuth secure subset：authorization code、refresh token、client credentials；无 implicit/password grant | 完成 | `src/http/token/dispatch.rs`, `src/http/authorization/request.rs`, token dispatch tests | Discovery 只声明已实现 grant；不得新增 implicit/password。 |
| BP-002 | Authorization response type 为 `code` | 完成 | authorization endpoint tests, OIDF matrix | 不引入 front-channel access token / ID Token issuance。 |
| BP-003 | PKCE S256 默认要求 | 完成 | `tests/in_source/src/http/token/tests/authorization_code/pkce.rs` | no-PKCE 只能作为显式 confidential legacy exception，不能用于 public、FAPI 或 sender-constrained clients。 |
| BP-004 | Redirect URI exact binding 和 RFC 8252 native redirect policy | 完成 | `src/support/oauth.rs`, redirect/PKCE tests, admin client tests | loopback port variance 只适用于 native loopback；拒绝 fragment、危险 scheme 和未注册 URI。 |
| BP-005 | Authorization state、session state 和 Valkey 单次状态 | 完成 | authorization request/session tests | 状态存储失败必须 fail closed。 |
| BP-006 | PAR endpoint、PAR handle 持久化和单次消费 | 完成 | `src/http/authorization/par.rs`, `src/http/authorization/request.rs`, PAR tests | PAR payload 不保留客户端 secret；`request_uri` 消费必须一次性。 |
| BP-007 | FAPI profile 自动要求 PAR | 完成 | `src/settings.rs`, `src/http/authorization/request.rs`, FAPI/PAR tests | FAPI 下 non-PAR authorization request 继续拒绝。 |
| BP-008 | Direct signed request object / JAR | 完成 | `src/http/authorization/jar.rs`, JAR/PAR tests | 继续校验签名、issuer/client、audience、nbf/exp、参数冲突。 |
| BP-009 | Signed request object `jti` replay protection policy | 基本完成，需补精确测试 | JAR validation and replay cache tests | 高价值部署建议要求 `REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar`。 |
| BP-010 | JARM / `response_mode=jwt` signed authorization response | 完成 | authorization response JWT tests, OIDF FAPI Message Signing plans | 签名失败不得回退为 unsigned query response；不得暗示 JWE。 |
| BP-011 | RFC 8707 Resource Indicators 全链路绑定 | 完成 | `src/support/oauth.rs`, authorization/PAR/token/refresh tests | `resource` 必须是无 fragment 的 absolute URI；refresh/token 只能收窄不能扩张。 |
| BP-012 | JWT access token audience/resource binding | 完成 | `src/http/token/issue.rs`, token claim tests, resource-server verifier tests | 不为指定 resource 的请求签发宽泛 default audience token。 |
| BP-013 | RFC 9396-style RAR allowlist 和 feature gate | 完成 | `src/domain/authorization_details.rs`, authorization/token/resource-server tests | 新 RAR type 必须补 parser、consent、policy、token claim 和 verifier tests。 |
| BP-014 | Scope 授权和 consent reuse 不扩权 | 基本完成，需补精确测试 | consent/prompt=none tests, grant persistence | silent consent reuse 不得扩展 scope/resource/audience/authorization_details。 |
| BP-015 | Client authentication：public `none` + PKCE；confidential 必须认证；FAPI 只允许 `private_key_jwt` 或 mTLS | 完成 | `src/http/token/client_auth.rs`, `src/http/token/dispatch.rs`, OIDF FAPI plans | client secret auth 只保留 baseline compatibility。 |
| BP-016 | `private_key_jwt` client authentication | 完成 | `src/support/security.rs`, client assertion tests | 保持签名、audience、exp/iat/nbf、jti、key status 和 replay 校验。 |
| BP-017 | mTLS client authentication 和 mTLS sender-constrained token | 完成 | `src/support/mtls.rs`, mTLS tests, FAPI resource tests | certificate header 只在 trusted proxy CIDR 内可信。 |
| BP-018 | DPoP proof validation 和 nonce policy | 完成 | `src/support/dpop.rs`, DPoP tests, resource-server DPoP tests | FAPI DPoP nonce 支持/要求不得因兼容性关闭。 |
| BP-019 | Refresh-token rotation / reuse detection / FAPI sender-constrained refresh behavior | 基本完成，需补精确测试 | `src/http/token/refresh.rs`, refresh tests, `docs/refresh-token-rotation.md` | 区分 baseline bearer rotation 与 FAPI sender-constrained refresh policy。 |
| BP-020 | Refresh-token audience narrowing | 完成 | migration `20260630000100_refresh_token_audience_binding`, refresh audience tests | audience 事实源是 refresh-token 持久状态，不是客户端输入。 |
| BP-021 | Revocation 和 JSON introspection | 完成 | `src/http/token/revoke.rs`, `src/http/token/introspect.rs`, tests | 不泄露 token 有效性；signed introspection 另属 RFC 9701。 |
| BP-022 | RFC 9728 Protected Resource Metadata | 完成 | `src/http/well_known.rs`, well-known/fapi resource tests | external resource API 必须使用一致的 protected resource identifier。 |
| BP-023 | Discovery metadata truth | 完成 | `src/http/well_known.rs`, well-known tests, OIDF Config plans | metadata 只能由 runtime profile/settings/key state 生成。 |
| BP-024 | RFC 9207 authorization response issuer | 完成 | authorization response tests, OIDF matrix | 保持 JARM 交互语义正确。 |
| BP-025 | Key lifecycle、JWKS 发布和 external signer boundary | 完成 | `src/support/keyset.rs`, keyctl/keyset tests | active/previous/retired 状态不得破坏；metadata alg 必须与可用 key 一致。 |
| BP-026 | Pairwise subject / sector identifier | 完成 | sector identifier and admin client tests | sector identifier 获取失败必须 fail closed；避免 SSRF。 |
| BP-027 | UserInfo | 完成 | `src/http/token/userinfo.rs`, UserInfo tests | 需要 `openid` scope，并保留 sender-constrained token 校验。 |
| BP-028 | RP-Initiated Logout 和 Back-Channel Logout | 完成 / profile-scoped | `src/http/profile/oidc_logout.rs`, logout tests | Back-Channel Logout 维持 best-effort 表述，除非实现持久重试。 |
| BP-029 | CORS、cookie/session、CSRF、rate limit、错误语义、敏感日志约束 | 基本完成，需补精确测试 | CORS/session/CSRF/rate-limit/security tests | 按矩阵补 authorization endpoint CORS forbidden、浏览器 token 暴露等专项测试。 |

## 基本完成但需要补齐的精确测试包

| ID | 测试包 | 当前缺口 | 验收条件 |
| --- | --- | --- | --- |
| TP-001 | FAPI precision test pack | 当前已有 FAPI/PAR/PKCE/client-auth/sender-constraint 测试，但需要更精确覆盖 FAPI 条款细节。 | 增加测试：authorization code lifetime <= 60s、PAR `expires_in` < 600s、FAPI PAR 必含 `redirect_uri`、non-PAR authorization request 拒绝、FAPI authorization endpoint 只接受 `client_id` + `request_uri`、避免 307、credential post 后使用 303。 |
| TP-002 | JWT / JOSE BCP negative pack | RFC 8725 控制已部分存在，但矩阵要求更完整的 alg/key confusion 测试。 | 增加测试：`alg=none` 拒绝、wrong key type、wrong `kid`、wrong `use`/`alg`、cross-JWT substitution、weak RSA/unsupported curve、duplicate `kid` 选择或拒绝策略。 |
| TP-003 | Client assertion FAPI clock-skew pack | `private_key_jwt` 已实现，但需按 FAPI 兼容窗口明确测试。 | 增加测试：接受 0-10s future `iat`/`nbf`，拒绝 >60s future；aud 在 FAPI 下必须是 AS issuer string，数组或 endpoint audience 只作为显式兼容例外。 |
| TP-004 | OIDC reauthentication/auth context pack | `max_age`、`prompt`、`auth_time`、`acr`/`amr` 有实现和部分测试，但需矩阵级负向测试。 | 增加测试：stale session、`prompt=none` 下需要 reauth 的失败、unsupported essential claim、不得伪造 `acr`/`amr`、`auth_time` 只在有真实认证证据时输出。 |
| TP-005 | Offline access pack | `offline_access` 与 refresh_token grant 有校验，但需从 OIDC consent/risk 角度补完。 | 增加测试：无 refresh grant 时拒绝 `offline_access`、缺 consent 不发长期 refresh token、scope narrowing、revocation、sender constraint 与 refresh issuance 关系。 |
| TP-006 | Browser / SPA / BFF pack | 当前 CORS 和同源 session 有测试，但未形成浏览器 OAuth profile 测试包。 | 增加测试：禁止 implicit/token fragment、authorization endpoint 不支持 CORS/XHR、credentialed CORS 不泛化、浏览器 refresh-token reuse、browser client silent privilege expansion。 |
| TP-007 | Race/replay pack | 单次状态和 replay 已有测试，但矩阵要求并发重放级别验收。 | 增加测试：authorization code、PAR `request_uri`、request object `jti`、client assertion `jti`、DPoP `jti`、refresh-token family 并发消费。 |
| TP-008 | Metadata overclaim pack | metadata truth 已有测试，但每新增 profile 需要显式防 overclaim。 | 增加测试：未实现 signed introspection、DCR、Device Grant、Token Exchange、Front-Channel Logout、Session Management、JWE/UserInfo signing 时 discovery 不广告。 |

## 部分完成或 profile-scoped 的控制项

| ID | 控制项 | 当前状态 | 不足 | 下一步 |
| --- | --- | --- | --- | --- |
| PS-001 | FAPI 2.0 Message Signing | 部分完成 | signed request object 和 signed authorization response 已覆盖；signed introspection 未实现。 | 先实现 RFC 9701，再单独声明 FAPI signed-introspection option。 |
| PS-002 | RFC 7523 | 部分完成 | `private_key_jwt` 已完成；JWT bearer authorization grant 未实现。 | 若产品需要 assertion grant，另建 trust policy、subject mapping、audience、jti replay 和 grant metadata。 |
| PS-003 | RFC 9101 JAR | profile-scoped | direct signed request object 已实现；external `request_uri` by-reference 未实现。 | 除非有明确生态需求，否则继续 defer；若实现，先设计 SSRF、cache、content-type、allowlist 和 lifetime 控制。 |
| PS-004 | RFC 9396 RAR | profile-scoped | 只支持 allowlisted types，不是通用任意 JSON registry。 | 新增 type 必须走 parser/policy/consent/token/resource-server 全链路。 |
| PS-005 | RFC 9068 JWT access token | profile-scoped | 当前 profile 使用 JWT access token；opaque token + introspection 也是安全可选架构但未实现。 | 不把 JWT access token 写成 OAuth/FAPI 唯一路径；如引入 opaque token，必须补 introspection/cache/revocation/signed response。 |
| PS-006 | Back-Channel Logout | profile-scoped | 已有 best-effort delivery；没有 durable retry queue。 | 若要提升为强交付能力，补队列、重试、遥测、失败状态和测试。 |
| PS-007 | Browser-based clients | profile-scoped | 同源/BFF 风格较清晰，但未建立完整 browser OAuth policy。 | 补 TP-006，并在客户端 metadata 或 profile 中区分 browser/public/native/confidential 风险。 |

## 未实现且不得广告的能力

| ID | 能力 | 状态 | 最小安全实现条件 |
| --- | --- | --- | --- |
| NI-001 | RFC 9701 signed JWT introspection response | 未实现 | JWT response mode、issuer/audience binding、resource-server identity、key selection、content negotiation 或显式 request mode、metadata gating、负向测试。 |
| NI-002 | RFC 8628 Device Authorization Grant | 未实现 | device authorization endpoint、user-code UX、polling interval、`slow_down`、expiration、denial、rate limit、metadata。 |
| NI-003 | RFC 8693 Token Exchange | 未实现 | subject/actor token 验证、impersonation/delegation policy、audience/resource 限制、issued token type policy。 |
| NI-004 | RFC 7591 / OIDC Dynamic Client Registration | 未实现 | initial access token 或 software statement policy、metadata validation、默认低权限、审计日志。 |
| NI-005 | RFC 7592 Dynamic Client Registration Management | 未实现 | registration access token 生命周期、read/update/delete 语义、权限隔离。 |
| NI-006 | RFC 7523 JWT Bearer Authorization Grant | 未实现 | assertion issuer trust、subject mapping、audience、expiry、jti replay、grant-type metadata。 |
| NI-007 | OpenID Connect CIBA / FAPI CIBA | 未实现 | CIBA Core endpoint、`auth_req_id`、用户绑定、consent UX、polling/backchannel state；之后再加 FAPI constraints。 |
| NI-008 | OpenID Connect Front-Channel Logout | 未实现 | client metadata、iframe/session 通知、浏览器测试。 |
| NI-009 | OpenID Connect Session Management | 未实现 | `check_session_iframe`、session state 计算、浏览器轮询测试。 |
| NI-010 | OpenID Connect Federation 1.0 | 未实现 | entity statement、trust anchor、trust chain resolution、metadata policy、trust marks。 |
| NI-011 | OpenID Connect Native SSO | 未实现 | `device_secret` issuance/rotation、grant support、mobile client metadata、revocation。 |
| NI-012 | UserInfo signing/encryption | 未实现 | metadata gating、JWS/JWE alg policy、per-client negotiation、claim minimization、负向测试。 |
| NI-013 | JARM/JWE encrypted authorization responses | 未实现 | JWE alg/enc policy、key management、metadata gating、decryption negative tests。 |
| NI-014 | FAPI 2.0 HTTP Signatures draft | 未实现 | 等待目标生态需求和草案稳定；实现前需要 canonicalization、key binding、签名/验签和资源服务器集成测试。 |
| NI-015 | RFC 9865 cursor pagination / RFC 9967 async SCIM or SCIM Security Events | 不广告 | 当前 SCIM docs 明确关闭；实现前不得在 SCIM ServiceProviderConfig 中广告。 |

## 外部边界任务

| ID | 边界 | 当前状态 | 后端责任 |
| --- | --- | --- | --- |
| EX-001 | TLS / HSTS / RFC 9325 / RFC 8996 | 外部边界 | 后端 README 不把 RFC 8996 写成实现项；部署文档记录 TLS 1.2+/TLS 1.3、HSTS、reverse proxy trust boundary。 |
| EX-002 | mTLS 证书转发 | 外部边界 | 代码只信任 trusted proxy CIDR 内的证书 header；部署文档必须说明代理侧证书验证责任。 |
| EX-003 | Resource server DPoP replay store | 外部边界 | 内置 verifier 的 process-local replay cache 不等于集群共享防重放；文档要求共享 replay store 或确定性路由。 |
| EX-004 | Native app claimed HTTPS / OS binding | 外部边界 | AS 只校验 redirect URI 注册和 RFC 8252 形态；OS/app-claiming 由客户端平台完成。 |
| EX-005 | Browser token storage | 外部边界 / 产品边界 | 后端应偏向 BFF/same-site session；如支持纯 SPA，必须在 profile 和测试中明确 token storage、CORS、refresh-token 风险控制。 |

## 路线计划

### Phase 0：文档基线和声明收口

状态：本次任务范围。

交付：

- 用 `10/10 Revision` 替换 `docs/rfc-compliance-matrix.md`。
- 新增本任务书。
- README 增加任务书入口。
- 确认 RFC 8996 不作为后端实现项重新进入 README 标准表。

验收：

```powershell
rtk proxy git diff --check
rtk rg -n "RFC 8996|fapi-2_0|oauth-best-practice-implementation-plan" README.md README.zh-CN.md docs
```

### Phase 1：补齐“已实现能力”的最佳实践精确测试

优先级最高。目标不是新增功能，而是证明已有安全边界真的完整。

任务：

- TP-001 FAPI precision test pack。
- TP-002 JWT / JOSE BCP negative pack。
- TP-003 Client assertion FAPI clock-skew pack。
- TP-004 OIDC reauthentication/auth context pack。
- TP-005 Offline access pack。
- TP-006 Browser / SPA / BFF pack。
- TP-007 Race/replay pack。
- TP-008 Metadata overclaim pack。

验收：

```powershell
rtk cargo fmt --check
rtk cargo check --workspace --all-targets --all-features --locked
rtk cargo clippy -- -D warnings
rtk cargo test --locked
```

若 Windows 本机 OpenSSL 环境不可用，使用 Docker/Linux builder 运行同等命令，并在结果中明确记录本机失败原因。

### Phase 2：补齐 FAPI Message Signing 的缺口

目标：如果项目要声明更完整的 FAPI 2.0 Message Signing option，先实现 RFC 9701 signed introspection。

任务：

- 设计 introspection JWT response mode。
- 绑定 `iss`、`aud`、resource-server identity、签名 key 和 token active state。
- 增加 metadata gating，未启用时 discovery 不广告。
- 增加 content negotiation 或显式 request parameter。
- 增加篡改、wrong audience、wrong issuer、revoked token、stale token、wrong key 的负向测试。

验收：

- `docs/profile-matrix.md` 中 `fapi2-message-signing-introspection` 从 deferred 转为 implemented 前，必须有本地测试和 OIDF/FAPI 对应证据。
- README 只能在实现后新增 signed introspection 能力声明。

### Phase 3：高风险扩展能力的产品决策

这些不是“越多越好”的 RFC 收集项。每项开工前必须有 threat model 和 profile decision。

候选任务：

- RFC 7523 JWT Bearer Authorization Grant。
- RFC 8628 Device Authorization Grant。
- RFC 8693 Token Exchange。
- RFC 7591 / OIDC DCR。
- RFC 7592 DCR Management。
- OIDC CIBA / FAPI CIBA。

验收前置：

- 新增 `docs/threat-model.md` 对应章节。
- 新增 discovery metadata gating。
- 新增正向、负向、重放、权限扩张、错误语义和日志脱敏测试。
- 确认 capability 不影响 FAPI/high-value profile 默认安全边界。

### Phase 4：生态互操作扩展

低于 Phase 1-3。只有明确目标生态需要时实施。

候选任务：

- OIDC Front-Channel Logout。
- OIDC Session Management。
- OIDC Federation。
- OIDC Native SSO。
- UserInfo signing/encryption。
- JARM encryption。
- FAPI HTTP Signatures draft。
- SCIM RFC 9865 / RFC 9967 能力。

验收：

- 不得因为实现互操作能力降低 baseline secure OAuth/OIDC 或 FAPI profile。
- 每项能力都必须有独立 metadata、配置、禁用默认值和测试证据。

## 工作顺序建议

推荐顺序：

1. TP-001 FAPI precision test pack。
2. TP-002 JWT / JOSE BCP negative pack。
3. TP-008 Metadata overclaim pack。
4. TP-004 OIDC reauthentication/auth context pack。
5. TP-005 Offline access pack。
6. TP-006 Browser / SPA / BFF pack。
7. TP-007 Race/replay pack。
8. RFC 9701 signed introspection。

这个顺序优先验证已经对外声明或已经实现的高风险能力，再考虑新增协议功能。

## 更新规则

当任何任务状态变化时，必须同步更新：

- `docs/rfc-compliance-matrix.md`
- `docs/oauth-best-practice-implementation-plan.zh-CN.md`
- `docs/profile-matrix.md`
- `README.md`
- `README.zh-CN.md`
- 对应 conformance 记录或本地测试证据

不得只改 README 或 discovery metadata 而不补实现与测试。
