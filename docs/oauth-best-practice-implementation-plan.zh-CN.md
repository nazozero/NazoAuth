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

- [x] **BP-001 OAuth secure subset：authorization code、refresh token、client credentials；无 implicit/password grant**
  - 状态：完成
  - 证据：`src/http/token/dispatch.rs`, `src/http/authorization/request.rs`, token dispatch tests
  - 保持要求：Discovery 只声明已实现 grant；不得新增 implicit/password。
- [x] **BP-002 Authorization response type 为 `code`**
  - 状态：完成
  - 证据：authorization endpoint tests, OIDF matrix
  - 保持要求：不引入 front-channel access token / ID Token issuance。
- [x] **BP-003 PKCE S256 默认要求**
  - 状态：完成
  - 证据：`tests/in_source/src/http/token/tests/authorization_code/pkce.rs`
  - 保持要求：no-PKCE 只能作为显式 confidential legacy exception，不能用于 public、FAPI 或 sender-constrained clients。
- [x] **BP-004 Redirect URI exact binding 和 RFC 8252 native redirect policy**
  - 状态：完成
  - 证据：`src/support/oauth.rs`, redirect/PKCE tests, admin client tests
  - 保持要求：loopback port variance 只适用于 native loopback；拒绝 fragment、危险 scheme 和未注册 URI。
- [x] **BP-005 Authorization state、session state 和 Valkey 单次状态**
  - 状态：完成
  - 证据：authorization request/session tests
  - 保持要求：状态存储失败必须 fail closed。
- [x] **BP-006 PAR endpoint、PAR handle 持久化和单次消费**
  - 状态：完成
  - 证据：`src/http/authorization/par.rs`, `src/http/authorization/request.rs`, PAR tests
  - 保持要求：PAR payload 不保留客户端 secret；`request_uri` 消费必须一次性。
- [x] **BP-007 FAPI profile 自动要求 PAR**
  - 状态：完成
  - 证据：`src/settings.rs`, `src/http/authorization/request.rs`, FAPI/PAR tests
  - 保持要求：FAPI 下 non-PAR authorization request 继续拒绝。
- [x] **BP-008 Direct signed request object / JAR**
  - 状态：完成
  - 证据：`src/http/authorization/jar.rs`, JAR/PAR tests
  - 保持要求：继续校验签名、issuer/client、audience、nbf/exp、参数冲突。
- [x] **BP-009 Signed request object `jti` replay protection policy**
  - 状态：完成
  - 证据：`src/http/authorization/jar.rs`, `tests/in_source/src/http/authorization/tests/jar.rs`, `docs/profile-matrix.md`
  - 保持要求：高价值部署建议要求 `REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar`。
- [x] **BP-010 JARM / `response_mode=jwt` signed authorization response**
  - 状态：完成
  - 证据：authorization response JWT tests, OIDF FAPI Message Signing plans
  - 保持要求：签名失败不得回退为 unsigned query response；不得暗示 JWE。
- [x] **BP-011 RFC 8707 Resource Indicators 全链路绑定**
  - 状态：完成
  - 证据：`src/support/oauth.rs`, authorization/PAR/token/refresh tests
  - 保持要求：`resource` 必须是无 fragment 的 absolute URI；refresh/token 只能收窄不能扩张。
- [x] **BP-012 JWT access token audience/resource binding**
  - 状态：完成
  - 证据：`src/http/token/issue.rs`, token claim tests, resource-server verifier tests
  - 保持要求：不为指定 resource 的请求签发宽泛 default audience token。
- [x] **BP-013 RFC 9396-style RAR allowlist 和 feature gate**
  - 状态：完成
  - 证据：`src/domain/authorization_details.rs`, authorization/token/resource-server tests
  - 保持要求：新 RAR type 必须补 parser、consent、policy、token claim 和 verifier tests。
- [x] **BP-014 Scope 授权和 consent reuse 不扩权**
  - 状态：完成
  - 证据：`src/http/authorization/request/prompt_none.rs`, migration `20260701000100_user_grant_resource_indicators`, consent/prompt=none tests, grant persistence tests
  - 保持要求：silent consent reuse 不得扩展 scope/resource/audience/authorization_details。
- [x] **BP-015 Client authentication：public `none` + PKCE；confidential 必须认证；FAPI 只允许 `private_key_jwt` 或 mTLS**
  - 状态：完成
  - 证据：`src/http/token/client_auth.rs`, `src/http/token/dispatch.rs`, OIDF FAPI plans
  - 保持要求：client secret auth 只保留 baseline compatibility。
- [x] **BP-016 `private_key_jwt` client authentication**
  - 状态：完成
  - 证据：`src/support/security.rs`, client assertion tests
  - 保持要求：保持签名、audience、exp/iat/nbf、jti、key status 和 replay 校验。
- [x] **BP-017 mTLS client authentication 和 mTLS sender-constrained token**
  - 状态：完成
  - 证据：`src/support/mtls.rs`, mTLS tests, FAPI resource tests
  - 保持要求：certificate header 只在 trusted proxy CIDR 内可信。
- [x] **BP-018 DPoP proof validation 和 nonce policy**
  - 状态：完成
  - 证据：`src/support/dpop.rs`, DPoP tests, resource-server DPoP tests
  - 保持要求：FAPI DPoP nonce 支持/要求不得因兼容性关闭。
- [x] **BP-019 Refresh-token rotation / reuse detection / FAPI sender-constrained refresh behavior**
  - 状态：完成 / profile-scoped
  - 证据：`src/http/token/refresh.rs`, `src/http/token/issue/refresh_persistence.rs`, refresh rotation/reuse/DPoP/mTLS/audience tests, `docs/refresh-token-rotation.md`, `docs/profile-matrix.md`
  - 保持要求：区分 baseline bearer rotation 与 FAPI sender-constrained refresh policy。
- [x] **BP-020 Refresh-token audience narrowing**
  - 状态：完成
  - 证据：migration `20260630000100_refresh_token_audience_binding`, refresh audience tests
  - 保持要求：audience 事实源是 refresh-token 持久状态，不是客户端输入。
- [x] **BP-021 Revocation 和 JSON introspection**
  - 状态：完成
  - 证据：`src/http/token/revoke.rs`, `src/http/token/introspect.rs`, tests
  - 保持要求：不泄露 token 有效性；signed introspection 另属 RFC 9701。
- [x] **BP-022 RFC 9728 Protected Resource Metadata**
  - 状态：完成
  - 证据：`src/http/well_known.rs`, well-known/fapi resource tests
  - 保持要求：external resource API 必须使用一致的 protected resource identifier。
- [x] **BP-023 Discovery metadata truth**
  - 状态：完成
  - 证据：`src/http/well_known.rs`, well-known tests, OIDF Config plans
  - 保持要求：metadata 只能由 runtime profile/settings/key state 生成。
- [x] **BP-024 RFC 9207 authorization response issuer**
  - 状态：完成
  - 证据：authorization response tests, OIDF matrix
  - 保持要求：保持 JARM 交互语义正确。
- [x] **BP-025 Key lifecycle、JWKS 发布和 external signer boundary**
  - 状态：完成
  - 证据：`src/support/keyset.rs`, keyctl/keyset tests
  - 保持要求：active/previous/retired 状态不得破坏；metadata alg 必须与可用 key 一致。
- [x] **BP-026 Pairwise subject / sector identifier**
  - 状态：完成
  - 证据：sector identifier and admin client tests
  - 保持要求：sector identifier 获取失败必须 fail closed；避免 SSRF。
- [x] **BP-027 UserInfo**
  - 状态：完成
  - 证据：`src/http/token/userinfo.rs`, UserInfo tests
  - 保持要求：需要 `openid` scope，并保留 sender-constrained token 校验。
- [x] **BP-028 RP-Initiated Logout 和 Back-Channel Logout**
  - 状态：完成 / profile-scoped
  - 证据：`src/http/profile/oidc_logout.rs`, `tests/in_source/src/http/profile/tests/oidc_logout.rs`, discovery logout tests
  - 保持要求：Back-Channel Logout 维持 best-effort 表述，除非实现持久重试。
- [x] **BP-029 CORS、cookie/session、CSRF、rate limit、错误语义、敏感日志约束**
  - 状态：完成 / browser-profile-scoped
  - 证据：`src/bootstrap/routes.rs`, CORS/session/CSRF/rate-limit/security tests, authorization endpoint CORS forbidden test
  - 保持要求：后端保持最小 CORS 与同源/BFF session 边界；纯 SPA token storage 仍属 EX-005 产品/部署边界。

## 基本完成但需要补齐的精确测试包

- [x] **TP-001 FAPI precision test pack**
  - 状态：完成
  - 覆盖：code TTL 启动上限、PAR `expires_in` 启动上限、FAPI `/authorize` 外层仅允许 `client_id` + `request_uri`、form credential post 使用 303、FAPI PAR 必含 `redirect_uri`、non-PAR 拒绝、client auth、sender constraint、S256 PKCE、JWKS duplicate-`kid`
  - 验收条件：每次调整 FAPI profile、PAR/JAR、redirect 或 signing key 管理时同步跑 FAPI precision 目标测试。
- [x] **TP-002 JWT / JOSE BCP negative pack**
  - 状态：完成
  - 覆盖：`alg=none`、wrong key type、wrong `kid`、wrong `use`/`alg`、private key material、weak RSA、unsupported curve、invalid signature、duplicate `kid` 和跨用途 JWT 混淆边界
  - 验收条件：所有 JWT 新用途必须走显式 alg allowlist、kid/key/alg 绑定和负向测试。
- [x] **TP-003 Client assertion FAPI clock-skew pack**
  - 状态：完成
  - 覆盖：PAR audience 默认为 AS issuer；endpoint audience 和 audience array 只在客户端显式策略开启时接受；future `iat`/`nbf` 10 秒内接受，超过 60 秒拒绝
  - 验收条件：FAPI client assertion 继续保持 issuer audience 优先，兼容例外必须是 per-client policy。
- [x] **TP-004 OIDC reauthentication/auth context pack**
  - 状态：完成
  - 覆盖：`max_age`、`prompt=login`、`prompt=none`、reauth nonce 单次消费、claims 参数解析、unsupported essential claim、`auth_time` 请求，以及不伪造未支撑的 `acr`/`amr`
  - 验收条件：新增认证方式或会话恢复路径时，必须证明 `auth_time`、`amr`、`acr` 来自真实认证证据。
- [x] **TP-005 Offline access pack**
  - 状态：完成
  - 覆盖：`offline_access` 必须配套 `refresh_token` grant、无 consent 不发长期 refresh token、scope/audience narrowing、revocation、refresh family reuse detection 和 sender-constrained refresh policy
  - 验收条件：refresh-token 行为变更必须保持权限不扩张、重放 fail-closed 和撤销隐私。
- [x] **TP-006 Browser / SPA / BFF pack**
  - 状态：完成
  - 覆盖：禁止 implicit/token authorization response、禁止 fragment response mode、authorization endpoint 无 CORS、browser OAuth CORS 不带 credentials、DPoP/retry challenge headers 暴露、refresh grant 不允许 silent privilege expansion
  - 验收条件：后端默认维持 BFF/same-origin session 边界；纯 SPA token storage 仍是产品/部署决策，不通过默认文档暗示安全。
- [x] **TP-007 Race/replay pack**
  - 状态：完成
  - 覆盖：authorization code、PAR `request_uri`、request object `jti`、client assertion `jti`、DPoP `jti`、refresh-token family 的单次消费或 replay fail-closed，并新增 PAR `GETDEL` 并发消费只能有一个 winner 的验收测试
  - 验收条件：对所有一次性凭据继续使用原子持久化/消费；新增状态句柄必须增加并发或 replay 代表性测试。
- [x] **TP-008 Metadata overclaim pack**
  - 状态：完成
  - 覆盖：Discovery 防 overclaim 覆盖 signed introspection、DCR、Device Grant、Token Exchange、JWT bearer grant、Front-Channel Logout、Session Management、JWE/UserInfo signing/encryption；新增 RFC 9701 和 RFC 7523 grant 后同步改为 profile/实现 gated
  - 验收条件：每新增 profile 或协议能力时必须先更新 metadata gating 测试，再更新 README 或 discovery 声明。

## 部分完成或 profile-scoped 的控制项

- [x] **PS-001 FAPI 2.0 Message Signing**
  - 状态：完成 / profile-scoped
  - 当前边界：signed request object、JARM 和 RFC 9701 signed/nested encrypted introspection 都已实现；JWT introspection 只在 `fapi2-message-signing-introspection` profile 且客户端请求 JWT media type 时返回
  - 下一步：JWE 只在 resource-server client 配置受支持的 `introspection_encrypted_response_alg`/`enc` 和匹配加密 JWK 后返回；错误响应保持 JSON OAuth error。
- [x] **NI-001 RFC 9701 JWE introspection response**
  - 状态：完成 / profile-scoped
  - 证据：`src/http/token/introspect.rs`, `src/support/oauth.rs`, `src/http/well_known.rs`, introspection/JWKS/metadata tests
  - 保持要求：保持 signed-then-encrypted 顺序、`RSA-OAEP-256`/`A256GCM` allowlist、per-client encryption metadata 和匹配 `use=enc` JWK 校验。
- [x] **PS-002 RFC 7523**
  - 状态：完成 / bounded grant
  - 当前边界：`private_key_jwt` 和 JWT bearer authorization grant 均已实现；JWT bearer grant 仅允许已认证 confidential client 为自身 `client_id` 签发 client-subject token，并要求 issuer/audience/time/jti/replay 校验
  - 下一步：不做任意用户 subject mapping；若未来需要第三方 assertion issuer trust，必须单独建 threat model 和 allowlist。
- [x] **PS-003 RFC 9101 JAR**
  - 状态：完成 / profile-scoped
  - 当前边界：direct signed request object 已实现；external `request_uri` by-reference 继续不支持，也不在 metadata 中广告
  - 下一步：只有明确互操作需求时才设计 by-reference JAR，并先解决 SSRF、cache、content-type、allowlist、lifetime 和 key trust。
- [x] **PS-004 RFC 9396 RAR**
  - 状态：完成 / allowlisted profile
  - 当前边界：只支持 allowlisted authorization detail types，不接受任意 JSON registry
  - 下一步：新增 type 必须走 parser/policy/consent/token/resource-server 全链路。
- [x] **PS-005 RFC 9068 JWT access token**
  - 状态：完成 / current token profile
  - 当前边界：当前 profile 使用 JWT access token；opaque token + introspection 是可选架构而非当前实现。RFC 9701 signed introspection 已作为独立 profile 支持
  - 下一步：不把 JWT access token 写成 OAuth/FAPI 唯一路径；如引入 opaque token，必须补 introspection/cache/revocation/signed response。
- [x] **PS-006 Back-Channel Logout**
  - 状态：完成 / best-effort profile
  - 当前边界：已有 signed logout token 和 best-effort delivery；没有声明 durable retry queue
  - 下一步：强交付能力是产品硬化项，需另加队列、重试、遥测、失败状态和测试后再声明。
- [x] **PS-007 Browser-based clients**
  - 状态：完成 / backend policy
  - 当前边界：同源/BFF 默认边界、authorization endpoint 无 CORS、browser OAuth CORS 不带 credentials、code+PKCE、无 implicit/token response 已有测试
  - 下一步：纯 SPA token storage 不作为默认后端能力；若产品启用，必须单独配置、测试 refresh-token 风险和存储边界。

## 默认关闭或未实现且不得无条件广告的能力

- [x] **NI-002 RFC 8628 Device Authorization Grant**
  - 状态：完成，默认关闭；仅当 `ENABLE_DEVICE_AUTHORIZATION_GRANT=true` 且客户端注册包含 `urn:ietf:params:oauth:grant-type:device_code` 时广告和执行。
  - 证据：`src/http/token/device.rs`、`src/http/token/dispatch.rs`、`src/bootstrap/routes.rs`、`src/http/well_known.rs`、`tests/in_source/src/http/token/tests/device.rs`、`tests/in_source/src/http/token/tests/forms.rs`、`tests/in_source/src/http/tests/well_known.rs`。
  - OIDF 覆盖：2026-07-01 检索 OpenID Foundation Conformance Suite 公开 master 快照 `076fbf4`，未发现 RFC 8628 Device Authorization Grant AS-side 官方 plan；只发现 RFC 8414 metadata schema 字段和 CIBA/client 条件复用 `authorization_pending` / `slow_down`。本次不新增 OIDF 矩阵，记录见 `docs/conformance/2026-07-01-ni-002-oidf-coverage.md`。
  - 保持要求：保持 user-code UX、登录+CSRF approval、轮询间隔、`slow_down`、expiration、denial、rate limit、metadata truth 和一次性 device_code 消费。
- [x] **NI-003 RFC 8693 Token Exchange**
  - 状态：完成 / bounded local access-token profile
  - 当前边界：仅接受本授权服务器签发且未撤销的 access token 作为 subject/actor token，仅签发新的本地 access token；要求显式 `resource` 或 RFC 8693 `audience`，scope 只能收窄，`actor_token` 会映射为 `act` claim。
  - 下一步：外部 issuer trust、refresh-token exchange、ID-token exchange、`authorization_details` 传播和更细 audit event 需作为独立 profile 设计。
- [x] **NI-004 RFC 7591 / OIDC Dynamic Client Registration**
  - 状态：完成，默认关闭；仅当 `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true` 时广告 `registration_endpoint` 并启用 `/register`。
  - 当前边界：支持标准 metadata 创建客户端、返回创建后的 client metadata、可通过 `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` 要求 initial access token；不支持 `software_statement` 或 `jwks_uri` 拉取。
  - OIDF 覆盖：OIDC Basic dynamic-client plan 已加入 full matrix 生成器。
  - 保持要求：保持 metadata validation、默认低权限、initial access token、discovery truth 和动态注册一致性测试。
- [x] **NI-005 RFC 7592 Dynamic Client Registration Management**
  - 状态：完成，继承 `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true` 默认关闭边界；仅 DCR 创建且持有 registration access token 的客户端可访问 `/register/{client_id}`。
  - 当前边界：`registration_access_token` 仅以 BLAKE3 哈希存储；GET/PUT 成功后轮换 registration access token，secret-auth 客户端同步轮换 `client_secret`；PUT 采用全量替换并拒绝客户端提交服务器管理字段；DELETE 停用客户端、清除 registration token、撤销 refresh token 行并移除 user grants。
  - 证据：`src/http/dynamic_client_registration.rs`、`src/http/admin/clients/create.rs`、`src/bootstrap/routes.rs`、`migrations/20260702000100_rfc7592_registration_management`、`tests/in_source/src/http/tests/dynamic_client_registration.rs`。
  - OIDF 覆盖：2026-07-02 NI-004 官方 17-plan 矩阵仍以 OIDC dynamic-client plan 为准，见 `docs/conformance/2026-07-02-ni-004-official-oidf-full-matrix.md`；该矩阵存在 2 个预期 `SKIPPED`，不能作为 zero-SKIPPED 证据。NI-005 记录见 `docs/conformance/2026-07-02-ni-005-oidf-coverage.md`。
- [x] **NI-006 RFC 7523 bounded JWT bearer grant**
  - 状态：已实现 bounded profile；`private_key_jwt` 和 `urn:ietf:params:oauth:grant-type:jwt-bearer` 均可用，JWT bearer grant 仅接受已认证 confidential client 对自身 `client_id` 的断言。
  - 当前边界：未开放 third-party assertion issuer trust；外部 issuer allowlist、subject mapping 和跨 issuer trust policy 仍是单独产品决策，不能用当前 self-asserted grant 替代。
  - 证据：`src/http/token/jwt_bearer.rs`、`src/support/oauth.rs`、`tests/in_source/src/http/token/tests/jwt_bearer.rs`、`tests/in_source/src/support/tests/oauth_client_metadata.rs`。
- [x] **NI-007 OpenID Connect CIBA / FAPI CIBA**
  - 状态：已实现默认关闭的 CIBA poll mode；`ENABLE_CIBA=true` 时 discovery 广告 `backchannel_authentication_endpoint` 和 CIBA grant，客户端仍需注册 `urn:openid:params:grant-type:ciba`。
  - 当前边界：支持 `login_hint` 用户绑定、`auth_req_id` Valkey 状态、CSRF 保护的用户 approve/deny、polling interval/`slow_down`/`authorization_pending`、confidential client auth、FAPI profile 的 token endpoint 约束，以及按客户端要求签发 DPoP/mTLS sender-constrained token；不支持 ping/push mode、`user_code` 和独立 CIBA UI 前端。
  - 证据：`src/http/token/ciba.rs`、`src/bootstrap/routes.rs`、`src/http/well_known.rs`、`tests/in_source/src/http/token/tests/ciba.rs`。
  - OIDF 覆盖：`fapi-ciba-id1-test-plan` 已加入 full matrix；2026-07-02 Hostinger targeted run 当前失败，记录见 `docs/conformance/2026-07-02-ni-006-011-hostinger-oidf-results.md`。
- [x] **NI-008 OpenID Connect Front-Channel Logout**
  - 状态：已实现默认关闭；`ENABLE_FRONTCHANNEL_LOGOUT=true` 时 discovery 广告 front-channel logout 支持。
  - 当前边界：DCR/admin client metadata 支持 `frontchannel_logout_uri` / `frontchannel_logout_session_required`；RP-Initiated Logout 成功时为已授权客户端生成 iframe 通知并按要求附加 `iss`/`sid`；仍保留 Back-Channel Logout 作为更强路径。
  - 证据：`migrations/20260702000200_oidc_frontchannel_logout`、`src/http/profile/oidc_logout.rs`、`src/http/dynamic_client_registration.rs`、`tests/in_source/src/http/profile/tests/oidc_logout.rs`。
  - OIDF 覆盖：`oidcc-frontchannel-rp-initiated-logout-certification-test-plan` 已加入 full matrix；2026-07-02 Hostinger isolated run 通过，记录见 `docs/conformance/2026-07-02-ni-006-011-hostinger-oidf-results.md`。
- [x] **NI-009 OpenID Connect Session Management**
  - 状态：已实现默认关闭；`ENABLE_SESSION_MANAGEMENT=true` 时 discovery 广告 `check_session_iframe`。
  - 当前边界：授权码响应包含 `session_state`；`/check_session` iframe 使用 postMessage + same-origin status endpoint 返回 `unchanged`/`changed`/`error`；响应 no-store，未把该浏览器轮询机制作为主 logout 安全边界。
  - 证据：`src/http/profile/session_management.rs`、`src/http/profile/session_management_iframe.*.html`、`src/http/authorization/request.rs`、`tests/in_source/src/http/profile/tests/session_management.rs`。
  - OIDF 覆盖：`oidcc-session-management-certification-test-plan` 已加入 full matrix；2026-07-02 Hostinger targeted run 通过，记录见 `docs/conformance/2026-07-02-ni-006-011-hostinger-oidf-results.md`。
- [ ] **NI-010 OpenID Connect Federation 1.0**
  - 状态：已实现默认关闭的 self-issued entity statement endpoint；`ENABLE_OIDC_FEDERATION=true` 时 `/.well-known/openid-federation` 返回 `application/entity-statement+jwt`。
  - 当前边界：仅覆盖 deployed entity/OP 元数据发布的最小 entity statement；trust anchor 配置、trust chain resolution、metadata policy、trust marks、federation fetch/list/resolve 尚未实现，不能声明完整 Federation 1.0 OP/RP 加入测试联盟能力。
  - 证据：`src/http/federation_entity.rs`、`src/bootstrap/routes.rs`、`tests/in_source/src/http/tests/federation_entity.rs`。
- [x] **NI-011 OpenID Connect Native SSO**
  - 状态：已实现默认关闭；`ENABLE_NATIVE_SSO=true` 时 discovery 广告 `native_sso_supported` 并将 `device_sso` 加入 `scopes_supported`。
  - 当前边界：authorization code 中的 `device_sso` 触发 `device_secret` 签发和 ID Token `ds_hash`/`sid` 绑定；Native SSO token exchange 使用 ID Token + `urn:openid:params:token-type:device-secret`，校验签名、`ds_hash`、session state、refresh family 活性、同租户和客户端 `device_sso` scope；不支持平台证书/应用签名证明，需由移动端安全存储边界保证。
  - 证据：`src/http/token/native_sso.rs`、`src/http/token/issue.rs`、`src/http/token/token_exchange.rs`、`tests/in_source/src/http/token/tests/native_sso.rs`。
- [ ] **NI-012 UserInfo signing/encryption**
  - 状态：未实现
  - 最小安全实现条件：metadata gating、JWS/JWE alg policy、per-client negotiation、claim minimization、负向测试。
- [ ] **NI-013 JARM/JWE encrypted authorization responses**
  - 状态：未实现
  - 最小安全实现条件：JWE alg/enc policy、key management、metadata gating、decryption negative tests。
- [ ] **NI-014 FAPI 2.0 HTTP Signatures draft**
  - 状态：未实现
  - 最小安全实现条件：等待目标生态需求和草案稳定；实现前需要 canonicalization、key binding、签名/验签和资源服务器集成测试。
- [ ] **NI-015 RFC 9865 cursor pagination / RFC 9967 async SCIM or SCIM Security Events**
  - 状态：不广告
  - 最小安全实现条件：当前 SCIM docs 明确关闭；实现前不得在 SCIM ServiceProviderConfig 中广告。

## NI OIDF 矩阵标注

检索日期：2026-07-02。检索对象：OpenID Foundation `conformance-suite`
源码快照 `21845642d279eacf627ed682094949050f1a88a4`。本表是后续每个
NI 任务的默认 OIDF 矩阵动作；实现任务时仍需重新确认官方 suite 是否更新。

| 任务 | 官方 suite 发现 | 本仓库矩阵动作 |
| --- | --- | --- |
| NI-001 RFC 9701 JWE introspection response | FAPI2 Message Signing Final plans 已覆盖 signed/encrypted introspection 相关 profile。 | 已在 full matrix 的 FAPI2 Message Signing 组合中保留；若 metadata/profile 变更，更新对应 FAPI2 Message Signing plan 配置和 conformance 记录。 |
| NI-002 RFC 8628 Device Authorization Grant | 未发现 RFC 8628 AS-side 官方 plan；仅发现 metadata 字段和 CIBA/client 条件复用错误码。 | 不新增 OIDF 矩阵；保留 `docs/conformance/2026-07-01-ni-002-oidf-coverage.md` 和本地正/负向测试。 |
| NI-003 RFC 8693 Token Exchange | 未发现 RFC 8693/token-exchange AS-side 官方 plan。 | 不新增 OIDF 矩阵；本地测试覆盖 issuer、audience/resource、scope downscope、revocation、actor-token 边界。 |
| NI-004 RFC 7591 / OIDC Dynamic Client Registration | `oidcc-dynamic-certification-test-plan` 覆盖 OIDC dynamic client registration。 | 已加入 full matrix；保留 dynamic-client 官方结果和 expected SKIPPED 说明。 |
| NI-005 RFC 7592 Dynamic Client Registration Management | 发现 Brazil DCR plans：`fapi1-advanced-final-brazil-dcr-test-plan`、`fapi2-security-profile-final-brazil-dcr-test-plan`、`fapi2-security-profile-id2-brazil-dcr-test-plan`；这些计划绑定 Brazil software statement、mTLS 和 Brazil profile。 | 当前不新增标准矩阵；除非产品明确实现 Brazil DCR profile，否则只记录 `docs/conformance/2026-07-02-ni-005-oidf-coverage.md` 并保留本地 RFC 7592 tests。 |
| NI-006 RFC 7523 third-party JWT bearer assertion trust | RFC 7523 client authentication 负向场景已由 OIDC/FAPI plans 覆盖；未发现第三方 assertion issuer trust 专项 plan。 | 不新增矩阵；若实现外部 issuer trust，新增本地 issuer allowlist/subject mapping/replay tests，并记录未发现官方 plan。 |
| NI-007 OpenID Connect CIBA / FAPI CIBA | `fapi-ciba-id1-test-plan` 覆盖 FAPI-CIBA AS；另有 RP/client alpha plan。 | 已加入 full matrix 并在 2026-07-02 Hostinger targeted run 执行；当前 FAPI-CIBA ID1 官方 suite 失败，需修复 backchannel authentication 正向请求和错误映射后再作为通过证据。 |
| NI-008 OpenID Connect Front-Channel Logout | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` 覆盖 OP front-channel logout + RP-initiated logout 组合。 | 已加入 full matrix；2026-07-02 Hostinger isolated run 通过，同时保留本地 iframe/redirect escaping tests。 |
| NI-009 OpenID Connect Session Management | `oidcc-session-management-certification-test-plan` 覆盖 OP session management。 | 已加入 full matrix；2026-07-02 Hostinger targeted run 通过，同时保留本地 `session_state` 和 iframe status tests。 |
| NI-010 OpenID Connect Federation 1.0 | 发现 federation entity / OP / RP alpha plans：`openid-federation-deployed-entity-test-plan`、`openid-federation-entity-joined-to-test-federation-op-test-plan`、`openid-federation-entity-joined-to-test-federation-rp-test-plan`。 | 当前只实现 entity statement；只能新增 deployed entity/entity statement 相关 alpha matrix，完整 joined-to-test-federation OP/RP matrix 需等 trust chain/metadata policy 实现后再加入。 |
| NI-011 OpenID Connect Native SSO | 未发现 Native SSO / `device_secret` 官方 plan。 | 不新增 OIDF 矩阵；保留本地 device_secret lifecycle、`ds_hash` binding、token exchange、refresh-family activity tests。 |
| NI-012 UserInfo signing/encryption | OIDC dynamic/basic modules 覆盖 signed UserInfo；suite 有 UserInfo encryption 条件和 client tests，但未发现独立 OP encryption certification plan。 | 若只支持 signed UserInfo，补 OIDC dynamic/static 组合即可；若支持 encrypted UserInfo，先确认官方 OP plan 是否新增，否则记录缺口并补本地 JWE tests。 |
| NI-013 JARM/JWE encrypted authorization responses | FAPI2 Message Signing plans 覆盖 JARM；suite 有 authorization response encryption 条件。 | 实现 encrypted authorization response 时新增或扩展 FAPI2 Message Signing JARM/JWE 组合，确保 metadata 与实际 JWE 支持一致。 |
| NI-014 FAPI 2.0 HTTP Signatures draft | 未发现 FAPI HTTP Signatures 官方 AS/RS plan。 | 不新增矩阵；实现前等待官方 plan 或目标生态要求，并补 canonicalization/signature 本地与资源服务器 E2E。 |
| NI-015 RFC 9865 / RFC 9967 SCIM or SCIM Security Events | 未发现 RFC 9865 cursor pagination 或 SCIM async server plan；suite 有 Shared Signals Framework transmitter/receiver plans，并包含 RFC 9967 SCIM event type 常量。 | 纯 SCIM cursor/async 不新增 OIDF 矩阵；若实现 SCIM Security Events/SSF transmitter，新增 `openid-ssf-transmitter-test-plan` 或 receiver plan。 |

## 外部边界任务

这些 `[x]` 表示后端边界已经归档，不表示外部基础设施由本仓库实现。

- [x] **EX-001 TLS / HSTS / RFC 9325 / RFC 8996**
  - 状态：外部边界
  - 后端责任：README 不把 RFC 8996 写成实现项；部署文档记录 TLS 1.2+/TLS 1.3、HSTS、reverse proxy trust boundary。
- [x] **EX-002 mTLS 证书转发**
  - 状态：外部边界
  - 后端责任：代码只信任 trusted proxy CIDR 内的证书 header；部署文档必须说明代理侧证书验证责任。
- [x] **EX-003 Resource server DPoP replay store**
  - 状态：外部边界
  - 后端责任：内置 verifier 的 process-local replay cache 不等于集群共享防重放；文档要求共享 replay store 或确定性路由。
- [x] **EX-004 Native app claimed HTTPS / OS binding**
  - 状态：外部边界
  - 后端责任：AS 只校验 redirect URI 注册和 RFC 8252 形态；OS/app-claiming 由客户端平台完成。
- [x] **EX-005 Browser token storage**
  - 状态：外部边界 / 产品边界
  - 后端责任：后端应偏向 BFF/same-site session；如支持纯 SPA，必须在 profile 和测试中明确 token storage、CORS、refresh-token 风险控制。

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

### Phase 2：收口 FAPI Message Signing

状态：完成当前范围。目标是让 FAPI 2.0 Message Signing 的三个选项各自独立 gating：signed request object、JARM、signed introspection。

已完成：

- RFC 9701 signed introspection response。
- RFC 9701 JWE introspection response，按 resource-server client metadata 返回 signed-then-encrypted nested JWT。
- `Accept: application/token-introspection+jwt` content negotiation。
- `iss`、`aud`、resource-server identity、active signing key 和 token introspection body 绑定。
- Metadata 只在 `fapi2-message-signing-introspection` profile 下广告，JWE alg/enc 只声明已实现的 `RSA-OAEP-256` / `A256GCM`。
- 测试覆盖 discovery gating、JWT media type、issuer/audience、top-level token-claim confusion 防护，以及 active access token introspection。
- 测试覆盖 JWE response metadata 校验、加密 JWK 校验，以及 nested JWT 解密后的 introspection payload。

保留边界：

- OAuth error response 仍为 JSON。
- OIDF/FAPI 官方矩阵可覆盖 signed introspection profile 时，再把结果加入认证证据。

### Phase 3：高风险扩展能力的产品决策

这些不是“越多越好”的 RFC 收集项。每项开工前必须有 threat model 和 profile decision。

候选任务：

- RFC 7523 third-party JWT bearer assertion trust。
- RFC 8628 Device Authorization Grant 已完成默认关闭实现；后续只做 UX、审计、限速观测和官方 OIDF 覆盖补充。
- RFC 8693 Token Exchange 的外部 token、refresh-token、ID-token 和跨 issuer profile。
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
8. RFC 9701 signed introspection profile regression。

这个顺序优先验证已经对外声明或已经实现的高风险能力，再考虑新增协议功能。

## 更新规则

当任何任务状态变化时，必须同步更新：

- `docs/rfc-compliance-matrix.md`
- `docs/oauth-best-practice-implementation-plan.zh-CN.md`
- `docs/profile-matrix.md`
- `README.md`
- `README.zh-CN.md`
- 对应 conformance 记录或本地测试证据

每新增一个 RFC、OIDC/FAPI profile 或标准协议能力支持时，必须额外执行 OIDF 一致性套件覆盖检查：

- 检索 OpenID Foundation Conformance Suite 的官方 production/staging 计划、公开源代码和 release notes，确认是否已有对应官方测试。
- 如果 OIDF 已有对应官方测试、计划或矩阵，必须在同一变更中更新本仓库的 OIDF 执行内容，例如 `.github/workflows/oidf-conformance-full.yml`、`scripts/run_oidf_conformance.py` 输入、`docs/conformance/oidf-full-matrix*.md`、`docs/conformance/oidf-plan-config-template.json` 或对应 plan 列表，使新增官方覆盖被实际执行并归档。
- 如果 OIDF 暂无对应官方测试，必须在任务证据或 conformance 记录中写明检索结论和日期；仍必须保留本地正向、负向、安全边界和 metadata truth 测试。
- OIDF 官方套件覆盖是额外证据，不替代本地测试。

不得只改 README 或 discovery metadata 而不补实现与测试。
