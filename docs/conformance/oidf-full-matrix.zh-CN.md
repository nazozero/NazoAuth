# OIDF 完整矩阵

本文说明仓库维护的 OpenID Foundation Conformance Suite 完整矩阵。矩阵包含 25 个 plan；针对 TP/PS 的新增检查应映射到这些 plan 的覆盖范围，而不是另开一个临时矩阵。

执行入口仍然是 `runtime/oidf/oidf-plan-set.json`。`scripts/setup_local_oidf_podman.py` 会同时生成 `runtime/oidf/oidf-plan-set-manifest.json`，用于记录每个 plan 的标题、描述和覆盖重点。

最新的远端本地与官方套件持久证据见
[`2026-07-15-fapi-ciba-mtls-ping-oidf-results.md`](2026-07-15-fapi-ciba-mtls-ping-oidf-results.md)。

## Plan 目录

| # | 标题 | 描述 |
| --- | --- | --- |
| 1 | OIDC Basic OP | 验证 public issuer 的 discovery、静态客户端注册和 OIDC 授权码互操作，包括 ID Token、UserInfo 和常见登录参数。 |
| 2 | OIDC Basic OP Dynamic Registration | 验证 RFC 7591 动态客户端注册、`registration_endpoint` metadata，以及动态注册后的 OIDC 授权码互操作。 |
| 3 | OIDC Config OP | 验证 provider metadata 是否真实反映当前实现，避免声明未实现的 endpoint、算法或会话能力。 |
| 4 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / JARM | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证签名 Request Object、PAR、JAR/JARM、PKCE、授权码重放和 OpenID Connect 响应。 |
| 5 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / plain response | 与 JARM 计划相同的签名请求边界，但授权响应保持普通 code response，用于区分 message-signing 请求侧和响应侧行为。 |
| 6 | FAPI2 Security / mTLS client auth / DPoP / OpenID Connect / authorization code | 使用 mTLS 做客户端认证、DPoP 绑定访问令牌，验证 OIDC 授权码流程中的 PAR、PKCE、授权码重放、刷新令牌和 discovery。 |
| 7 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / client credentials | 使用 mTLS 客户端认证和 DPoP 绑定访问令牌，验证 client credentials grant、audience、token endpoint 和资源访问约束。 |
| 8 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / authorization code | 使用 mTLS 客户端认证和 DPoP sender constraint，验证非 OIDC 授权码流程的 PAR、PKCE、授权码重放和资源访问。 |
| 9 | FAPI2 Security / mTLS client auth / mTLS sender / OpenID Connect / authorization code | 同时覆盖 mTLS 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及 holder-bound 访问令牌。 |
| 10 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / client credentials | 使用 mTLS 作为客户端认证和 sender constraint，验证 client credentials grant 的证书绑定和资源访问。 |
| 11 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / authorization code | 使用 mTLS 作为客户端认证和 sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码和资源访问边界。 |
| 12 | FAPI2 Security / private_key_jwt / DPoP / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证 OIDC 授权码流程，是 PAR `request_uri`、外层参数和刷新令牌行为的主要回归 plan。 |
| 13 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / client credentials | 使用 `private_key_jwt` 和 DPoP，验证 client credentials grant 的 token endpoint、audience 和资源访问约束。 |
| 14 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / authorization code | 使用 `private_key_jwt` 和 DPoP，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |
| 15 | FAPI2 Security / private_key_jwt / mTLS sender / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及证书绑定资源访问。 |
| 16 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / client credentials | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证 client credentials grant 的证书绑定 token 和资源访问。 |
| 17 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |
| 18 | OIDC Front-Channel Logout OP | 验证 OP discovery 中 front-channel logout metadata、RP-initiated logout、前通道 iframe 通知、`iss`/`sid` 参数和 `post_logout_redirect_uri`。 |
| 19 | OIDC Session Management OP | 验证 `check_session_iframe` metadata、授权响应 `session_state`、RP-initiated logout 后的会话状态变化。 |
| 20 | FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI | 验证 FAPI-CIBA AS discovery、backchannel authentication endpoint、`private_key_jwt` 客户端认证、poll token exchange、错误处理、refresh token 和资源访问。 |
| 21 | FAPI-CIBA ID1 / mTLS / poll / plain FAPI | 验证 mTLS 客户端认证和证书绑定的 poll token 签发。 |
| 22 | FAPI-CIBA ID1 / private_key_jwt / ping / plain FAPI | 验证带 Bearer 鉴权、TLS 1.2 FAPI 基线并支持 TLS 1.3 的 ping 通知、token endpoint 取令牌、拒绝重定向和 401 终态处理。 |
| 23 | FAPI-CIBA ID1 / mTLS / ping / plain FAPI | 验证相同的 TLS 1.2 最低版本、支持 TLS 1.3 的 ping 生命周期与 mTLS 客户端认证、持有者绑定令牌的组合。 |
| 24 | OIDC Form Post OP | 通过浏览器流程验证成功与错误授权响应的 `response_mode=form_post`。 |
| 25 | OIDC Third-Party Initiated Login OP | 验证 `initiate_login_uri` 动态注册回读，以及非 HTTPS 元数据拒绝。 |

## TP/PS 覆盖边界

本矩阵中与当前 TP/PS 工作直接相关的覆盖点包括：

- `OIDC Basic OP Dynamic Registration` 覆盖 RFC 7591 动态客户端注册和 `registration_endpoint` metadata。
- 远程 `jwks_uri`、精确注册的外部 `request_uri`、签名 Request Object、签名 UserInfo 和展示元数据等动态注册扩展仍按现有安全边界实现；这些能力不构成 OIDF Dynamic OP 认证档案的支持声明。
- `OIDC Form Post OP` 覆盖安全 HTML form-post 响应及浏览器提交。
- `OIDC Third-Party Initiated Login OP` 覆盖 `initiate_login_uri` 注册元数据；该 OP profile 不新增 OP 侧发起端点。
- `OIDC Config OP` 覆盖 metadata truth，防止 discovery 暴露未实现能力。
- FAPI2 Security 和 Message Signing plans 覆盖 PAR 强制、`request_uri` 过期、`request_uri` 重用、跨客户端 `request_uri` 使用、外层授权请求参数、PKCE、redirect URI、audience 和 client assertion。
- `private_key_jwt / DPoP / OpenID Connect / authorization code` 是 TP/PS 改动面的主要单 plan；完整回归以 25-plan 矩阵为准。
- `OIDC Front-Channel Logout OP` 覆盖 NI-008。
- `OIDC Session Management OP` 覆盖 NI-009。
- 四个 FAPI-CIBA plans 覆盖 `private_key_jwt | mTLS` × `poll | ping` 的正交组合。FAPI-CIBA 禁止 Push，因此项目明确不实现 Push。
- NI-006 未发现 RFC 7523 third-party JWT bearer grant 专项官方 plan；现有覆盖来自 OIDC/FAPI 中的 client assertion 场景和本地 RFC 7523 tests。
- NI-010 跟踪 OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1。本项目当前不实现该 trust-chain 生态能力，且已不暴露 `/.well-known/openid-federation`，因此 Federation plans 不纳入必跑矩阵。
- NI-011 未发现 Native SSO / `device_secret` 官方 OP plan；保留本地 device-secret lifecycle、`ds_hash` 绑定、token exchange 与 refresh-family tests。

因此，临时 targeted plan-set 只适合开发期间快速定位问题；正式回归和证据记录应引用 25-plan 完整矩阵。

## 明确的“不实现”边界

OIDF `oidcc-dynamic-certification-test-plan` 明确为**不实现**，不得出现在生成的、本地的或官方的 plan set 中。官方套件的 dynamic profile discovery 检查要求同时支持 `code`、`id_token`、`token id_token` 三种 response type，以及 `authorization_code`、`implicit` 两种 grant type；证据见官方套件的 [`OIDCCCheckDiscEndpointResponseTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.java) 和 [`OIDCCCheckDiscEndpointGrantTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.java)。

实现该认证档案意味着声明并启用 implicit response；RFC 9700 第 2.1.2 节要求授权服务器 SHOULD NOT 支持 implicit grant。NazoAuth 因此坚持交互流程只使用 authorization code，并保持 discovery 如实声明。RFC 7591 动态客户端注册仍完整实现并由 `OIDC Basic OP Dynamic Registration` 覆盖；“动态注册”不等于旧的 OIDF “Dynamic OP”认证档案。

## Expected Skip 策略

当前官方 workflow 在 Basic OP 静态、动态注册与 Form Post 配置中明确允许 8 条 expected-skip 记录：

- `oidcc-idtoken-unsigned`
- `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`
- `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
- `oidcc-ensure-request-object-with-redirect-uri`

这些跳过项对应当前有意不支持的 unsigned 兼容能力：服务不声明 unsigned ID Token
和 unsigned Request Object。最后一个模块的名称比实际前置条件更宽；OIDF suite
v5.2.0 在 `request_object_signing_alg_values_supported` 不含 `none` 时会跳过它。
带 `redirect_uri` 的签名 Request Object 仍由 FAPI/JAR plans 验证。包含这些
expected skips 的 workflow run 可以作为 `0 failures`、`0 warnings` 的证据，
但不能作为 zero-SKIPPED 证据。

## Expected Warning 策略

官方套件入口当前在 CIBA ping 回调中协商 TLS 1.2，即使客户端已提供 TLS 1.3。
因此 workflow 只允许
[`oidf-official-expected-warnings.json`](../../tests/contracts/oidf-official-expected-warnings.json)
中 26 条精确的 `EnsureIncomingTls13` warning 上下文。每条记录同时绑定配置、
完整 variant、模块、block、condition 和 result；出现额外 warning 或缺少预期记录
都会让 workflow 失败。配套的“安全 TLS 1.2 或 TLS 1.3”条件通过；同一 NazoAuth
运行时与 Hostinger 本地套件可协商 TLS 1.3，并产生 0 warning。具体测量边界和
制品摘要见上述证据记录。
