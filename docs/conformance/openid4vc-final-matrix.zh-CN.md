# OpenID4VC Final 一致性矩阵

本实现提供 OpenID4VCI 1.0 Final 的 **Credential Issuer** 角色和 OpenID4VP
1.0 Final 的 **Verifier** 角色；不实现、也不宣告 Wallet 角色。

实现按职责拆分为四个协议边界：

- `nazo-digital-credentials`：DCQL、SD-JWT VC、ISO mdoc、JOSE/COSE 与信任端口；
- `nazo-openid4vci`：元数据、offer、proof 契约、即时/批量/延迟签发、nonce 与通知；
- `nazo-openid4vp`：Verifier 请求策略、事务状态和受 DCQL 约束的展示验证；
- `nazo-openid4vc-http-actix`：仅负责 HTTP transport 与管理适配。

持久化、密钥管理、主体数据和 HTTP 都是领域端口后的适配器。测试只放在
各 crate 的 `tests/` 下，静态 CI 会拒绝把测试重新放入生产 `src/`。

Issuer 支持 `dc+sd-jwt` 与 `mso_mdoc`、authorization code 与
pre-authorized code、Wallet/Issuer 发起、offer 值/引用、S256/DPoP 和
client-attestation HAIP 路径、一次性 proof nonce、JWT/key-attestation proof、
即时/批量/延迟签发、通知、签名元数据，以及 ECDH-ES/A256GCM（可选 `DEF`）
请求/响应加密。

HAIP 签发场景中的 Wallet 客户端按 authenticated PAR、S256 PKCE 与 DPoP
登记。使用 Wallet Attestation 不会自动要求 JAR Request Object。HAIP 1.0 在该
场景采用 FAPI 2.0 Security Profile；把全部 PAR 授权参数放入签名 Request Object
是独立的 FAPI 2.0 Message Signing Profile 要求。生态可以另外启用 Message
Signing，但 HAIP client-attestation profile 不会隐式启用它。

Verifier 支持两种凭证格式的 DCQL、`redirect_uri`/`x509_san_dns`/
`x509_hash`、`direct_post`/`direct_post.jwt`、URL query 与签名 request URI
（GET/POST）、每事务密钥加密响应、transaction data、SD-JWT KB-JWT 验证和
Final 版 mdoc session transcript。HAIP 固定为 `x509_hash`、签名 request URI
和 `direct_post.jwt`。

不会宣告未实现的可选机制：Wallet、Digital Credentials API transport、DID
client identifier、verifier attestation client identifier，以及无 holder binding
的 mdoc。

## 签名密钥边界

OpenID4VC 使用只允许 `credential` 与 `presentation_request` 两种用途的 ES256
仓库生成的测试密钥，并通过现有原子密钥库生成：

```text
nazo-oauth-keyctl generate-local --alg ES256 --purposes credential,presentation_request
```

持久化的 `purposes` 字段采用 fail-closed 校验。该专用密钥不会参与 OIDC 轮换，
也不能签 Access Token、ID Token、JARM、Logout Token、HTTP Message 或 Security
Event。配置的 OpenID4VC 叶证书必须与这把专用密钥精确匹配，并能链接到配置的
信任锚；否则服务拒绝启动。运维不得手工编辑 `keyset.json`。

OIDF Conformance Suite 固定到 v5.2.0 commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`，运行四个上游计划：

- `oid4vci-1_0-issuer-test-plan`
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vp-1final-verifier-test-plan`
- `oid4vp-1final-verifier-haip-test-plan`

17 个有界执行组合见
[`tests/contracts/openid4vc-oidf-matrix.json`](../../tests/contracts/openid4vc-oidf-matrix.json)。
自动化只能经管理 HTTP 创建 offer 或 presentation transaction，不能读取协议状态表，
因此属于黑盒证据。

官方套件执行按 4 个 plan 一批有界运行。这是 runner 调度边界，不是协议豁免：
17 个生成的 plan expression 仍全部针对操作者提供的同一个公网 issuer 执行；
每批只接收与本批配置文件匹配的 expected skip/warning 记录。这样可以避免
Issuer/Verifier 驱动型 `WAITING` 模块一次性压垮官方控制面 API，同时保留黑盒协议覆盖。

上游 v5.2.0 套件没有覆盖 `mso_mdoc` + `redirect_uri` client identifier prefix +
签名 request URI + `direct_post.jwt` 的模块；`mso_mdoc` 加密响应覆盖因此通过上游
支持的 x509 前缀签名请求变体执行。

HAIP issuer plan 可能在 `Check for refresh token` 块中产生上游
`FAPIEnsureServerConfigurationDoesNotSupportRefreshToken` advisory。套件文本明确说明：
如果授权服务器整体声明支持 refresh token，但按策略只向部分客户端签发 refresh token，
该情况可以接受。因此矩阵只允许 4 条精确 warning：4 个 HAIP issuer 执行组合、
该模块、该 block、该 condition。由于官方 runner 在该可接受 warning 后会把模块
终态标记为 `SKIPPED`，同样的 4 个上下文也登记为 expected skip。任何其他 warning
或 skip 仍视为失败。

上游计划标题明确标为 **alpha**，并注明可能不完整/不正确或尚未纳入认证计划。
因此全绿只能称为“官方套件回归通过”，不能称为 OpenID Foundation 正式认证，
也不能据此使用 OpenID Certified 标志。

最新长期证据：

- [2026-07-16 OpenID4VC Final / HAIP OIDF results](2026-07-16-openid4vc-final-oidf-results.md)
- official-suite 调试运行使用操作者提供的生产目标；公开仓库中脱敏为
  `https://issuer.example`。17 个 plan 执行全部完成，`0 failures`。它是调试证据，
  不是仓库用户的默认测试目标。
- GitHub 官方运行
  [#29530484889](https://github.com/nazozero/NazoAuth/actions/runs/29530484889)
  针对同一生产 origin 成功完成。

正式规范：

- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VC HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)
