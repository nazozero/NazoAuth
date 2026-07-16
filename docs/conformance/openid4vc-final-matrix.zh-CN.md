# OpenID4VC Final 一致性矩阵

NazoAuth 实现 OpenID4VCI 1.0 Final 的 **Credential Issuer** 角色和
OpenID4VP 1.0 Final 的 **Verifier** 角色；不实现、也不宣告 Wallet 角色。

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
本地密钥，并通过现有原子密钥库生成：

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

18 个有界执行组合见
[`tests/contracts/openid4vc-oidf-matrix.json`](../../tests/contracts/openid4vc-oidf-matrix.json)。
自动化只能经管理 HTTP 创建 offer 或 presentation transaction，不能读取协议状态表，
因此属于黑盒证据。

上游计划标题明确标为 **alpha**，并注明可能不完整/不正确或尚未纳入认证计划。
因此全绿只能称为“官方套件回归通过”，不能称为 OpenID Foundation 正式认证，
也不能据此使用 OpenID Certified 标志。

正式规范：

- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VC HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
