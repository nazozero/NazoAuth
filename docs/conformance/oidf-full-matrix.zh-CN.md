# OIDF 完整矩阵

本文说明仓库维护的 OpenID Foundation Conformance Suite 完整矩阵。矩阵保持 16 个 plan；针对 TP/PS 的新增检查应映射到这些 plan 的覆盖范围，而不是另开一个临时矩阵。

执行入口仍然是 `runtime/oidf/oidf-plan-set.json`。`scripts/setup_local_oidf_podman.py` 会同时生成 `runtime/oidf/oidf-plan-set-manifest.json`，用于记录每个 plan 的标题、描述和覆盖重点。

## Plan 目录

| # | 标题 | 描述 |
| --- | --- | --- |
| 1 | OIDC Basic OP | 验证 public issuer 的 discovery、静态客户端注册和 OIDC 授权码互操作，包括 ID Token、UserInfo 和常见登录参数。 |
| 2 | OIDC Config OP | 验证 provider metadata 是否真实反映当前实现，避免声明未实现的 endpoint、算法或会话能力。 |
| 3 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / JARM | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证签名 Request Object、PAR、JAR/JARM、PKCE、授权码重放和 OpenID Connect 响应。 |
| 4 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / plain response | 与 JARM 计划相同的签名请求边界，但授权响应保持普通 code response，用于区分 message-signing 请求侧和响应侧行为。 |
| 5 | FAPI2 Security / mTLS client auth / DPoP / OpenID Connect / authorization code | 使用 mTLS 做客户端认证、DPoP 绑定访问令牌，验证 OIDC 授权码流程中的 PAR、PKCE、授权码重放、刷新令牌和 discovery。 |
| 6 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / client credentials | 使用 mTLS 客户端认证和 DPoP 绑定访问令牌，验证 client credentials grant、audience、token endpoint 和资源访问约束。 |
| 7 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / authorization code | 使用 mTLS 客户端认证和 DPoP sender constraint，验证非 OIDC 授权码流程的 PAR、PKCE、授权码重放和资源访问。 |
| 8 | FAPI2 Security / mTLS client auth / mTLS sender / OpenID Connect / authorization code | 同时覆盖 mTLS 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及 holder-bound 访问令牌。 |
| 9 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / client credentials | 使用 mTLS 作为客户端认证和 sender constraint，验证 client credentials grant 的证书绑定和资源访问。 |
| 10 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / authorization code | 使用 mTLS 作为客户端认证和 sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码和资源访问边界。 |
| 11 | FAPI2 Security / private_key_jwt / DPoP / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证 OIDC 授权码流程，是 PAR `request_uri`、外层参数和刷新令牌行为的主要回归 plan。 |
| 12 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / client credentials | 使用 `private_key_jwt` 和 DPoP，验证 client credentials grant 的 token endpoint、audience 和资源访问约束。 |
| 13 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / authorization code | 使用 `private_key_jwt` 和 DPoP，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |
| 14 | FAPI2 Security / private_key_jwt / mTLS sender / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及证书绑定资源访问。 |
| 15 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / client credentials | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证 client credentials grant 的证书绑定 token 和资源访问。 |
| 16 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |

## TP/PS 覆盖边界

本矩阵中与当前 TP/PS 工作直接相关的覆盖点包括：

- `OIDC Config OP` 覆盖 metadata truth，防止 discovery 暴露未实现能力。
- FAPI2 Security 和 Message Signing plans 覆盖 PAR 强制、`request_uri` 过期、`request_uri` 重用、跨客户端 `request_uri` 使用、外层授权请求参数、PKCE、redirect URI、audience 和 client assertion。
- `private_key_jwt / DPoP / OpenID Connect / authorization code` 是最贴近本次 TP/PS 改动面的单 plan；完整回归仍以 16-plan 矩阵为准。

因此，临时 targeted plan-set 只适合开发期间快速定位问题；正式回归和证据记录应引用 16-plan 完整矩阵。
