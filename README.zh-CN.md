# Nazo Auth Server

<p align="right">
  <a href="https://openid.net/certification/#OPs">
    <img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png" alt="OpenID Certified" width="140">
  </a>
</p>

[![code-quality](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/bymoye/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/bymoye/NazoAuth)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bymoye/NazoAuth/badge)](https://scorecard.dev/viewer/?uri=github.com/bymoye/NazoAuth)

[English](README.md) · [文档](#文档) · [快速启动](#快速启动) · [安全策略](SECURITY.md)

Nazo Auth Server 是一个用 Rust 写的自托管 OAuth 2.1 / OpenID Connect 授权服务器。它面向同域部署：issuer、浏览器 UI、passkey、CORS、cookie 和协议端点共享同一个公开 origin。

项目包含授权服务器、小型 identity/admin 管理面、本地签名密钥管理、WebAuthn/passkeys、MFA、外部身份联邦、SCIM，以及 Rust resource-server verifier。PostgreSQL 保存持久状态，Valkey 保存短生命周期协议状态。

## 状态

| 项目 | 值 |
| --- | --- |
| 包名 | `nazo-oauth-server` |
| 版本 | `0.1.0` |
| 许可证 | AGPL-3.0-or-later |
| 语言 | Rust 2024 |
| 运行依赖 | PostgreSQL、Valkey |
| 已认证公开 issuer | `https://auth.nazo.run` |
| 默认部署模型 | 同域 |

## 标准

Nazo Auth Server 实现并测试了现代授权服务器需要的核心标准。兼容性例外会明确写在文档里，不靠 discovery metadata 模糊带过。

IETF 和 RFC：

| 标准 | 实现 |
| --- | --- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), OAuth 2.0 | authorization code、refresh token、client credentials grant |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), Bearer Token Usage | bearer access token 处理 |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), Token Revocation | `/revoke` |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), JWT Client Authentication | `private_key_jwt` |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), PKCE | S256 PKCE |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), Token Introspection | `/introspect` |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), Authorization Server Metadata | `/.well-known/oauth-authorization-server` |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705), OAuth 2.0 mTLS | mTLS client auth 和 sender-constrained token |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), Resource Indicators | `resource` 和 JWT `aud` 绑定 |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), JWT Access Tokens | 面向 resource server 的 JWT access token |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101), JAR | 启用后支持 signed request object |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126), PAR | `/par` |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396), Rich Authorization Requests | 由 `ENABLE_AUTHORIZATION_DETAILS` 控制 |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), DPoP | proof 校验和 sender-constrained token |
| OAuth 2.1 draft 方向 | OAuth 2.1 风格默认值，兼容例外需要显式开关 |

OpenID Foundation：

| 规格 | 实现 |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token、UserInfo、claims、authorization code flow |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout` |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | best-effort logout notification |
| [JWT Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html) | active profile 声明时支持 JARM |
| [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-2_0-security-profile-final.html) | `fapi2-security` profile |
| [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-2_0-message-signing-final.html) | signed authorization request 和 JARM profile support |

其他协议能力：

| 标准 | 实现 |
| --- | --- |
| SCIM 2.0, [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) 和 [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | 默认 tenant 的 user provisioning |
| WebAuthn | passkey 注册和登录 |

## 认证

Nazo Auth Server 已列入 OpenID Foundation 认证列表，名称为
`Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

长期证据保存在 [docs/conformance](docs/conformance)。最新官方 full matrix 针对 `https://auth.nazo.run` 和 runtime commit `be7ef9f6a9197520235a59d42866a0918a293014` 执行，导出全部 16 个 plan archives，结果为 `0 failures`、`0 warnings`。

## 功能

- Authorization code + PKCE、refresh token、client credentials、revocation、introspection、discovery、JWKS、UserInfo、PAR、JAR、DPoP、mTLS。
- Runtime profile：`oauth2-baseline`、`fapi2-security`、`fapi2-message-signing-authz-request`。
- 本地用户、资料、OAuth client、grant、access request、TOTP MFA、backup code、remembered MFA、WebAuthn/passkeys、外部 OIDC/SAML federation、SCIM provisioning。
- 本地签名密钥生命周期，包含 prepublish、active、grace、retired 状态。也可以用 external-command signer 接 KMS/HSM。
- Rust resource-server verifier，提供 Actix Web、Axum/Tower、tonic adapter。
- 发布安全 workflow：CodeQL、dependency review、cargo audit、cargo deny、SBOM、Trivy image scanning、OpenSSF Scorecard、keyless signing、provenance attestation。

## 快速启动

需要：

- 兼容 Rust 2024 edition 的 Rust toolchain
- PostgreSQL 18 或兼容版本
- Valkey 8 或兼容 Redis protocol 的服务
- Docker 或 Podman

用 Docker Compose 启动：

```sh
cp .env.yaml.example .env.yaml
docker compose up -d nazo_oauth_server
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

如果直接在宿主机运行，先把 `.env.yaml` 里的 PostgreSQL 和 Valkey 地址改成可访问的服务：

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## 配置

新部署只需要少量启动配置：

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
RUST_LOG: "info"
```

`PUBLIC_BASE_URL` 派生同域默认值：

| 值 | 默认规则 |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | `PUBLIC_BASE_URL` 的 origin |
| `COOKIE_SECURE` | HTTPS issuer 下为 `true` |
| `PASSKEY_ORIGIN` 和 `PASSKEY_RP_ID` | 从 issuer 派生 |

`DATA_DIR` 派生本地持久化路径：

| 值 | 默认规则 |
| --- | --- |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

高级配置仍然保留，用于兼容旧部署和特殊环境。详见
[docs/configuration.md](docs/configuration.md)。

## 默认边界

以下能力不属于默认授权服务器表面；只有在实现、测试并显式启用后才会对外声明：

- Dynamic Client Registration / RFC 7591。
- Client Configuration Management / RFC 7592。
- Device Authorization Grant。
- Token Exchange / RFC 8693。
- 请求级动态 tenant 或 issuer routing。
- Signed introspection response。

当前范围见 [docs/roadmap.md](docs/roadmap.md)。

## 文档

| 主题 | 链接 |
| --- | --- |
| 配置 | [docs/configuration.md](docs/configuration.md) |
| 部署 | [docs/deployment.zh-CN.md](docs/deployment.zh-CN.md) |
| 英文部署文档 | [docs/deployment.md](docs/deployment.md) |
| Conformance 记录 | [docs/conformance](docs/conformance) |
| Profile matrix | [docs/profile-matrix.md](docs/profile-matrix.md) |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| 发布安全 | [docs/release-security.md](docs/release-security.md) |
| PostgreSQL 和 Valkey 运维 | [docs/ha-operations.md](docs/ha-operations.md) |
| Resource server verifier | [docs/resource-server-verifier.md](docs/resource-server-verifier.md) |
| SCIM | [docs/scim.md](docs/scim.md) |
| Federation | [docs/federation.md](docs/federation.md) |
| Passkeys | [docs/passkeys.md](docs/passkeys.md) |
| MFA | [docs/mfa.md](docs/mfa.md) |
| 安全策略 | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## 开发

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

HTTP 和并发检查：

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

Windows coverage 见
[docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md)。

## 许可证

AGPL-3.0-or-later。详见 [LICENSE](LICENSE)。
