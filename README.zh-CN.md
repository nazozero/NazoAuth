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

[English](README.md)

**链接：** [文档](#文档) · [快速启动](#快速启动) · [配置](#配置) ·
[认证和 conformance](#认证和-conformance) · [部署](docs/deployment.zh-CN.md) ·
[安全策略](SECURITY.md)

Nazo Auth Server 是一个用 Rust 写的自托管 OAuth 2.1 / OpenID Connect 授权服务器。它负责授权、发 token、discovery、JWKS、UserInfo、会话和管理 API，适合部署成小型生产身份服务。

项目按协议 profile 明确划边界。基础 OAuth/OIDC 可以跑兼容路径；FAPI2 profile 会要求 PAR、PKCE、confidential client、必要时的签名 request object，以及 DPoP 或 mTLS sender constraint。

## 目录

- [概览](#概览)
- [包含什么](#包含什么)
- [默认不包含什么](#默认不包含什么)
- [标准和 profile](#标准和-profile)
- [快速启动](#快速启动)
- [配置](#配置)
- [端点](#端点)
- [密钥](#密钥)
- [认证和 conformance](#认证和-conformance)
- [开发检查](#开发检查)
- [OpenID Foundation suite](#openid-foundation-suite)
- [部署](#部署)
- [文档](#文档)
- [许可证](#许可证)

## 概览

| 项目 | 值 |
| --- | --- |
| 包名 | `nazo-oauth-server` |
| 语言 | Rust 2024 |
| 许可证 | AGPL-3.0-or-later |
| 状态 | 授权服务器，包含本地 identity/admin API |
| 运行依赖 | PostgreSQL、Valkey |
| 已认证公开 issuer | `https://auth.nazo.run` |
| 主分支 | `main` |

## 包含什么

- Authorization code flow + S256 PKCE。
- Token、refresh、revocation、introspection、UserInfo、JWKS、discovery endpoint。
- PAR 和 signed request object。
- `client_secret_basic`、兼容性 `client_secret_post`、`private_key_jwt`、public client、mTLS client authentication。
- DPoP 和 mTLS sender-constrained access token。
- 兼容 profile 下的 refresh-token rotation 和 token-family reuse detection。
- OIDC RP-Initiated Logout 和 back-channel logout notification。
- Pairwise subject identifier。
- RFC 8707 `resource` 参数。
- 显式开关控制的 RFC 9396 风格 `authorization_details`。
- Cookie session、CSRF、防护响应头、rate limit、结构化审计事件。
- 用户、资料、头像、OAuth client、授权记录、MFA、passkey、federation、SCIM、access request API。
- Rust resource-server verifier core，并提供 Actix Web、Axum/Tower、tonic adapter。
- 本地签名密钥生命周期管理，也支持 external-command signer 连接 KMS/HSM。

## 默认不包含什么

这些能力默认不对外声明。启用前需要单独的 threat model 和验收测试：

- Dynamic Client Registration / RFC 7591。
- Client Configuration Management / RFC 7592。
- Device Authorization Grant。
- Token Exchange / RFC 8693。
- 请求级多 issuer tenant routing。
- Signed introspection response。

当前范围见 [docs/roadmap.md](docs/roadmap.md) 和
[docs/ecosystem-onboarding.md](docs/ecosystem-onboarding.md)。

## 标准和 profile

当前 authorization-server profile 由 `AUTHORIZATION_SERVER_PROFILE` 选择。
Discovery metadata 根据当前 profile 和部署配置生成，不是静态文件。

IETF / RFC 相关实现：

| 标准 | 状态 |
| --- | --- |
| OAuth 2.0 Authorization Framework / [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | authorization code、refresh token、client credentials grant |
| Bearer Token Usage / [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | bearer access token 处理 |
| PKCE / [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | authorization code client 使用 S256 PKCE |
| Token Revocation / [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | `/revoke` endpoint |
| Token Introspection / [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | `/introspect` endpoint |
| OAuth 2.0 Authorization Server Metadata / [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | `/.well-known/oauth-authorization-server` |
| JWT Profile for Client Authentication / [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | `private_key_jwt` client authentication |
| OAuth 2.0 mTLS / [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) | mTLS client auth 和 sender-constrained access token |
| Resource Indicators / [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | `resource` request parameter 和 JWT `aud` 绑定 |
| JWT-Secured Authorization Request / [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) | 启用后支持 signed request object |
| Pushed Authorization Requests / [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | `/par` endpoint |
| JWT Profile for Access Tokens / [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | 面向 resource server 的 JWT access token 形态 |
| DPoP / [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP proof 校验和 sender-constrained token |
| Rich Authorization Requests / [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | 由 `ENABLE_AUTHORIZATION_DETAILS` 控制 |
| OAuth 2.1 draft 方向 | OAuth 2.1 风格默认值；兼容例外会显式写明 |

OpenID Foundation 相关实现：

| 规格 | 状态 |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token、UserInfo、claims 和标准 OIDC authorization flow |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout` endpoint |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | best-effort back-channel logout notification |
| [JWT Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html) | active profile 声明时支持 JARM |
| [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-2_0-security-profile-final.html) | FAPI2 部署 profile |
| [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-2_0-message-signing-final.html) | signed authorization request 和 JARM profile support |

认证：

| 项目 | 证据 |
| --- | --- |
| [OpenID Connect Certified](https://openid.net/certification/#OPs) | 以 `Nazo Auth Server 0.1.0` 列入认证列表，日期 `09-Jun-2026` |
| OpenID Provider certification plans | OIDC Basic OP 和 OIDC Config OP 记录保存在 [docs/conformance](docs/conformance) |
| FAPI 2.0 certification plans | FAPI2 Security Profile Final 和 FAPI2 Message Signing Final 记录保存在 [docs/conformance](docs/conformance) |

其他协议能力：

| 标准 | 状态 |
| --- | --- |
| SCIM 2.0 / [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643)、[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) | 默认 tenant 的 user provisioning API |
| WebAuthn | passkey 注册和登录流程 |

## 快速启动

需要：

- 兼容 Rust 2024 edition 的 Rust toolchain
- PostgreSQL 18 或兼容版本
- Valkey 8 或兼容 Redis protocol 的服务
- Docker 或 Podman

创建本地配置：

```sh
cp .env.yaml.example .env.yaml
```

启动本地集成环境：

```sh
docker compose up -d nazo_oauth_server
```

检查服务：

```sh
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

如果直接在宿主机运行，先把 `.env.yaml` 里的 `DATABASE_URL` 和 `VALKEY_URL`
指向可访问的服务，然后执行：

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## 配置

配置加载顺序：

```text
defaults < .env.yaml < process environment variables
```

只接受 allowlist 里的环境变量。不支持 `.env`；如果仓库里存在 `.env`，服务会拒绝启动。

默认部署是同域模式。只配置一次 `PUBLIC_BASE_URL`，服务会从它派生 issuer、UI URL、passkey origin、CORS origin 和持久化子目录。

最小配置：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP 监听地址 |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | 公开同域 base URL |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL 连接串 |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey 连接串 |
| `DATA_DIR` | `runtime` | 持久化文件根目录 |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | `oauth2-baseline`、`fapi2-security` 或 `fapi2-message-signing-authz-request` |
| `RUST_LOG` | `info` | tracing filter |

派生默认值：

| 值 | 规则 |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | `PUBLIC_BASE_URL` 的 origin |
| `PASSKEY_ORIGIN` / `PASSKEY_RP_ID` | 从 issuer 派生 |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

见 [.env.yaml.example](.env.yaml.example) 和
[docs/configuration.md](docs/configuration.md)。

## 端点

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/authorize` | Authorization endpoint |
| `GET` | `/authorize/consent` | Consent page data |
| `POST` | `/authorize/decision` | Consent decision |
| `POST` | `/par` | Pushed Authorization Request |
| `POST` | `/token` | Token endpoint |
| `GET`/`POST` | `/logout` | OIDC RP-Initiated Logout |
| `POST` | `/revoke` | Token revocation |
| `POST` | `/introspect` | Token introspection |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth server metadata |
| `GET` | `/jwks.json` | JWKS |
| `GET` | `/userinfo` | OIDC UserInfo |

Token endpoint 使用 RFC 8707 `resource` 作为标准 audience 输入。旧的
`audience` 参数默认拒绝，只有 `ENABLE_LEGACY_AUDIENCE_PARAM=true` 时才接受。

## 密钥

如果 `keyset.json` 不存在，启动时会创建本地 RS256 签名密钥。密钥生命周期包含 prepublished、active、grace 和 retired 状态。超过相关 token 最大生命周期后，retired key 会从 JWKS 中移除。

校验 keyset：

```sh
nazo-oauth-keyctl validate
```

注册外部密钥时只保存 public JWK 和 provider reference：

```sh
nazo-oauth-keyctl register-external \
  --kid rs256-kms-2026-06 \
  --alg RS256 \
  --key-ref kms://prod/oauth/rs256-kms-2026-06 \
  --public-jwk /secure/exported-public-jwk.json
nazo-oauth-keyctl validate
```

配置 `SIGNING_EXTERNAL_COMMAND` 后，服务会把 signing input 通过 stdin 发给命令，并用 active public JWK 校验返回的签名，再返回 token。

## 认证和 conformance

Nazo Auth Server 已列入 OpenID Foundation 认证列表，认证部署名为
`Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`：

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

GitHub Actions artifact 会过期，所以长期证据保存在 [docs/conformance](docs/conformance)：

- [2026-06-09 OIDF full matrix](docs/conformance/2026-06-09-oidf-full-matrix.md)
- [2026-06-26 security findings OIDF full matrix](docs/conformance/2026-06-26-security-findings-full-matrix.md)
- [2026-06-27 PR 15 official OIDF full matrix](docs/conformance/2026-06-27-pr15-official-oidf-full-matrix.md)

最新官方 full matrix 针对 runtime commit
`be7ef9f6a9197520235a59d42866a0918a293014` 和 `https://auth.nazo.run` 执行，导出全部 16 个 plan archives，结果为 `0 failures`、`0 warnings`。

Baseline OIDC metadata 会声明 `none`，用于 unsigned Request Object 兼容路径。FAPI2、PAR request-object、signed-authorization-request 和 holder-bound-token 路径仍会拒绝 unsigned Request Object。

## 开发检查

常用本地检查：

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

本地 Rust coverage：

```sh
cargo install cargo-llvm-cov
python -m pip install requests "psycopg[binary]" redis argon2-cffi pyjwt cryptography aiosmtpd
bash scripts/generate_codecov_lcov.sh
```

Windows 上建议使用 [docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md)，让 PostgreSQL、Valkey、Python 和 llvm-cov 在同一个可复现环境里运行。

## OpenID Foundation suite

完整 suite workflow 位于
[.github/workflows/oidf-conformance-full.yml](.github/workflows/oidf-conformance-full.yml)。它会对公开 HTTPS 部署运行 OpenID Foundation Conformance Suite，并导出每个 plan 的结果归档。

需要的 GitHub secret：

- `OIDF_CONFORMANCE_TOKEN`

Plan config 可以通过 `OIDF_PLAN_CONFIG_JSON` 提供，也可以拆成
`OIDF_PLAN_CONFIG_JSON_GZ_B64_01` 到 `OIDF_PLAN_CONFIG_JSON_GZ_B64_10`。

## 部署

生产部署至少需要：

- `PUBLIC_BASE_URL` 设置为精确的公开 HTTPS origin。
- PostgreSQL backup 和 migration rollback 方案。
- Valkey 可用性，用于短生命周期协议状态。
- 签名密钥轮换和 JWKS 预发布。
- Secure cookie。HTTPS 下会默认派生为启用。
- 配置 `TRUSTED_PROXY_CIDRS` 后才信任 forwarded IP 或 mTLS header。
- 每次部署后做 live endpoint 检查。

详细说明见 [docs/deployment.md](docs/deployment.md) 和
[docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)。

## 文档

- [安全策略](SECURITY.md)
- [配置](docs/configuration.md)
- [发布安全](docs/release-security.md)
- [Profile matrix](docs/profile-matrix.md)
- [Threat model](docs/threat-model.md)
- [Refresh-token rotation](docs/refresh-token-rotation.md)
- [Tenant, realm, and organization boundaries](docs/tenancy.md)
- [PostgreSQL and Valkey operations](docs/ha-operations.md)
- [Resource server verifier](docs/resource-server-verifier.md)
- [SCIM provisioning](docs/scim.md)
- [External identity federation](docs/federation.md)
- [WebAuthn passkeys](docs/passkeys.md)
- [MFA and step-up authentication](docs/mfa.md)
- [Change history](CHANGELOG.md)

## 许可证

AGPL-3.0-or-later。详见 [LICENSE](LICENSE)。
