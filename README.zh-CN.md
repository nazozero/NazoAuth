# Nazo Auth Server

[![OpenID Certified](https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png)](https://openid.net/mark/)

[![code-quality](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/bymoye/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/bymoye/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/bymoye/NazoAuth)

[English](README.md)

Nazo Auth Server 是一个基于 Rust 的 OAuth 2.1 / OpenID Connect 授权服务器，面向自托管部署。项目重点是清晰的协议边界、sender-constrained token、可复现的合规测试证据，以及可直接面向生产部署的安全默认值。

当前公开部署为 `https://auth.nazo.run`，前端用户界面位于 `https://auth.nazo.run/ui/`。

## 项目概览

- 包名：`nazo-oauth-server`
- 语言：Rust 2024
- 许可证：Apache-2.0
- 运行依赖：PostgreSQL 和 Valkey
- 主分支策略：所有仓库动作在 `main` 进行
- 部署文档：[docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)
- OIDF 证据：[docs/conformance](docs/conformance)
- 安全策略：[SECURITY.md](SECURITY.md)
- 发布安全：[docs/release-security.md](docs/release-security.md)

## 官方认证

Nazo Auth Server 已发布在 OpenID Foundation 官方认证列表中。认证部署名为 `Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

仓库中保留了对应的工程证据：[2026-06-09 OIDF full matrix](docs/conformance/2026-06-09-oidf-full-matrix.md)。移除 OIDF-only 前端页面并启用 JSON-only 后端授权错误响应后，最新官方 full matrix 记录为 [2026-06-13 real public UI OIDF regression](docs/conformance/2026-06-13-real-public-ui-regression.md) 中的 workflow run `27472766776`。该 run 针对 `https://auth.nazo.run` 执行，GitHub conclusion 为 `success`，官方 runner 报告 71 个 test modules、5929 successes、`0 failures`、`0 warnings`。

## 能力范围

- OAuth authorization code + S256 PKCE。
- refresh token 轮换、token family 复用检测、授权码原子消费。
- client credentials、refresh token、revocation、introspection。
- OpenID Connect Discovery、OAuth Authorization Server Metadata、JWKS、ID Token、UserInfo。
- PAR 与 JAR，支持 `EdDSA`、`RS256`、`ES256`、`PS256` 签名请求对象。
- `client_secret_basic`、兼容性 `client_secret_post`、`private_key_jwt`、public client、mTLS client authentication。
- DPoP proof 校验、nonce 处理、sender-constrained access token、DPoP-bound UserInfo。
- 通过可信反向代理边界支持 mTLS sender-constrained access token。
- 服务端签名密钥轮换，发布 active / previous JWKS。
- pairwise subject identifier。
- Cookie session、CSRF、防护响应头、结构化审计事件。
- PostgreSQL 持久化与 Rust-native migration。
- Valkey 存储 session、授权码、PAR handle、replay prevention、rate limit 状态。
- 用户、资料、头像、OAuth client、授权记录、接入申请管理 API。
- RFC 8707 `resource` 参数，支持重复 resource indicator 映射为 JWT access token `aud` 数组。
- RFC 9396 风格 Rich Authorization Requests。
- Rust 资源服务器 JWT access-token verifier core。

## 架构

```text
.
├── Cargo.toml
├── Containerfile
├── compose.yml
├── docs/
│   ├── conformance/
│   └── deployment.zh-CN.md
├── migrations/
├── scripts/
└── src/
    ├── bootstrap/       # 应用组装和路由注册
    ├── bin/             # 运维命令
    ├── domain/          # 领域行、OAuth payload、配置类型
    ├── http/            # HTTP endpoint handler
    ├── support/         # 安全、存储、响应、协议辅助模块
    └── main.rs          # HTTP 服务入口
```

关键二进制：

| Binary | 用途 |
| --- | --- |
| `nazo-oauth-server` | HTTP 授权服务器 |
| `nazo-oauth-migrate` | 数据库迁移命令 |
| `nazo-oauth-keyctl` | JWT 签名密钥生命周期管理 |

## 本地启动

准备配置：

```sh
cp .env.yaml.example .env.yaml
```

启动本地集成栈：

```sh
docker compose up -d nazo_oauth_server
```

检查服务：

```sh
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

## 测试与验证

常用检查：

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

完整认证级验证以 OIDF Conformance Suite 为最终验收标准。官方 full matrix workflow 位于 [.github/workflows/oidf-conformance-full.yml](.github/workflows/oidf-conformance-full.yml)。

## 部署

生产部署建议放在 TLS 终止反向代理之后，使用 PostgreSQL 保存持久状态，使用 Valkey 保存短生命周期协议状态。详细说明见 [docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)。

生产关键点：

- `ISSUER` 必须精确等于公开 HTTPS issuer，例如 `https://auth.nazo.run`。
- `FRONTEND_BASE_URL` 应指向前端用户界面，例如 `https://auth.nazo.run/ui/`。
- `COOKIE_SECURE=true`。
- `TRUSTED_PROXY_CIDRS` 只允许你控制的反向代理地址。
- 生产密钥、数据库密码、SMTP 密码不得进入 Git。
- 协议端点和 discovery metadata 必须与实际运行行为一致。

## 许可证

Apache-2.0。
