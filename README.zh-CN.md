<div align="center">
  <h1>NazoAuth</h1>
  <p>使用 Rust 构建的 OAuth 2.0 与 OpenID Connect 服务。</p>
  <p>
    <a href="https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml"><img src="https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main" alt="代码质量"></a>
    <a href="https://github.com/nazozero/NazoAuth/releases"><img src="https://img.shields.io/github/v/release/nazozero/NazoAuth?label=release" alt="发布版本"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-2563eb" alt="AGPL-3.0-or-later"></a>
  </p>
  <p>
    <a href="docs/operations/one-click-update.zh-CN.md">部署</a> ·
    <a href="#openid-certified">OIDF 认证</a> ·
    <a href="docs/integration/openid-connect.zh-CN.md">接入应用</a> ·
    <a href="docs/protocol/rfc-compliance-matrix.md">协议状态</a> ·
    <a href="README.md">English</a>
  </p>
</div>

在自己的基础设施上管理登录、令牌签发和应用授权。NazoAuth 支持通行密钥、MFA、
租户路由和外部身份提供方。协议与业务核心通过存储接口访问持久化状态和短期状态，
具体存储由适配器实现。

> [!WARNING]
> **0.5.0 之前，本项目快速迭代，版本更新不做任何历史兼容。**
> 配置、持久化状态、管理接口和控制消息均以当前格式为准。
> 升级前备份，并按目标版本的要求准备部署；项目不维护旧格式读取、转换或兼容层。

## OpenID Certified

<p align="center">
  <a href="https://openid.net/certification/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png" width="180" alt="OpenID Certified — Nazo Auth Server 0.2.0"></a>
</p>

OpenID Foundation 的公开认证目录收录了 **NazoAuth / Nazo Auth Server 0.2.0**，
覆盖下列 **29 个 conformance profile**。表中链接均指向官方登记页，可查看认证及测试结果记录。

| 认证 | 已认证的 profile | 登记日期 |
| --- | --- | --- |
| [OpenID Provider](https://openid.net/certification/certified-openid-providers-profiles/) | `Basic OP` · `Config OP` · `Form Post OP` · `3rd Party-Init OP` | 2026-07-29 |
| [OpenID Connect Logout](https://openid.net/certification/certified-openid-providers-for-logout-profiles/) | `RP-Initiated OP` · `Session OP` · `Front-Channel OP` · `Back-Channel OP` | 2026-07-29 |
| [FAPI 2.0 Security Profile Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2SP OP MTLS + MTLS`<br>`FAPI2SP OP MTLS + DPoP`<br>`FAPI2SP OP private key + MTLS`<br>`FAPI2SP OP private key + DPoP`<br>`FAPI2SP OP OpenID Connect` | 2026-07-29 |
| [FAPI 2.0 Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2MS OP JAR` · `FAPI2MS OP JARM` | 2026-07-29 |
| [FAPI 2.0 Client Credentials](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) | `FAPI2SP OP Client Credentials MTLS + MTLS`<br>`FAPI2SP OP Client Credentials MTLS + DPoP`<br>`FAPI2SP OP Client Credentials private key + MTLS`<br>`FAPI2SP OP Client Credentials private key + DPoP` | 2026-07-29 |
| [FAPI-CIBA](https://openid.net/certification/certified-fapi-ciba-openid-providers-profiles/) | `FAPI-CIBA OP Poll w/ MTLS`<br>`FAPI-CIBA OP Poll w/ Private Key`<br>`FAPI-CIBA OP Ping w/ MTLS`<br>`FAPI-CIBA OP Ping w/ Private Key` | 2026-07-29 |
| [**OID4VCI 1.0 + HAIP 1.0**](https://openid.net/certification/certified-oid4vci-haip-final/) | `OID4VCI-1.0+HAIP-1.0 Issuer sd_jwt_vc issuer_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer sd_jwt_vc wallet_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer mdoc issuer_initiated`<br>`OID4VCI-1.0+HAIP-1.0 Issuer mdoc wallet_initiated` | 2026-08-21 |
| [**OID4VP 1.0 + HAIP 1.0**](https://openid.net/certification/certified-oid4vp-haip-final/) | `OID4VP-1.0+HAIP-1.0 Verifier sd_jwt_vc direct_post.jwt`<br>`OID4VP-1.0+HAIP-1.0 Verifier iso_mdl direct_post.jwt` | 2026-08-23 |

OID4VCI、OID4VP 登记页中的实现版本写作 `v0.2.0`。上方认证标识与范围对应这些已登记的实现。

## 能力

| 领域 | 支持内容 |
| --- | --- |
| 应用授权 | Authorization Code + PKCE、客户端凭据、刷新令牌轮换、令牌内省与撤销、设备授权、CIBA poll/ping |
| 请求与令牌保护 | PAR、JAR、JARM、DPoP、mTLS、客户端独立安全策略、FAPI 2.0 控制 |
| 身份认证 | 密码、通行密钥、TOTP MFA、外部 OIDC、QQ/微信适配器、受信 SAML 网关 |
| 多租户 | 按 Host 选择 issuer，隔离服务图、签名密钥、客户端、会话和存储 |
| 身份管理 | 账号资料、客户端与授权管理、SCIM 用户供应、安全事件 |
| 数字凭据 | OpenID4VCI 签发与 OpenID4VP 出示，按部署配置凭据类型及信任材料 |

服务公布某项能力，不等于每个客户端都能使用它。
[能力策略](docs/protocol/composable-capability-policy.md)列出了默认值、启用条件和客户端控制。
Implicit、Hybrid、密码授权、未签名 Request Object 和 CIBA push 不受支持。

## 部署

使用 [NazoAuthCtl](https://github.com/nazozero/NazoAuthCtl) 在本机或 SSH 主机上安装并管理正式版本。
运行方式可选 Docker、Podman 或宿主机二进制。当前发行版使用 PostgreSQL、Valkey 适配器，
部署前需要准备公网 HTTPS issuer、具有独立 runtime/lifecycle 角色的 PostgreSQL，以及 Valkey。

<details>
<summary><strong>在 SSH 主机上安装</strong></summary>

先在两端安装 NazoAuthCtl，远端 helper 必须与控制端构建一致。
使用已有的 OpenSSH 别名，并将示例中的 release tag 替换为目标签名版本。

~~~sh
nazoauthctl host add production-host --ssh production --privilege sudo

nazoauthctl install \
  --host production-host --name production \
  --to '<nazoauth-release-tag>' \
  --runtime podman --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name nazoauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password

nazoauthctl admin create --instance production
~~~

登录 https://auth.example.com/ui/auth 并完成 MFA 绑定，再使用该管理员账号绑定控制端：

~~~sh
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl verify --instance production
~~~

离线保管恢复密钥。创建首个管理员使用目标机的本地部署权限；
控制端绑定则需要该管理员和新的 MFA 授权。

</details>

[安装指南](docs/operations/one-click-update.zh-CN.md)包含完整流程、备份验证、更新和恢复。
[TLS 与部署](docs/operations/deployment.zh-CN.md)说明了反向代理和健康检查。
外部 PostgreSQL、Valkey 由部署方管理。

## 接入应用

从 issuer 的 Discovery 文档开始：

~~~text
https://auth.example.com/.well-known/openid-configuration
~~~

注册客户端及其精确回调地址，使用 Authorization Code 和 S256 PKCE。
[OIDC 接入指南](docs/integration/openid-connect.zh-CN.md)覆盖客户端注册、发现、授权、令牌和退出登录。

每个客户端保存独立的安全策略。按应用需要授权 grant 和令牌保护方式；
启用服务端模块不会向所有客户端开放访问权限。

## 服务结构

一个可执行程序组合协议核心、身份服务和适配器。核心依赖表达业务语义的持久化与状态接口；
适配器实现这些契约，并负责驱动调用、事务和存储机制。

~~~mermaid
flowchart TB
    Core["协议与身份核心"] --> Ports["持久化与状态接口"]
    PG["PostgreSQL 适配器"] -. 持久化 .-> Ports
    VK["Valkey 适配器"] -. 短期状态 .-> Ports
~~~

PostgreSQL、Valkey 是目前已经实现的适配器，并非核心架构必须依赖的存储。
入口程序负责选择和装配它们，协议与业务 crate 不依赖对应驱动。
头像存储另有本地和 S3 兼容适配器。

请求进入业务处理前，先完成租户选择。每个活跃租户拥有独立服务图和签名密钥生命周期。
Host 路由读取进程内的不可变索引，未知 Host 会被拒绝。
具体边界见[架构](docs/project/architecture.md)与[租户模型](docs/features/tenancy.md)。

## 开发与验证

使用仓库固定的 Rust 工具链。涉及 PostgreSQL、Valkey 和对象存储的测试，需要准备
[质量工作流](.github/workflows/code-quality.yml)中定义的隔离服务与测试配置。

~~~sh
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
~~~

[测试说明](docs/project/testing.md)列出了检查项与外部测试环境。
[一致性验证记录](docs/conformance/README.md)注明了项目回归验证对应的制品与条件。
正式认证的 profile 与登记日期见上方 [OpenID Certified](#openid-certified)。

## 文档

| 接入与开发 | 部署与运维 |
| --- | --- |
| [OIDC 接入](docs/integration/openid-connect.zh-CN.md) | [配置](docs/operations/configuration.md) |
| [通行密钥](docs/features/passkeys.md) · [MFA](docs/features/mfa.md) | [部署与 TLS](docs/operations/deployment.zh-CN.md) |
| [身份联邦](docs/features/federation.md) | [高可用](docs/operations/ha-operations.md) |
| [SCIM](docs/features/scim.md) | [安全模型](docs/security/threat-model.md) |
| [协议覆盖](docs/protocol/rfc-compliance-matrix.md) | [性能测量](docs/performance/README.md) |

漏洞报告见 [SECURITY.md](SECURITY.md)，贡献规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

项目使用 [AGPL-3.0-or-later](LICENSE) 许可证。[商业许可](COMMERCIAL-LICENSE.md)须另行签署协议。
