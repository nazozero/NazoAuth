# Nazo OAuth Server

Nazo OAuth Server 是一个 lightweight self-hosted OAuth 2.1 draft-compatible / OpenID Connect authorization server，提供用户认证、授权码流程、token 签发与轮换、JWKS、userinfo、客户端管理、授权记录管理、接入申请管理和头像管理能力。

## 特性

- OAuth 2.1 authorization code + PKCE、refresh token、client credentials、PAR、JAR 流程
- OpenID Connect discovery、OAuth Authorization Server Metadata、JWKS、userinfo
- 服务端 access token / ID token keyset 支持 EdDSA、RS256、ES256、PS256；客户端 `private_key_jwt`、JAR request object 和 DPoP proof 支持 EdDSA、RS256、ES256、PS256
- `client_secret_basic`、`client_secret_post`、`private_key_jwt` 和 public client 认证
- refresh token 轮换与复用检测
- HTTPS / loopback / native redirect URI 门禁、S256 PKCE、授权码原子消费与重放撤销、DPoP proof 与一次性 nonce、敏感 token 响应 no-store
- active + previous JWKS 发布、access token 验签与 key rotation CLI
- 基于 Valkey 的登录、注册、token、PAR、introspection 和 revoke 限流
- trusted proxy 模式、pairwise subject、结构化安全审计日志和安全响应头
- 基于 Cookie 的用户会话和 CSRF 防护
- 管理端用户、客户端、授权记录和接入申请接口
- PostgreSQL 持久化与 Rust 原生数据库迁移
- Valkey 临时状态存储
- UUIDv7 主键与标识符生成

## 技术栈

| 领域 | 实现 |
| --- | --- |
| HTTP | Actix Web |
| 数据库 | PostgreSQL |
| ORM | Diesel / diesel-async |
| 缓存与临时状态 | Valkey |
| JWT | EdDSA、RS256、ES256、PS256 服务端签发与客户端 proof 验签 |
| 密码哈希 | Argon2 |
| JSON | serde / serde_json |
| ID | UUIDv7 |

## 项目结构

```text
.
├── Cargo.toml
├── Cargo.lock
├── Containerfile
├── compose.yml
├── migrations/
└── src/
    ├── bootstrap/          # 应用启动、CORS、路由注册
    ├── bin/                # 独立命令入口
    ├── db.rs               # 数据库连接池
    ├── domain/             # 领域类型、配置、数据库行模型、OAuth 载荷
    ├── http/               # HTTP handler，按端点职责拆分
    ├── main.rs             # HTTP 服务入口
    ├── schema.rs           # Diesel schema
    └── support/            # 安全、响应、Valkey、视图、仓储等共享能力
```

目录职责：

- `bootstrap` 负责应用装配，不承载业务流程。
- `http` 负责 HTTP 输入输出、鉴权入口和 handler 编排。
- `domain` 负责领域数据结构，不访问外部系统。
- `support` 放置多个 handler 共享的底层能力。
- `migrations` 保存本项目的数据库迁移。

## 二进制

| 名称 | 说明 |
| --- | --- |
| `nazo-oauth-server` | HTTP 服务 |
| `nazo-oauth-migrate` | 数据库迁移命令 |
| `nazo-oauth-keyctl` | JWT keyset 轮换命令 |

## 配置

配置优先级为 `defaults < .env.yaml < process environment variables`。环境变量只接受代码中显式白名单内的键；未知环境变量不会进入运行配置。`.env` 文件不受支持，如果 `.env` 存在，服务会拒绝启动。`.env.yaml` 可省略；此时必需配置必须由默认值或白名单环境变量满足。

`.env.yaml` 支持顶层键值形式；数组值会按逗号合并，适合 `CORS_ALLOWED_ORIGINS` 这类列表配置。仓库提供 `.env.yaml.example` 作为字段参考，真实配置文件不应提交。

`.env.yaml.example` 默认面向 `compose.yml`，因此 `DATABASE_URL` 和 `VALKEY_URL` 使用 Docker service 名称。直接在宿主机运行二进制时，应在本地 `.env.yaml` 中改为宿主机可访问的地址。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP 监听地址 |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL 连接串 |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey 连接串 |
| `VALKEY_COMMAND_TIMEOUT_MS` | `1000` | Valkey 单次命令、连接和内部命令超时，单位为毫秒；依赖不可用时敏感接口返回 `server_error` |
| `ISSUER` | `http://127.0.0.1:8000` | OAuth/OIDC issuer；生产环境必须使用 HTTPS，本地开发仅允许 loopback HTTP；不能以 `/` 结尾 |
| `FRONTEND_BASE_URL` | `http://127.0.0.1:3000` | 前端地址，用于登录和授权确认跳转；生产环境必须使用 HTTPS，本地开发仅允许 loopback HTTP |
| `CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:3000` | 允许的 CORS origin，多个值用逗号分隔；只接受 HTTPS origin 或 loopback HTTP origin |
| `DEFAULT_AUDIENCE` | `resource://default` | 默认 access token audience |
| `SESSION_COOKIE_NAME` | `nazo_oauth_session` | 会话 cookie 名 |
| `CSRF_COOKIE_NAME` | `nazo_oauth_csrf` | CSRF cookie 名 |
| `COOKIE_SECURE` | HTTPS issuer 时为 `true`，否则为 `false` | 是否给会话和 CSRF cookie 设置 `Secure` 属性；生产环境不能关闭 |
| `SESSION_TTL_SECONDS` | `28800` | 会话有效期，单位为秒 |
| `AUTH_CODE_TTL_SECONDS` | `60` | 授权码有效期，单位为秒 |
| `ACCESS_TOKEN_TTL_SECONDS` | `300` | access token 有效期，单位为秒 |
| `ID_TOKEN_TTL_SECONDS` | `600` | ID token 有效期，单位为秒 |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | refresh token 有效期，单位为秒 |
| `AVATAR_MAX_BYTES` | `2097152` | 头像最大字节数 |
| `CLIENT_DELIVERY_TTL_SECONDS` | `86400` | 客户端接入信息投递有效期，单位为秒 |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | 固定窗口限流窗口长度，单位为秒 |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | `30` | 单个连接来源在一个窗口内可调用登录、注册和验证码发送接口的最大次数 |
| `TOKEN_RATE_LIMIT_MAX_REQUESTS` | `60` | 单个连接来源在一个窗口内可调用 `/token` 的最大次数 |
| `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS` | `120` | 单个连接来源在一个窗口内可调用 `/introspect` 和 `/revoke` 的最大次数 |
| `TRUSTED_PROXY_CIDRS` | 空 | 可信反向代理 CIDR 列表，多个值用逗号分隔；默认不信任任何转发头 |
| `CLIENT_IP_HEADER_MODE` | `none` | 客户端 IP 解析模式，可选 `none`、`forwarded`、`x-forwarded-for` |
| `SUBJECT_TYPE` | `public` | OIDC subject 类型，可选 `public`、`pairwise` |
| `PAIRWISE_SUBJECT_SECRET` | 无 | pairwise subject 派生 secret；`SUBJECT_TYPE=pairwise` 时必填 |
| `PAR_TTL_SECONDS` | `90` | pushed authorization request 有效期，单位为秒 |
| `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` | `false` | 是否要求授权请求必须通过 PAR 进入 |
| `EMAIL_DELIVERY` | `disabled` | 邮件投递方式；`smtp` 启用真实 SMTP 投递，`disabled` 时 `/auth/send-code` 返回服务不可用 |
| `EMAIL_CODE_TTL_SECONDS` | `900` | 注册邮箱验证码有效期，单位为秒 |
| `EMAIL_CODE_SEND_COOLDOWN_SECONDS` | `60` | 同一邮箱验证码发送冷却时间，单位为秒 |
| `EMAIL_CODE_PEER_COOLDOWN_SECONDS` | `5` | 同一来源地址验证码发送冷却时间，单位为秒 |
| `EMAIL_SMTP_HOST` | 无 | SMTP 主机；`EMAIL_DELIVERY=smtp` 时必填 |
| `EMAIL_SMTP_PORT` | `587` | SMTP 端口 |
| `EMAIL_SMTP_TLS` | `starttls` | SMTP TLS 模式，可选 `starttls`、`implicit`、`none` |
| `EMAIL_SMTP_USERNAME` | 无 | SMTP 用户名；如需认证，应与 `EMAIL_SMTP_PASSWORD` 同时配置 |
| `EMAIL_SMTP_PASSWORD` | 无 | SMTP 密码；如需认证，应与 `EMAIL_SMTP_USERNAME` 同时配置 |
| `EMAIL_FROM` | 无 | 发件人邮箱；`EMAIL_DELIVERY=smtp` 时必填，支持 `Name <mail@example.com>` 格式 |
| `EMAIL_CODE_DEV_RESPONSE_ENABLED` | `false` | 仅 debug 构建可用；邮件成功投递后，响应包含注册验证码，便于本地开发 |
| `AVATAR_STORAGE_DIR` | `runtime/avatars` | 头像存储目录 |
| `JWK_KEYS_DIR` | `runtime/keys` | JWT keyset 存储目录 |

## 构建

```sh
cargo build --release
```

构建完成后，二进制位于：

```text
target/release/nazo-oauth-server
target/release/nazo-oauth-migrate
target/release/nazo-oauth-keyctl
```

## 数据库迁移

```sh
cargo run --bin nazo-oauth-migrate
```

迁移命令会在完成 schema migration 后执行 `nazo_oauth_cleanup_expired_security_state()`，清理已过期的 access token revocation 记录和已撤销且过期的 refresh token 记录。

## Key Rotation

生成新 key。默认生成 EdDSA；可通过 `--alg` 指定 `EdDSA`、`RS256`、`ES256` 或 `PS256`。首次启动时如不存在 keyset，服务会生成 RS256 active key，以满足 OpenID Connect Core 对 RS256 ID token 签名能力的互操作要求。

```sh
nazo-oauth-keyctl generate
nazo-oauth-keyctl generate --alg RS256
nazo-oauth-keyctl generate --alg ES256
nazo-oauth-keyctl generate --alg PS256
```

部署新私钥文件和更新后的 `keyset.json` 后，发布 `/jwks.json`，再激活新 key：

```sh
nazo-oauth-keyctl activate <kid>
```

等待最大 token TTL 后退役旧 key：

```sh
nazo-oauth-keyctl retire <old-kid> --at 2026-06-01T00:00:00Z
```

检查 keyset：

```sh
nazo-oauth-keyctl validate
```

`keyset.json` 的每个 key entry 使用 `alg` 记录签名算法；未写 `alg` 的既有条目按 `EdDSA` 读取。`keyset.json` 采用临时文件加 rename 写入；Unix 平台私钥 PEM 权限设置为 `0600`。active key 不允许退役，已退役 key 不发布到 JWKS。

## 运行服务

```sh
cargo run --bin nazo-oauth-server
```

健康检查：

```sh
curl -fsS "<server-url>/health"
```

## Docker

构建镜像：

```sh
docker build -f Containerfile -t nazo-oauth-server .
```

运行迁移：

```sh
docker run --rm \
  -v "$PWD/.env.yaml:/app/.env.yaml:ro" \
  nazo-oauth-server \
  nazo-oauth-migrate
```

运行服务：

```sh
docker run --rm \
  -p 8000:8000 \
  -v "$PWD/.env.yaml:/app/.env.yaml:ro" \
  nazo-oauth-server
```

项目提供 `compose.yml`，用于启动包含 PostgreSQL、Valkey、迁移任务和服务进程的本地集成环境。运行前应先创建 `.env.yaml`：

```sh
cp .env.yaml.example .env.yaml
```

```sh
docker compose up -d nazo_oauth_server
```

## 接口

### OAuth / OIDC

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/authorize` | OAuth 授权请求入口 |
| `GET` | `/authorize/consent` | 授权确认页数据 |
| `POST` | `/authorize/decision` | 提交授权同意或拒绝 |
| `POST` | `/par` | Pushed Authorization Request |
| `POST` | `/token` | OAuth 2.1 token 签发、刷新、client credentials |
| `POST` | `/revoke` | token 撤销 |
| `POST` | `/introspect` | token introspection |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth Authorization Server Metadata |
| `GET` | `/jwks.json` | JWKS |
| `GET` | `/userinfo` | OIDC userinfo；根据 access token scope 返回 `sub`、`profile`、`email`、`address` 和 `phone` 对应 claims |

`/token` 仅在授权范围包含 `offline_access` 且客户端启用 `refresh_token` grant 时签发和轮换 refresh token。

`private_key_jwt` 客户端必须在客户端元数据中配置公开 `jwks`。客户端 JWKS 只接受公开签名密钥，必须包含 `kid`、`alg` 和 `use=sig`；`alg` 支持 `EdDSA`、`RS256`、`ES256`、`PS256`。DPoP proof 使用同一组签名算法；若缺少或使用过期 nonce，服务端返回 `use_dpop_nonce` 并通过 `DPoP-Nonce` 响应头提供新的 nonce；DPoP token 和 DPoP-bound userinfo 成功响应也返回下一次 nonce。客户端元数据中的 `require_dpop_bound_tokens=true` 表示该客户端的授权码和 refresh token 签发路径必须形成 DPoP sender constraint；未显式要求时，普通 OIDC 授权码流程可签发 Bearer token。

PAR 使用 `POST /par` 提交授权请求参数，成功后返回一次性 `request_uri`。`/authorize` 使用 `request_uri` 时拒绝外层参数覆盖。JAR 使用 `request=<jwt>`，接受 `EdDSA`、`RS256`、`ES256`、`PS256` 签名请求对象，使用客户端 JWKS 验签，并校验 `iss`、`client_id`、`aud`、`exp`、`nbf`、`iat` 等 claims；`sub` 和 `jti` 为可选 claims，出现时必须有效，且 `jti` 出现时会写入防重放状态。

`/introspect` 只接受机密客户端认证，并按 access token audience 或客户端自身 token 归属返回 active metadata；非 active token 只返回 `{"active": false}`。public client 可调用 `/revoke` 撤销属于自身的 token，但不能读取 introspection metadata。

### 资源服务器集成模式

资源服务器可以选择两种 access token 验证模式：

| 模式 | 行为 | 适用边界 |
| --- | --- | --- |
| 在线 introspection | 每次或按短缓存周期调用 `/introspect`，服务端会检查 access token revocation 表、audience 和客户端权限；撤销可被资源服务器感知 | 需要撤销实时生效、权限变化敏感或风险较高的 API |
| 离线 JWKS 验签 | 资源服务器只读取 `/jwks.json` 验证 JWT 签名、`iss`、`aud`、`exp`、`nbf`、`scope` 和 DPoP `cnf`；不会读取 revocation 表 | 可接受 access token 在过期前保持有效的低延迟场景 |

JWT access token 是自包含凭据；离线 JWKS 验签不能感知 `/revoke`、authorization code replay revocation 或服务端黑名单状态。需要撤销实时语义时，资源服务器应使用 `/introspect` 或将离线验签缓存窗口限制在 access token TTL 内的很短周期。

### 请求示例

public PKCE client：

```text
GET /authorize?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid%20profile&code_challenge=<s256>&code_challenge_method=S256
```

Public authorization code client 必须使用 S256 PKCE。Confidential client 可以执行 OIDC Core authorization code flow；若请求携带 PKCE，服务端同样要求 `code_challenge_method=S256` 并在 token endpoint 校验 `code_verifier`。FAPI、PAR/JAR 安全 profile 和 OAuth 2.1 集成应始终发送 PKCE。

confidential `client_secret_basic` token 请求：

```sh
curl -u "confidential-client:<secret>" \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=https://client.example/callback&code_verifier=<verifier>" \
  https://issuer.example/token
```

`private_key_jwt` token 请求：

```sh
curl -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<jwt>" \
  https://issuer.example/token
```

DPoP nonce retry：先按服务端 `use_dpop_nonce` 响应读取 `DPoP-Nonce`，再用包含 `nonce` claim 的 DPoP proof 重试；成功 token 和 userinfo 响应会返回下一次 `DPoP-Nonce`。

PAR：

```sh
curl -u "confidential-client:<secret>" \
  -d "response_type=code&client_id=confidential-client&redirect_uri=https://client.example/callback&scope=openid&code_challenge=<s256>&code_challenge_method=S256" \
  https://issuer.example/par
```

JAR：客户端用已注册 JWKS 对 request object 进行 `EdDSA`、`RS256`、`ES256` 或 `PS256` 签名，然后传入 `/authorize?request=<jwt>` 或 `/par` 的 `request=<jwt>` 字段。

### 认证与当前用户

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/auth/captcha-config` | 验证码配置 |
| `POST` | `/auth/send-code` | 发送注册验证码 |
| `POST` | `/auth/register` | 用户注册 |
| `POST` | `/auth/login` | 用户登录 |
| `GET` | `/auth/csrf` | 刷新 CSRF token |
| `GET` | `/auth/me` | 当前用户信息 |
| `PATCH` | `/auth/me` | 更新当前用户资料 |
| `POST` | `/auth/me/avatar` | 上传头像 |
| `GET` | `/auth/me/avatar` | 获取头像 |
| `DELETE` | `/auth/me/avatar` | 删除头像 |
| `GET` | `/auth/me/applications` | 当前用户授权应用 |
| `GET` | `/auth/me/access-requests` | 当前用户接入申请 |
| `POST` | `/auth/me/access-requests` | 创建接入申请 |
| `GET` | `/auth/me/access-delivery` | 读取接入信息投递 |
| `POST` | `/auth/logout` | 退出登录 |

### 管理端

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/admin/users` | 用户列表 |
| `PATCH` | `/admin/users/{user_id}` | 更新用户状态或权限 |
| `GET` | `/admin/clients` | OAuth 客户端列表 |
| `POST` | `/admin/clients` | 创建 OAuth 客户端 |
| `GET` | `/admin/clients/{client_id}` | OAuth 客户端详情 |
| `PATCH` | `/admin/clients/{client_id}` | 更新 OAuth 客户端 |
| `GET` | `/admin/grants` | 授权记录列表 |
| `POST` | `/admin/grants/revoke` | 撤销授权记录 |
| `GET` | `/admin/access-requests` | 接入申请列表 |
| `POST` | `/admin/access-requests/{request_id}/approve` | 批准接入申请 |
| `POST` | `/admin/access-requests/{request_id}/reject` | 拒绝接入申请 |

## 开发检查

```sh
cargo fmt --check
cargo check
cargo clippy -- -D warnings
cargo test --locked
```

安全与协议流水线：

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

GitHub Actions 中的 `conformance-security` workflow 会运行 Rust gate、真实 HTTP E2E、压测、PAR/JAR/DPoP/JWT/JWK 负面路径、重复参数校验、并发授权码兑换和 refresh token 复用检测。

### OpenID Foundation Conformance Suite

官方 OpenID Foundation Conformance Suite 仓库为 `https://gitlab.com/openid/conformance-suite/`。本项目提供 `oidf-conformance` workflow，通过该仓库的官方 `scripts/run-test-plan.py` 执行测试计划。该 workflow 适用于对公网或具备 suite 回调能力的 HTTPS 测试环境，不替代每个 PR 都运行的本地确定性安全矩阵。

运行前需要在 GitHub Actions 中配置一次：

- GitHub Secret `OIDF_CONFORMANCE_TOKEN`：OpenID Foundation conformance suite API token。
- GitHub Secret `OIDF_PLAN_CONFIG_JSON`：传给 suite 的 plan config JSON 对象，内容应包含被测 issuer discovery URL、预注册 client、scope、client authentication、redirect URI 等 plan 所需字段。
- OP 测试的 plan config 必须包含能够命中授权端点的 `browser` 自动化规则，例如匹配 `https://oauth.nazo.run/authorize*`。该规则内的 tasks 必须按被测环境的真实页面流转覆盖登录页、授权确认页和 conformance callback 完成页；只匹配前端登录页、只匹配 consent 页，或把 callback 当作第一步，都会导致 suite 浏览器自动化在 `WAITING`、`Unexpected URL` 或 `submission_complete` 超时状态中断。涉及 `prompt=login` 的模块还需要在登录页 task 中用 suite 支持的 image placeholder 更新命令捕获登录页证据，否则模块会停留在人工 review 等待状态。
- 授权错误页截图自动化只应匹配真实 OAuth 错误页内容，不应把正常登录页、授权确认页或成功 callback 路径当作 screenshot placeholder 完成条件；否则 suite 可能在 callback finalisation 后继续执行浏览器后台任务并把模块中断为 `INTERRUPTED`。
- 可选 Repository Variable `OIDF_PLAN_SET_JSON`：conformance plan expression 字符串数组。该项不是敏感材料，应放在可见的 repository variable 中；不要放在 secret 中，否则过期值会隐藏实际运行输入并覆盖仓库内置默认集合。
- 可选 Repository Variable `OIDF_CONFORMANCE_SERVER`，默认 `https://www.certification.openid.net/`。
- 可选 Repository Variable `OIDF_CONFORMANCE_SUITE_REF`，默认 `master`。
- 可选 Repository Variable `OIDF_PLAN_EXPRESSION`：仅运行单个 plan expression；未设置 `OIDF_PLAN_SET_JSON` 且该项为空时，workflow 使用内置综合计划集合。
- 可选 Repository Variable `OIDF_EXPORT_RESULTS`，默认 `true`。
- 可选 Repository Variable `OIDF_VERBOSE`，默认 `true`。
- 可选 Repository Variable `OIDF_DISABLE_SSL_VERIFY`，默认 `false`。
- 可选 Repository Variable `OIDF_NO_PARALLEL`，默认 `true`，使官方 runner 串行执行所有计划，避免多个计划同时占用 alias 或让失败日志互相干扰。
- 可选 Repository Variable `OIDF_RUN_TIMEOUT_SECONDS`，默认 `10800`，限制官方 runner 单次执行最长时间，避免 conformance suite 或浏览器自动化步骤无限挂起。
- 可选 Repository Variable `OIDF_MONITOR_INTERVAL_SECONDS`，默认 `60`。包装脚本会按该间隔读取 conformance suite API；若当前 plan 的 module 出现 `FAILED`、`SKIPPED`、`INTERRUPTED`、`WARNING` 或未明确允许的 `REVIEW`，会终止官方 runner 并返回失败，避免等待整套计划完成后才发现首个异常。
- 被测环境的 `ISSUER` 必须与 discovery 文档一致，并且 conformance suite 可以访问授权端点、token 端点、JWKS、userinfo、PAR、introspection、revocation 等公开端点。
- OAuth client 的 redirect URI 必须与 suite plan config 生成或声明的 callback 地址一致。

`oidf-conformance` workflow 手动触发时不需要填写参数；workflow 会从 repository variables 和 secrets 自动读取配置。未设置 repository variable `OIDF_PLAN_SET_JSON` 和 `OIDF_PLAN_EXPRESSION` 时，默认综合计划集合覆盖：

- OIDC Basic OP certification plan
- OIDC Config OP certification plan
- FAPI2 Security Profile Final，`private_key_jwt` + PAR + DPoP + OpenID Connect
- FAPI2 Message Signing Final，`private_key_jwt` + signed request object/JAR + PAR + DPoP + OpenID Connect
- FAPI2 Security Profile ID2，`private_key_jwt` + PAR + DPoP + OpenID Connect
- FAPI2 Message Signing ID1，`private_key_jwt` + signed request object/JAR + PAR + DPoP + OpenID Connect

提交官方 workflow 前，应先用本地 conformance suite 对远端 HTTPS 部署跑 16-plan OIDF 矩阵。该矩阵由 `scripts/setup_local_oidf_podman.py` 生成 `runtime/oidf/oidf-plan-configs.json` 和 `runtime/oidf/oidf-plan-set.json`，覆盖：

- OIDC Basic 和 OIDC Config
- FAPI2 Message Signing Final 的 `plain_response` / `JARM`
- FAPI2 Security Profile Final 的 8 种组合：`private_key_jwt` / `mtls` client authentication，`dpop` / `mtls` sender constraint，`plain_oauth` / `openid_connect`
- FAPI2 Client Credentials 的 4 种组合：`mtls+mtls`、`mtls+dpop`、`private_key_jwt+mtls`、`private_key_jwt+dpop`

本地生成默认使用 `https://host.containers.internal:9443` 和 `https://host.containers.internal:9444`。对已经部署到远端的测试域名运行时，用环境变量覆盖 issuer；例如 `oauth-test.nazo.run` 同时承载普通和 mTLS endpoint 时：

```sh
OIDF_LOCAL_ISSUER=https://oauth-test.nazo.run \
OIDF_LOCAL_MTLS_ISSUER=https://oauth-test.nazo.run \
OIDF_LOCAL_WRITE_ENV_YAML=0 \
python3 scripts/setup_local_oidf_podman.py
```

运行矩阵：

```sh
OIDF_CONFORMANCE_TOKEN=<token> \
python3 scripts/run_oidf_conformance.py \
  --suite-dir /root/oidf-conformance-suite \
  --conformance-server https://localhost:8443 \
  --disable-ssl-verify \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --timeout-seconds 14400 \
  --monitor-interval-seconds 20 \
  --no-parallel
```

通过门槛是所有 plan 跑到完成，并且 summary 中每个 plan 都是 `0 failures, 0 warnings`。`WAITING` 和 `NOT_STARTED` 在运行中不是失败；只在出现真实 `FAILED`、`WARNING` 或 `INTERRUPTED` 时停止等待并定位根因。

最近一次本地远端证明是在 `2026-06-06 Asia/Shanghai` 对 `https://oauth-test.nazo.run` 完成 16 plans，所有计划均跑完，条件计数为 `0 failures, 0 warnings`。随后官方 OpenID Foundation Conformance Suite workflow 也完成同一 16-plan 矩阵：

- GitHub Actions run：`https://github.com/bymoye/oauth2_server/actions/runs/27057998666`
- GitHub Actions job：`https://github.com/bymoye/oauth2_server/actions/runs/27057998666/job/79865783825`
- 结果归档 artifact：`https://github.com/bymoye/oauth2_server/actions/runs/27057998666/artifacts/7453664494`
- Head commit：`26ee661653488fe5ac1e3532ad07753a7cc7f51a`
- 官方 suite：`https://www.certification.openid.net/`
- 运行时间：`2026-06-06T08:56:09Z` 至 `2026-06-06T10:35:35Z`
- workflow 结论：`success`

| # | Suite / profile | Client auth | Sender constraint | OAuth/OIDC mode | Variant / profile | 本地远端结果 | 官方结果 |
|---|---|---|---|---|---|---|---|
| 1 | OIDC Basic OP certification | static client | n/a | OpenID Connect | discovery | Passed, `0 failures`, `0 warnings` | [plan S7SHEaBMJbddQ](https://www.certification.openid.net/plan-detail.html?plan=S7SHEaBMJbddQ): 32 `FINISHED/PASSED`, 3 allowed `FINISHED/REVIEW`, `0 failures`, `0 warnings` |
| 2 | OIDC Config OP certification | n/a | n/a | OpenID Connect | server metadata | Passed, `0 failures`, `0 warnings` | [plan FZ8gYQS6wjetI](https://www.certification.openid.net/plan-detail.html?plan=FZ8gYQS6wjetI): 1 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 3 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | `openid_connect` | `JARM` | Passed, `0 failures`, `0 warnings` | [plan 9nzLuDQLPxevF](https://www.certification.openid.net/plan-detail.html?plan=9nzLuDQLPxevF): 70 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 4 | FAPI2 Message Signing Final | `private_key_jwt` | `dpop` | `openid_connect` | `plain_response` / JAR | Passed, `0 failures`, `0 warnings` | [plan qJzt888vVs0ly](https://www.certification.openid.net/plan-detail.html?plan=qJzt888vVs0ly): 70 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 5 | FAPI2 Security Profile Final | `mtls` | `dpop` | `openid_connect` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan 2K5dhrBDJICOD](https://www.certification.openid.net/plan-detail.html?plan=2K5dhrBDJICOD): 46 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 6 | FAPI2SP Client Credentials | `mtls` | `dpop` | `plain_oauth` | client credentials | Passed, `0 failures`, `0 warnings` | [plan zIl6BlByDdCPj](https://www.certification.openid.net/plan-detail.html?plan=zIl6BlByDdCPj): 9 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 7 | FAPI2 Security Profile Final | `mtls` | `dpop` | `plain_oauth` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan eEP7TEnmVxLgM](https://www.certification.openid.net/plan-detail.html?plan=eEP7TEnmVxLgM): 40 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 8 | FAPI2 Security Profile Final | `mtls` | `mtls` | `openid_connect` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan VFw5cUANQ0He9](https://www.certification.openid.net/plan-detail.html?plan=VFw5cUANQ0He9): 37 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 9 | FAPI2SP Client Credentials | `mtls` | `mtls` | `plain_oauth` | client credentials | Passed, `0 failures`, `0 warnings` | [plan hPEE1PS3oOm5G](https://www.certification.openid.net/plan-detail.html?plan=hPEE1PS3oOm5G): 5 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 10 | FAPI2 Security Profile Final | `mtls` | `mtls` | `plain_oauth` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan kbygJAtdQLGzC](https://www.certification.openid.net/plan-detail.html?plan=kbygJAtdQLGzC): 31 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 11 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | `openid_connect` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan lL4X76lBVUUCS](https://www.certification.openid.net/plan-detail.html?plan=lL4X76lBVUUCS): 56 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 12 | FAPI2SP Client Credentials | `private_key_jwt` | `dpop` | `plain_oauth` | client credentials | Passed, `0 failures`, `0 warnings` | [plan ICeD464NwHxlp](https://www.certification.openid.net/plan-detail.html?plan=ICeD464NwHxlp): 14 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 13 | FAPI2 Security Profile Final | `private_key_jwt` | `dpop` | `plain_oauth` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan Yq6G6SKJyRGGB](https://www.certification.openid.net/plan-detail.html?plan=Yq6G6SKJyRGGB): 50 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 14 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | `openid_connect` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan ZVo0f0rsK8d4i](https://www.certification.openid.net/plan-detail.html?plan=ZVo0f0rsK8d4i): 47 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 15 | FAPI2SP Client Credentials | `private_key_jwt` | `mtls` | `plain_oauth` | client credentials | Passed, `0 failures`, `0 warnings` | [plan Mmrywx7hibOts](https://www.certification.openid.net/plan-detail.html?plan=Mmrywx7hibOts): 10 `FINISHED/PASSED`, `0 failures`, `0 warnings` |
| 16 | FAPI2 Security Profile Final | `private_key_jwt` | `mtls` | `plain_oauth` | `plain_fapi` | Passed, `0 failures`, `0 warnings` | [plan bzthsVHgtLcwG](https://www.certification.openid.net/plan-detail.html?plan=bzthsVHgtLcwG): 41 `FINISHED/PASSED`, `0 failures`, `0 warnings` |

如需覆盖更多 ecosystem profile 或认证组合，应调整 `OIDF_PLAN_SET_JSON`，并提供与这些 plan 匹配的 `OIDF_PLAN_CONFIG_JSON`。例如：

```json
[
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] oidf-oidcc-plan-config.json",
  "oidcc-config-certification-test-plan oidf-oidcc-plan-config.json",
  "fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][sender_constrain=dpop][openid=openid_connect] oidf-fapi-plan-config.json",
  "fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][fapi_profile=plain_fapi][fapi_request_method=signed_non_repudiation][fapi_response_mode=plain_response][sender_constrain=dpop][openid=openid_connect] oidf-fapi-plan-config.json"
]
```

workflow 会导出 suite 结果归档作为 artifact，并在日志中打印实际传给官方 runner 的参数列表。通过该 workflow 表示项目已接入官方 conformance 测试入口；是否达到某个 OpenID Foundation 认证 profile，以对应 plan 的完整通过结果和认证流程为准。

容器构建检查：

```sh
docker build -f Containerfile -t nazo-oauth-server .
```

## 生产部署 Checklist

- HTTPS issuer，并设置 `COOKIE_SECURE=true`
- 按真实反向代理地址配置 `TRUSTED_PROXY_CIDRS` 和 `CLIENT_IP_HEADER_MODE`
- 制定 key rotation 流程并定期执行 `nazo-oauth-keyctl validate`
- PostgreSQL 备份与恢复演练
- Valkey 高可用和持久化策略
- 审计日志采集、访问控制、脱敏校验与保留周期清理
- 登录、token、PAR、introspection、revocation 限流
- 最小化 `CORS_ALLOWED_ORIGINS`
- 管理员账号加固
- 依赖扫描和镜像扫描
