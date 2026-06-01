# Nazo OAuth Server

Nazo OAuth Server 是一个 lightweight self-hosted OAuth 2.1 draft-compatible / OpenID Connect authorization server，提供用户认证、授权码流程、token 签发与轮换、JWKS、userinfo、客户端管理、授权记录管理、接入申请管理和头像管理能力。

## 特性

- OAuth 2.1 authorization code + PKCE、refresh token、client credentials、PAR、JAR 流程
- OpenID Connect discovery、OAuth Authorization Server Metadata、JWKS、userinfo
- Ed25519 JWT 签名
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
| JWT | Ed25519 |
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
| `nazo-oauth-keyctl` | Ed25519 keyset 轮换命令 |

## 配置

配置优先级为 `defaults < .env.yaml < process environment variables`。环境变量只接受代码中显式白名单内的键；未知环境变量不会进入运行配置。`.env` 文件不受支持，如果 `.env` 存在，服务会拒绝启动。`.env.yaml` 可省略；此时必需配置必须由默认值或白名单环境变量满足。

`.env.yaml` 支持顶层键值形式；数组值会按逗号合并，适合 `CORS_ALLOWED_ORIGINS` 这类列表配置。仓库提供 `.env.yaml.example` 作为字段参考，真实配置文件不应提交。

`.env.yaml.example` 默认面向 `compose.yml`，因此 `DATABASE_URL` 和 `VALKEY_URL` 使用 Docker service 名称。直接在宿主机运行二进制时，应在本地 `.env.yaml` 中改为宿主机可访问的地址。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP 监听地址 |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL 连接串 |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey 连接串 |
| `ISSUER` | `http://127.0.0.1:8000` | OAuth/OIDC issuer；生产环境必须使用 HTTPS，本地开发仅允许 loopback HTTP；不能以 `/` 结尾 |
| `FRONTEND_BASE_URL` | `http://127.0.0.1:3000` | 前端地址，用于登录和授权确认跳转；生产环境必须使用 HTTPS，本地开发仅允许 loopback HTTP |
| `CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:3000` | 允许的 CORS origin，多个值用逗号分隔；只接受 HTTPS origin 或 loopback HTTP origin |
| `DEFAULT_AUDIENCE` | `resource://default` | 默认 access token audience |
| `SESSION_COOKIE_NAME` | `nazo_oauth_session` | 会话 cookie 名 |
| `CSRF_COOKIE_NAME` | `nazo_oauth_csrf` | CSRF cookie 名 |
| `COOKIE_SECURE` | HTTPS issuer 时为 `true`，否则为 `false` | 是否给会话和 CSRF cookie 设置 `Secure` 属性；生产环境不能关闭 |
| `SESSION_TTL_SECONDS` | `28800` | 会话有效期，单位为秒 |
| `AUTH_CODE_TTL_SECONDS` | `300` | 授权码有效期，单位为秒 |
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
| `JWK_KEYS_DIR` | `runtime/keys` | Ed25519 keyset 存储目录 |

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

生成新 key：

```sh
nazo-oauth-keyctl generate
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

`keyset.json` 采用临时文件加 rename 写入；Unix 平台私钥 PEM 权限设置为 `0600`。active key 不允许退役，已退役 key 不发布到 JWKS。

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
| `GET` | `/userinfo` | OIDC userinfo；根据 access token scope 返回 `sub`、`preferred_username`、`profile` 和 `email` 对应 claims |

`/token` 仅在授权范围包含 `offline_access` 且客户端启用 `refresh_token` grant 时签发和轮换 refresh token。

`private_key_jwt` 客户端必须在客户端元数据中配置公开 `jwks`，当前支持 Ed25519 / EdDSA 公钥。DPoP proof 若缺少或使用过期 nonce，服务端返回 `use_dpop_nonce` 并通过 `DPoP-Nonce` 响应头提供新的 nonce；DPoP token 和 DPoP-bound userinfo 成功响应也返回下一次 nonce。

PAR 使用 `POST /par` 提交授权请求参数，成功后返回一次性 `request_uri`。`/authorize` 使用 `request_uri` 时拒绝外层参数覆盖。JAR 使用 `request=<jwt>`，只接受 EdDSA 签名请求对象，使用客户端 JWKS 验签，并校验 `iss`、`sub`、`client_id`、`aud`、`exp`、`nbf`、`iat`、`jti` 和防重放状态。

`/introspect` 只接受机密客户端认证，并按 access token audience 或客户端自身 token 归属返回 active metadata；非 active token 只返回 `{"active": false}`。public client 可调用 `/revoke` 撤销属于自身的 token，但不能读取 introspection metadata。

### 请求示例

public PKCE client：

```text
GET /authorize?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid%20profile&code_challenge=<s256>&code_challenge_method=S256
```

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

JAR：客户端用已注册 JWKS 对 request object 进行 EdDSA 签名，然后传入 `/authorize?request=<jwt>` 或 `/par` 的 `request=<jwt>` 字段。

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
