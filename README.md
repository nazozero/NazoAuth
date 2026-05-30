# Nazo OAuth Server

Nazo OAuth Server 是一个基于 Actix Web 的 OAuth/OIDC 服务，提供用户认证、授权码流程、token 签发与轮换、JWKS、userinfo、客户端管理、授权记录管理、接入申请管理和头像管理能力。

## 特性

- OAuth 2.0 authorization code、refresh token、client credentials 流程
- OpenID Connect discovery、JWKS、userinfo
- Ed25519 JWT 签名
- refresh token 轮换与复用检测
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

## 配置

服务启动时会读取 `env.yaml`、`env.yml` 和 `.env`，也支持直接使用进程环境变量。优先级为：进程环境变量高于 `.env`，`.env` 高于 `env.yaml` / `env.yml`，配置文件未提供时使用内置默认值；配置文件存在但不可读、格式错误或字段类型错误时启动失败。

`env.yaml` 支持顶层键值形式；数组值会按逗号合并，适合 `CORS_ALLOWED_ORIGINS` 这类列表配置。`.env` 支持 `KEY=value` 形式，适合本地密钥或临时覆盖。仓库提供 `.env.example` 和 `env.yaml.example` 作为字段参考，真实配置文件不应提交。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP 监听地址 |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL 连接串 |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey 连接串 |
| `ISSUER` | `http://127.0.0.1:8000` | OAuth/OIDC issuer |
| `FRONTEND_BASE_URL` | `http://127.0.0.1:3000` | 前端地址，用于登录和授权确认跳转 |
| `CORS_ALLOWED_ORIGINS` | `http://127.0.0.1:3000` | 允许的 CORS origin，多个值用逗号分隔 |
| `DEFAULT_AUDIENCE` | `resource://default` | 默认 access token audience |
| `SESSION_COOKIE_NAME` | `nazo_oauth_session` | 会话 cookie 名 |
| `CSRF_COOKIE_NAME` | `nazo_oauth_csrf` | CSRF cookie 名 |
| `SESSION_TTL_SECONDS` | `28800` | 会话有效期，单位为秒 |
| `AUTH_CODE_TTL_SECONDS` | `300` | 授权码有效期，单位为秒 |
| `ACCESS_TOKEN_TTL_SECONDS` | `300` | access token 有效期，单位为秒 |
| `ID_TOKEN_TTL_SECONDS` | `600` | ID token 有效期，单位为秒 |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | refresh token 有效期，单位为秒 |
| `AVATAR_MAX_BYTES` | `2097152` | 头像最大字节数 |
| `CLIENT_DELIVERY_TTL_SECONDS` | `86400` | 客户端接入信息投递有效期，单位为秒 |
| `EMAIL_CODE_DEV_RESPONSE_ENABLED` | `false` | 仅 debug 构建可用；启用后 `/auth/send-code` 响应包含注册验证码，便于本地开发 |
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
```

## 数据库迁移

```sh
DATABASE_URL="<postgres-url>" cargo run --bin nazo-oauth-migrate
```

## 运行服务

```sh
DATABASE_URL="<postgres-url>" \
VALKEY_URL="<valkey-url>" \
ISSUER="<issuer-url>" \
FRONTEND_BASE_URL="<frontend-url>" \
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
  -e DATABASE_URL="<postgres-url>" \
  nazo-oauth-server \
  nazo-oauth-migrate
```

运行服务：

```sh
docker run --rm \
  -p 8000:8000 \
  -e BIND="0.0.0.0:8000" \
  -e DATABASE_URL="<postgres-url>" \
  -e VALKEY_URL="<valkey-url>" \
  -e ISSUER="<issuer-url>" \
  -e FRONTEND_BASE_URL="<frontend-url>" \
  nazo-oauth-server
```

项目提供 `compose.yml`，用于启动包含 PostgreSQL、Valkey、迁移任务和服务进程的本地集成环境：

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
| `POST` | `/token` | token 签发、刷新、client credentials |
| `POST` | `/revoke` | token 撤销 |
| `POST` | `/introspect` | token introspection |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/jwks.json` | JWKS |
| `GET` | `/userinfo` | OIDC userinfo |

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
