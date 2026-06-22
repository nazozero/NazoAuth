# 部署指南

## 范围

生产部署中，Nazo Auth Server 运行在 TLS 终止反向代理之后。PostgreSQL 保存持久状态，Valkey 保存短生命周期协议状态。公开 issuer 必须是 HTTPS origin，并与 Discovery metadata、README、OIDF 测试配置保持一致。

当前公开部署：

| 项目 | 值 |
| --- | --- |
| Issuer | `https://auth.nazo.run` |
| 前端 UI | `https://auth.nazo.run/ui/` |
| Health | `https://auth.nazo.run/health` |
| Discovery | `https://auth.nazo.run/.well-known/openid-configuration` |

## 部署模型

必要组件：

- `nazo-oauth-server` HTTP 进程
- `nazo-oauth-migrate` 数据库迁移命令
- PostgreSQL 数据库
- Valkey 实例
- 持久化 JWT key 目录
- 持久化头像目录
- HTTPS 反向代理

服务本身监听 HTTP，通常是 `0.0.0.0:8000`。反向代理负责公开 HTTPS issuer。

## 上线前检查

1. 创建 PostgreSQL 数据库和用户。
2. 创建 Valkey 实例，并确定持久化 / HA 策略。
3. 为签名密钥和头像分配持久目录。
4. 在仓库之外创建 `.env.yaml`。
5. 将 `ISSUER` 设置为精确公开 HTTPS issuer，不带结尾斜杠。
6. 设置 `FRONTEND_BASE_URL` 和 `CORS_ALLOWED_ORIGINS`。
7. 设置 `COOKIE_SECURE=true`。
8. `TRUSTED_PROXY_CIDRS` 只包含你控制的反向代理地址。
9. 在代理正确清洗 forwarded headers 之前，保持 `CLIENT_IP_HEADER_MODE=none`。
10. 先执行迁移，再切流量。

## 配置基线

```yaml
BIND: "0.0.0.0:8000"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres.example.internal:5432/oauth"
VALKEY_URL: "redis://valkey.example.internal:6379/0"
ISSUER: "https://auth.nazo.run"
FRONTEND_BASE_URL: "https://auth.nazo.run/ui/"
CORS_ALLOWED_ORIGINS:
  - "https://auth.nazo.run"
DEFAULT_AUDIENCE: "resource://default"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
COOKIE_SECURE: true
TRUSTED_PROXY_CIDRS: "10.0.0.0/24"
CLIENT_IP_HEADER_MODE: "forwarded"
SUBJECT_TYPE: "pairwise"
PAIRWISE_SUBJECT_SECRET: "<high-entropy-secret>"
EMAIL_DELIVERY: "smtp"
EMAIL_SMTP_HOST: "smtp.example.com"
EMAIL_SMTP_PORT: 587
EMAIL_SMTP_TLS: "starttls"
EMAIL_SMTP_USERNAME: "<smtp-user>"
EMAIL_SMTP_PASSWORD: "<smtp-password>"
EMAIL_FROM: "Nazo Auth <no-reply@example.com>"
AVATAR_STORAGE_DIR: "/var/lib/nazo_oauth/avatars"
JWK_KEYS_DIR: "/var/lib/nazo_oauth/keys"
SIGNING_EXTERNAL_COMMAND: ""
SIGNING_EXTERNAL_TIMEOUT_MS: 2000
SIGNING_KEY_ROTATION_INTERVAL_SECONDS: 7776000
SIGNING_KEY_PREPUBLISH_SECONDS: 86400
RUST_LOG: "info"
OTEL_ENABLED: false
OTEL_EXPORTER_OTLP_ENDPOINT: ""
OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf"
OTEL_EXPORTER_OTLP_TIMEOUT: 10000
```

不要把生产 secret 提交到 Git。

## Profile 选择

`AUTHORIZATION_SERVER_PROFILE=fapi2-security` 只适用于能满足以下要求的 client 群体：

- confidential-client-only
- PAR-only authorization request
- PKCE S256
- `private_key_jwt` 或 mTLS client authentication
- DPoP 或 mTLS sender-constrained token

当 signed request object 是强制要求时，使用 `fapi2-message-signing-authz-request`。Discovery metadata 会反映当前 profile；除非配置了可信代理，否则不会发布 mTLS 能力。

## 构建和运行容器

构建镜像：

```sh
docker build -f Containerfile -t nazo-oauth-server:$(git rev-parse --short=7 HEAD) .
```

执行迁移：

```sh
docker run --rm \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-migrate
```

启动服务：

```sh
docker run -d --name nazo-oauth-server \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-server
```

`compose.yml` 面向本地集成，不是完整生产拓扑。

## 在线部署脚本

仓库提供 [scripts/deploy_live.ps1](../scripts/deploy_live.ps1)，用于构建镜像、传输到远端、执行迁移、替换 Podman 容器，并校验 health 与 discovery。

默认 live 假设：

| 设置 | 默认值 |
| --- | --- |
| 远端主机 | `nazo.run` |
| 容器名 | `nazo-oauth-server` |
| 网络 | `nazo_oauth_net` |
| 容器 IP | `10.101.0.20` |
| 远端配置 | `/opt/nazo-oauth/.env.yaml` |
| Keys 路径 | `/opt/nazo-oauth/runtime/keys` |
| Avatars 路径 | `/opt/nazo-oauth/runtime/avatars` |
| Health URL | `https://auth.nazo.run/health` |
| Discovery URL | `https://auth.nazo.run/.well-known/openid-configuration` |
| Expected issuer | `https://auth.nazo.run` |

示例：

```powershell
pwsh scripts/deploy_live.ps1 `
  -RemoteHost nazo.run `
  -ImageRepository localhost/nazo-oauth-server `
  -ImageTag main-$(git rev-parse --short=7 HEAD)
```

该脚本面向 `nazo.run` 环境。迁移到其他主机前，必须重新检查监听器、反向代理、容器网络、TLS 设置和 expected issuer。

## 反向代理边界

反向代理要求：

- 使用公开 issuer 域名终止 TLS。
- 只向应用转发经过清洗的代理头。
- 删除客户端传入的 `Forwarded`、`X-Forwarded-*`、mTLS 和证书相关头，再由代理写入可信值。
- `TRUSTED_PROXY_CIDRS` 只包含允许转发 client IP 和 mTLS 证书信息的代理地址。
- 保护代理到应用之间的链路；转发证书元数据只在可信内部通道上有意义。
- 保持 OAuth endpoint 路径精确不变。
- 禁止协议端点被错误缓存，除非端点明确可缓存。
- 确保 `/.well-known/openid-configuration`、`/.well-known/oauth-authorization-server`、`/jwks.json`、`/authorize`、`/par`、`/token`、`/userinfo`、`/introspect`、`/revoke` 可按预期访问。

mTLS sender constraint 和 mTLS client authentication 依赖可信反向代理完成客户端证书校验，并转发证书证据。应用只接受来自 `TRUSTED_PROXY_CIDRS` 的证书元数据；其他来源视为没有已验证证书。

## 密钥轮换

首次启动时，如果 keyset 不存在，服务会创建本地 RS256 签名密钥。本地 PEM
keyset 在服务启动和 keyset 加载时自动维护生命周期：active key 进入预发布窗口后，
服务通过进程内生命周期任务定期刷新运行时 keyset 快照；active key 进入预发布窗口后，
服务会生成并发布下一把本地 key；预发布窗口结束且 active key 到达轮换周期后，服务
自动激活下一把 key；上一把 active key 会继续发布到 JWKS，直到
`max(ACCESS_TOKEN_TTL_SECONDS, ID_TOKEN_TTL_SECONDS)` 对应的宽限窗口结束。

默认生命周期配置：

- `SIGNING_KEY_ROTATION_INTERVAL_SECONDS=7776000`（90 天）
- `SIGNING_KEY_PREPUBLISH_SECONDS=86400`（1 天）

预发布窗口必须为正数，并且必须短于轮换周期。运行时刷新间隔由预发布窗口派生，最长
不超过一小时。部署或恢复备份后可校验 keyset：

```sh
nazo-oauth-keyctl validate
```

`validate` 会拒绝格式错误的 `retire_at`，也会拒绝 active key 携带
`retire_at`。应定期备份 key 目录。丢失 active private key 会破坏 token 签名连续性。

## 数据库和 Valkey

PostgreSQL 保存用户、client、grant、token、撤销状态等持久数据。生产要求：

- 自动备份
- 恢复演练
- migration rollback 计划
- 复制延迟和存储容量监控

Valkey 保存短生命周期 session、授权码、PAR handle、DPoP / client assertion replay 状态和 rate limit counter。生产要求：

- 有界内存策略
- 延迟监控
- 与风险模型匹配的持久化或 HA
- 明确的故障处理预期

Valkey 不可用时，敏感协议路径应 fail closed，以 OAuth error 返回，而不是降低 replay 或 rate limit 保护。

## 部署后验证

```sh
curl -fsS https://auth.nazo.run/health
curl -fsS https://auth.nazo.run/.well-known/openid-configuration
curl -fsS https://auth.nazo.run/.well-known/oauth-authorization-server
curl -fsS https://auth.nazo.run/jwks.json
```

检查 discovery 的 `issuer` 必须精确等于 `ISSUER`。

## OIDF 准备

启动完整 OpenID Foundation conformance run 前：

1. 部署要测试的精确 commit。
2. 通过公开 issuer 校验 discovery 和 JWKS。
3. 确认 suite plan config 中 redirect URI 正确。
4. 确认浏览器自动化规则匹配真实 login、consent、callback 页面。
5. 确认 mTLS endpoint alias 和代理证书转发。
6. 运行 `.github/workflows/oidf-conformance-full.yml`。
7. 在 artifact 过期前保存最终结果到 `docs/conformance`。

## 运维检查清单

- 生产只使用 HTTPS issuer。
- `COOKIE_SECURE=true`。
- `CORS_ALLOWED_ORIGINS` 最小化。
- 严格限制可信代理 CIDR。
- 不存在 proxy header spoofing 路径。
- PostgreSQL 备份与恢复演练完成。
- Valkey 可用性和内存受监控。
- 签名密钥备份和轮换计划明确。
- 审计日志被采集和保留。
- 管理员账号完成加固。
- 发布流程保留 SBOM、镜像签名和 provenance attestation。
- OIDF conformance 证据在 artifact 过期前更新。
