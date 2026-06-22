# NazoAuth 安全加固 — Feature Gates / CORS Restructuring / Pairwise Subject

**日期**: 2026-06-22
**基线**: OAuth 2.1 (draft) + RFC 9700 (Security BCP) + FAPI 2.0 Security Profile + OIDC Core 1.0

---

## 一、Feature Gates

### 1.1 配置字段

```rust
// src/settings.rs
pub(crate) enable_request_object: bool,                // default: false — 控制 /authorize?request=...
pub(crate) enable_request_uri_parameter: bool,         // default: false — 控制 /authorize?request_uri=...
pub(crate) enable_par_request_object: bool,            // default: false — 控制 PAR body 中的 request object
pub(crate) enable_authorization_details: bool,         // default: false — 控制 RFC 9396 authorization_details
pub(crate) enable_legacy_audience_param: bool,         // default: false — 控制项目私有 audience 参数
```

### 1.2 Profile 约束

```rust
impl AuthorizationServerProfile {
    pub(crate) fn requires_par(&self) -> bool {
        matches!(self, Self::Fapi2Security | Self::Fapi2MessageSigningAuthzRequest)
    }

    pub(crate) fn requires_signed_request_object_at_par(&self) -> bool {
        matches!(self, Self::Fapi2MessageSigningAuthzRequest)
    }
}
```

| Profile | requires_par | requires_signed_request_object_at_par | 对 feature gates 的影响 |
|---|---|---|---|
| Oauth2Baseline | false | false | 无（全默认 false） |
| Fapi2Security | true | false | 无（全默认 false） |
| Fapi2MessageSigningAuthzRequest | true | true | enable_par_request_object 会被 profile 逻辑覆盖为 true |

FAPI2 Message Signing 仅影响 PAR 内的 signed request object 要求；**不**开启 `/authorize?request=` 或 `/authorize?request_uri=`。

### 1.3 Gate 拒绝逻辑（早拒绝 + 覆盖所有入口）

```
/authorize:
  request              → enable_request_object
  request_uri          → enable_request_uri_parameter
  authorization_details → enable_authorization_details

/par:
  PAR body request=...        → enable_par_request_object || requires_signed_request_object_at_par()
  PAR body authorization_details → enable_authorization_details
```

在检测到参数时就拒绝，不进入深层解析：

```rust
// /authorize 入口
if q.contains_key("request") && !state.settings.enable_request_object {
    return oauth_error(400, "invalid_request", "request parameter is not enabled");
}
if q.contains_key("request_uri") && !state.settings.enable_request_uri_parameter {
    return oauth_error(400, "invalid_request", "request_uri parameter is not enabled");
}
if q.contains_key("authorization_details") && !state.settings.enable_authorization_details {
    return oauth_error(400, "invalid_request", "authorization_details is not enabled");
}

// /par 入口
if payload.request.is_some() 
    && !state.settings.enable_par_request_object 
    && !state.settings.authorization_server_profile.requires_signed_request_object_at_par()
{
    return oauth_error(400, "invalid_request", "request object at PAR is not enabled");
}
if payload.authorization_details.is_some() && !state.settings.enable_authorization_details {
    return oauth_error(400, "invalid_request", "authorization_details is not enabled");
}
```

### 1.4 Discovery metadata

原则：不暴露空数组；不应省略时有明确语义。

```
request_parameter_supported:
  仅 enable_request_object == true → true，否则省略

request_uri_parameter_supported:
  必须显式暴露（OIDC Discovery 省略时默认值为 true）：
  - enable_request_uri_parameter == false → false
  - enable_request_uri_parameter == true  → true
  - 高安全/FAPI 场景下，必须暴露：
    "request_uri_parameter_supported": true,
    "require_request_uri_registration": true

request_object_signing_alg_values_supported:
  暴露条件：enable_request_object
           || enable_request_uri_parameter
           || enable_par_request_object
           || requires_signed_request_object_at_par()
  暴露时列出 AS 支持的 Request Object 验签算法：["RS256", "ES256", "EdDSA", "PS256"]
  永远不包含 "none"
  否则省略

authorization_details_types_supported:
  仅 enable_authorization_details == true → 暴露，否则省略
```

### 1.5 涉及文件

| 文件 | 改动 |
|---|---|
| src/settings.rs | 新增 5 个 bool 字段 + from_config() |
| src/settings/profile.rs | profile 方法 |
| src/config.rs | 新增 5 条 env var allowlist |
| src/http/authorization/request.rs | /authorize gate 检查 |
| src/http/authorization/par.rs | /par gate 检查 |
| src/http/token/forms.rs 或 dispatch.rs | audience gate |
| src/http/well_known.rs | discovery 动态暴露 |
| .env.yaml.example | 配置示例 |

---

## 二、CORS Restructuring

### 2.1 策略矩阵

| 分段 | 端点 | Methods | Credentials | 说明 |
|---|---|---|---|---|
| 协议-公开 | /.well-known/\*, /jwks.json | GET, HEAD | false | 读取公开 metadata 和密钥 |
| 授权端点 | /authorize | — | — | 不挂 CORS。OAuth client 经 302 重定向访问 |
| 浏览器 OAuth API | /token | POST | 默认 false；仅 cookie session + CSRF 时 true | 按 allowlist 开放 |
| | /revoke | POST | 同上 | 同上 |
| | /userinfo | GET, POST | 同上 | 同上 |
| Backchannel | /par | — | — | 不挂 CORS |
| | /introspect | — | — | 不挂 CORS |
| | /logout (backchannel) | — | — | 不挂 CORS |
| 用户认证 UI | /auth/login, /auth/register, /auth/consent, /auth/federation/\*, /auth/passkey/\*, /auth/send-code, /auth/email-code | — | — | 不挂 CORS。表单/重定向页面 |
| 用户认证 API | /auth/me/\*, /auth/sessions, /auth/mfa/\*, /auth/avatar, /auth/delivery/\*, /auth/applications, /auth/access-requests | GET, POST, PATCH, DELETE | cookie session → true + CSRF；token → false | 前后端分离时按 allowlist |
| 管理/SCIM | /admin/\*, /scim/v2/\* | GET, POST, PATCH, DELETE | 按场景 | 默认 no CORS。管理前端需独立 allowlist |

### 2.2 实现结构

src/bootstrap/cors.rs 导出 5 个函数：

```rust
pub(crate) fn cors_well_known(settings: &Settings) -> Cors;
pub(crate) fn cors_browser_oauth(settings: &Settings) -> Cors;
pub(crate) fn cors_auth_api(settings: &Settings) -> Cors;
pub(crate) fn cors_admin(settings: &Settings) -> Cors;
pub(crate) fn cors_scim(settings: &Settings) -> Cors;
```

src/bootstrap/routes.rs 按 scope/resource 分别包裹。

### 2.3 涉及文件

| 文件 | 改动 |
|---|---|
| src/bootstrap/cors.rs | 重写为 5 个构造函数 |
| src/bootstrap/routes.rs | scope 级 CORS 挂载 |

---

## 三、Pairwise Subject

### 3.1 数据库迁移

```sql
ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'
    CHECK (subject_type IN ('public', 'pairwise'));
ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE clients ADD COLUMN sector_identifier_host TEXT;
```

### 3.2 Client metadata

```rust
pub(crate) subject_type: SubjectType,              // public | pairwise
pub(crate) sector_identifier_uri: Option<String>,  // 原始 URI
pub(crate) sector_identifier_host: Option<String>, // 持久化 host(uri)
```

settings.subject_type 仅作为部署级默认值或约束，不替代 client-level 选择。

### 3.3 注册/更新校验流程

```
若 client.subject_type == pairwise:

  ┌─ sector_identifier_uri 存在？
  │   ├─ 是：
  │   │    1. SSRF 防护（详见 3.4）
  │   │    2. GET → JSON array of strings
  │   │    3. sector_identifier_host = host(sector_identifier_uri)
  │   │    4. 验证：client.redirect_uris ⊆ JSON array
  │   │       - 精确匹配（使用注册时相同的 canonical representation）
  │   │       - 不要求严格相等
  │   │       - 不要求所有条目 host 相同
  │   │    5. 存储 sector_identifier_uri + sector_identifier_host
  │   │
  │   └─ 否：
  │        1. redirect_uris 全同一 host → sector_identifier_host = 该 host
  │        2. 多 host → 拒绝，要求 sector_identifier_uri
  │
  └─ pairwise_subject_secret 可用？
      └─ 否 → 拒绝
```

变更保护：已存在的 pairwise client 不允许修改 sector_identifier_uri（会导致 sub 变化）。需运维执行 breaking-change migration。

### 3.4 SSRF 防护

```
发送前校验：
  - scheme == "https"
  - host 不得为：
      域名: localhost, 127.0.0.1
      IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 0.0.0.0/8
      IPv6: ::1/128, fc00::/7, fe80::/10, ::/128, ::ffff:0:0/96
      特殊: 169.254.169.254（云 metadata）, 0.0.0.0, ::
  - 禁用自动跟随重定向 / 每次重定向重新校验
  - 重定向目标仍须 https + 同一套规则

超时与限制：
  - 连接超时: 5s, 总超时: 10s
  - 最大响应体: 128KB
  - Content-Type 含 application/json
  - 响应体解码为 JSON array of strings
```

### 3.5 Subject 计算

```rust
pub(crate) fn oidc_subject(
    pairwise_subject_secret: &[u8],
    issuer: &str,
    sector_identifier_host: &str,
    user_id: Uuid,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    debug_assert!(pairwise_subject_secret.len() >= 32);
    let mut mac = Hmac::<Sha256>::new_from_slice(pairwise_subject_secret)
        .expect("HMAC key should be valid");
    mac.update(issuer.as_bytes());
    mac.update(b"\x1f");
    mac.update(sector_identifier_host.as_bytes());
    mac.update(b"\x1f");
    mac.update(user_id.to_string().as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}
```

### 3.6 pairwise_subject_secret 长度校验（配置加载层）

```rust
// src/settings.rs — from_config()
if let Some(secret) = &pairwise_subject_secret {
    if secret.len() < 32 {
        return Err("pairwise_subject_secret must be at least 32 bytes");
    }
}
```

不依赖 Hmac::new_from_slice().expect() — 安全约束必须在配置加载阶段显式完成。

### 3.7 调用链路变更

oidc_subject() 签名从 (settings, user_id, redirect_uri) 改为 (pairwise_subject_secret, issuer, sector_identifier_host, user_id)。

| 文件 | 改动 |
|---|---|
| src/support/oidc_claims.rs | 重写 oidc_subject + oidc_user_claims 传入 sector_identifier_host |
| src/http/token/issue.rs | 令牌签发时传 sector_identifier_host |
| src/http/token/userinfo.rs | UserInfo 传 sector_identifier_host |

### 3.8 Discovery — subject_types_supported

```
pairwise_subject_secret 缺失           → ["public"]
pairwise_subject_secret 存在 + 部署允许 public → ["public", "pairwise"]
pairwise_subject_secret 存在 + 部署强制 pairwise → ["pairwise"]
```

### 3.9 文档注意事项

- pairwise_subject_secret 不可随意轮换：轮换会改变所有 pairwise sub。需执行显式迁移。
- sector_identifier_host 变更同理。

---

## 四、实施顺序

| 步骤 | 模块 | 核心文件 |
|---|---|---|
| 1 | Feature Gates — Settings 字段 + profile 方法 | settings.rs, settings/profile.rs, config.rs |
| 2 | Feature Gates — /authorize gate 拒绝 | http/authorization/request.rs |
| 3 | Feature Gates — /par gate 拒绝 | http/authorization/par.rs |
| 4 | Feature Gates — token audience gate | http/token/forms.rs 或 dispatch.rs |
| 5 | Feature Gates — discovery 动态暴露 | http/well_known.rs |
| 6 | Feature Gates — 配置示例 | .env.yaml.example |
| 7 | CORS — 重写 cors.rs | bootstrap/cors.rs |
| 8 | CORS — routes.rs scope 级挂载 | bootstrap/routes.rs |
| 9 | Pairwise — DB migration + ClientRow | migrations/, domain/rows.rs |
| 10 | Pairwise — 注册/更新校验 + SSRF | 客户端创建/更新 handler |
| 11 | Pairwise — 重写 oidc_subject (HMAC-SHA256) | support/oidc_claims.rs |
| 12 | Pairwise — 更新调用链路 | token/issue.rs, userinfo.rs |
| 13 | Pairwise — discovery 动态暴露 | http/well_known.rs |
