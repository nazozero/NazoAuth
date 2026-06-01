//! OIDC 标准 claims 构造。
//! 只从已授权 scope 和本地用户事实源生成声明，不为缺失字段写入 null。

use super::prelude::*;
use crate::settings::SubjectType;

pub(crate) fn oidc_subject(settings: &Settings, user_id: Uuid, redirect_uri: &str) -> String {
    match settings.subject_type {
        SubjectType::Public => user_id.to_string(),
        SubjectType::Pairwise => {
            let sector = url::Url::parse(redirect_uri)
                .ok()
                .and_then(|url| url.host_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| redirect_uri.to_owned());
            let secret = settings
                .pairwise_subject_secret
                .as_deref()
                .unwrap_or_default();
            let material = format!("{secret}\x1f{sector}\x1f{user_id}");
            URL_SAFE_NO_PAD.encode(Sha256::digest(material.as_bytes()))
        }
    }
}

const PROFILE_CLAIMS: &[&str] = &[
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
];

const EMAIL_CLAIMS: &[&str] = &["email", "email_verified"];

pub(crate) fn supported_user_claim(name: &str) -> bool {
    PROFILE_CLAIMS.contains(&name) || EMAIL_CLAIMS.contains(&name)
}

pub(crate) fn oidc_user_claims(
    user: &UserRow,
    scopes: &[String],
    subject: &str,
    requested_claims: &[String],
) -> Value {
    let mut claims = json!({"sub": subject});
    let has_profile_scope = scopes.iter().any(|scope| scope == "profile");
    let has_email_scope = scopes.iter().any(|scope| scope == "email");

    if has_profile_scope || requested_claim(requested_claims, "preferred_username") {
        claims["preferred_username"] = json!(user.username);
    }
    if has_profile_scope || requested_claim(requested_claims, "name") {
        claims["name"] = json!(user_display_name(user));
    }
    if has_profile_scope || requested_claim(requested_claims, "given_name") {
        optional_string_claim(&mut claims, "given_name", user.given_name.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "family_name") {
        optional_string_claim(&mut claims, "family_name", user.family_name.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "middle_name") {
        optional_string_claim(&mut claims, "middle_name", user.middle_name.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "nickname") {
        optional_string_claim(&mut claims, "nickname", user.nickname.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "profile") {
        optional_string_claim(&mut claims, "profile", user.profile_url.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "picture") {
        optional_string_claim(&mut claims, "picture", user.avatar_url.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "website") {
        optional_string_claim(&mut claims, "website", user.website_url.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "gender") {
        optional_string_claim(&mut claims, "gender", user.gender.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "birthdate") {
        optional_string_claim(&mut claims, "birthdate", user.birthdate.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "zoneinfo") {
        optional_string_claim(&mut claims, "zoneinfo", user.zoneinfo.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "locale") {
        optional_string_claim(&mut claims, "locale", user.locale.as_deref());
    }
    if has_profile_scope || requested_claim(requested_claims, "updated_at") {
        claims["updated_at"] = json!(user.updated_at.timestamp());
    }

    if has_email_scope || requested_claim(requested_claims, "email") {
        claims["email"] = json!(user.email);
    }
    if has_email_scope || requested_claim(requested_claims, "email_verified") {
        claims["email_verified"] = json!(user.email_verified);
    }

    claims
}

fn optional_string_claim(claims: &mut Value, name: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        claims[name] = json!(value);
    }
}

fn requested_claim(requested_claims: &[String], name: &str) -> bool {
    requested_claims.iter().any(|claim| claim == name)
}

fn user_display_name(user: &UserRow) -> &str {
    user.display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&user.username)
}

pub(crate) fn oidc_id_token_user_claims(
    user: &UserRow,
    scopes: &[String],
    subject: &str,
    requested_claims: &[String],
) -> Value {
    let mut claims = oidc_user_claims(user, scopes, subject, requested_claims);
    if let Some(object) = claims.as_object_mut() {
        if !requested_claim(requested_claims, "email") {
            object.remove("email");
        }
        if !requested_claim(requested_claims, "email_verified") {
            object.remove("email_verified");
        }
    }
    claims
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{EmailDelivery, EmailSettings, RateLimitSettings};
    use crate::support::ClientIpHeaderMode;

    fn user() -> UserRow {
        let now = Utc::now();
        UserRow {
            id: Uuid::now_v7(),
            username: "alice".to_owned(),
            email: "alice@example.com".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            avatar_url: Some("https://cdn.example/alice.png".to_owned()),
            given_name: Some("Alice".to_owned()),
            family_name: Some("Example".to_owned()),
            middle_name: Some("Quinn".to_owned()),
            nickname: Some("ally".to_owned()),
            profile_url: Some("https://profiles.example/alice".to_owned()),
            website_url: Some("https://alice.example".to_owned()),
            gender: Some("female".to_owned()),
            birthdate: Some("1990-01-02".to_owned()),
            zoneinfo: Some("Asia/Shanghai".to_owned()),
            locale: Some("zh-CN".to_owned()),
            role: "user".to_owned(),
            admin_level: 0,
            email_verified: true,
            password_hash: "hash".to_owned(),
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn settings() -> Settings {
        Settings {
            issuer: "https://issuer.example".to_owned(),
            frontend_base_url: "https://frontend.example".to_owned(),
            cors_allowed_origins: vec!["https://frontend.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            session_cookie_name: "session".to_owned(),
            csrf_cookie_name: "csrf".to_owned(),
            cookie_secure: true,
            session_ttl_seconds: 28_800,
            auth_code_ttl_seconds: 300,
            access_token_ttl_seconds: 300,
            id_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            avatar_max_bytes: 2_097_152,
            client_delivery_ttl_seconds: 86_400,
            rate_limit: RateLimitSettings {
                window_seconds: 60,
                auth_max_requests: 30,
                token_max_requests: 60,
                token_management_max_requests: 120,
            },
            email: EmailSettings {
                delivery: EmailDelivery::Disabled,
                code_ttl_seconds: 900,
                send_cooldown_seconds: 60,
                send_peer_cooldown_seconds: 5,
            },
            email_code_dev_response_enabled: false,
            avatar_storage_dir: std::env::temp_dir().join("unused-avatars"),
            jwk_keys_dir: std::env::temp_dir().join("unused-keys"),
            trusted_proxy_cidrs: Vec::new(),
            client_ip_header_mode: ClientIpHeaderMode::None,
            subject_type: SubjectType::Public,
            pairwise_subject_secret: None,
            par_ttl_seconds: 90,
            require_pushed_authorization_requests: false,
        }
    }

    #[test]
    fn userinfo_claims_follow_authorized_scopes() {
        let user = user();
        let claims = oidc_user_claims(
            &user,
            &[
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            "subject-1",
            &[],
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["preferred_username"], "alice");
        assert_eq!(claims["name"], "Alice Example");
        assert_eq!(claims["given_name"], "Alice");
        assert_eq!(claims["family_name"], "Example");
        assert_eq!(claims["middle_name"], "Quinn");
        assert_eq!(claims["nickname"], "ally");
        assert_eq!(claims["profile"], "https://profiles.example/alice");
        assert_eq!(claims["picture"], "https://cdn.example/alice.png");
        assert_eq!(claims["website"], "https://alice.example");
        assert_eq!(claims["gender"], "female");
        assert_eq!(claims["birthdate"], "1990-01-02");
        assert_eq!(claims["zoneinfo"], "Asia/Shanghai");
        assert_eq!(claims["locale"], "zh-CN");
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["email_verified"], true);
    }

    #[test]
    fn userinfo_claims_omit_unrequested_profile_and_email() {
        let user = user();
        let claims = oidc_user_claims(&user, &["openid".to_owned()], "subject-1", &[]);

        assert!(claims.get("name").is_none());
        assert!(claims.get("given_name").is_none());
        assert!(claims.get("family_name").is_none());
        assert!(claims.get("middle_name").is_none());
        assert!(claims.get("nickname").is_none());
        assert!(claims.get("profile").is_none());
        assert!(claims.get("preferred_username").is_none());
        assert!(claims.get("picture").is_none());
        assert!(claims.get("website").is_none());
        assert!(claims.get("gender").is_none());
        assert!(claims.get("birthdate").is_none());
        assert!(claims.get("zoneinfo").is_none());
        assert!(claims.get("locale").is_none());
        assert!(claims.get("email").is_none());
        assert!(claims.get("email_verified").is_none());
    }

    #[test]
    fn id_token_user_claims_do_not_expose_email_scope_claims() {
        let user = user();
        let claims = oidc_id_token_user_claims(
            &user,
            &[
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            "subject-1",
            &[],
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["preferred_username"], "alice");
        assert!(claims.get("email").is_none());
        assert!(claims.get("email_verified").is_none());
    }

    #[test]
    fn requested_userinfo_claims_are_returned_without_profile_scope() {
        let mut user = user();
        user.display_name = None;
        let claims = oidc_user_claims(
            &user,
            &["openid".to_owned()],
            "subject-1",
            &["name".to_owned()],
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["name"], "alice");
        assert!(claims.get("preferred_username").is_none());
    }

    #[test]
    fn pairwise_subject_is_stable_within_sector_and_distinct_across_sectors() {
        let user_id = Uuid::now_v7();
        let mut settings = settings();
        settings.subject_type = SubjectType::Pairwise;
        settings.pairwise_subject_secret = Some("secret".to_owned());

        let first = oidc_subject(&settings, user_id, "https://client.example/callback");
        let second = oidc_subject(&settings, user_id, "https://client.example/other");
        let third = oidc_subject(&settings, user_id, "https://other.example/callback");

        assert_eq!(first, second);
        assert_ne!(first, third);
        assert_ne!(first, user_id.to_string());
    }
}
