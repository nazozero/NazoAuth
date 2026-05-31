//! OIDC 标准 claims 构造。
//! 只从已授权 scope 和本地用户事实源生成声明，不为缺失字段写入 null。

use super::prelude::*;

pub(crate) fn oidc_user_claims(user: &UserRow, scopes: &[String], subject: &str) -> Value {
    let mut claims = json!({"sub": subject});

    if scopes.iter().any(|scope| scope == "profile") {
        claims["preferred_username"] = json!(user.username);
        if let Some(name) = user
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims["name"] = json!(name);
        }
        if let Some(picture) = user
            .avatar_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims["picture"] = json!(picture);
        }
    }

    if scopes.iter().any(|scope| scope == "email") {
        claims["email"] = json!(user.email);
        claims["email_verified"] = json!(user.email_verified);
    }

    claims
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserRow {
        UserRow {
            id: Uuid::now_v7(),
            username: "alice".to_owned(),
            email: "alice@example.com".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            avatar_url: Some("https://cdn.example/alice.png".to_owned()),
            role: "user".to_owned(),
            admin_level: 0,
            email_verified: true,
            password_hash: "hash".to_owned(),
            is_active: true,
            created_at: Utc::now(),
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
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["preferred_username"], "alice");
        assert_eq!(claims["name"], "Alice Example");
        assert_eq!(claims["picture"], "https://cdn.example/alice.png");
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["email_verified"], true);
    }

    #[test]
    fn userinfo_claims_omit_unrequested_profile_and_email() {
        let user = user();
        let claims = oidc_user_claims(&user, &["openid".to_owned()], "subject-1");

        assert!(claims.get("name").is_none());
        assert!(claims.get("preferred_username").is_none());
        assert!(claims.get("picture").is_none());
        assert!(claims.get("email").is_none());
        assert!(claims.get("email_verified").is_none());
    }
}
