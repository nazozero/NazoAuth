//! OIDC 标准 claims 构造。
//! 只从已授权 scope 和本地用户事实源生成声明，不为缺失字段写入 null。

use super::prelude::*;
use crate::domain::OidcClaimRequest;
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
const ADDRESS_CLAIMS: &[&str] = &["address"];
const PHONE_CLAIMS: &[&str] = &["phone_number", "phone_number_verified"];

pub(crate) fn supported_user_claim(name: &str) -> bool {
    PROFILE_CLAIMS.contains(&name)
        || EMAIL_CLAIMS.contains(&name)
        || ADDRESS_CLAIMS.contains(&name)
        || PHONE_CLAIMS.contains(&name)
}

pub(crate) fn oidc_user_claims(
    user: &UserRow,
    scopes: &[String],
    subject: &str,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
) -> Value {
    let mut claims = json!({"sub": subject});
    let has_profile_scope = scopes.iter().any(|scope| scope == "profile");
    let has_email_scope = scopes.iter().any(|scope| scope == "email");
    let has_address_scope = scopes.iter().any(|scope| scope == "address");
    let has_phone_scope = scopes.iter().any(|scope| scope == "phone");

    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "preferred_username",
        &json!(user.username),
    ) {
        claims["preferred_username"] = json!(user.username);
    }
    let name = user_display_name(user);
    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "name",
        &json!(name),
    ) {
        claims["name"] = json!(name);
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "given_name",
        user.given_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "given_name", user.given_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "family_name",
        user.family_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "family_name", user.family_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "middle_name",
        user.middle_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "middle_name", user.middle_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "nickname",
        user.nickname.as_deref(),
    ) {
        optional_string_claim(&mut claims, "nickname", user.nickname.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "profile",
        user.profile_url.as_deref(),
    ) {
        optional_string_claim(&mut claims, "profile", user.profile_url.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "picture",
        user.avatar_url.as_deref(),
    ) {
        optional_string_claim(&mut claims, "picture", user.avatar_url.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "website",
        user.website_url.as_deref(),
    ) {
        optional_string_claim(&mut claims, "website", user.website_url.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "gender",
        user.gender.as_deref(),
    ) {
        optional_string_claim(&mut claims, "gender", user.gender.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "birthdate",
        user.birthdate.as_deref(),
    ) {
        optional_string_claim(&mut claims, "birthdate", user.birthdate.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "zoneinfo",
        user.zoneinfo.as_deref(),
    ) {
        optional_string_claim(&mut claims, "zoneinfo", user.zoneinfo.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "locale",
        user.locale.as_deref(),
    ) {
        optional_string_claim(&mut claims, "locale", user.locale.as_deref());
    }
    let updated_at = json!(user.updated_at.timestamp());
    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "updated_at",
        &updated_at,
    ) {
        claims["updated_at"] = json!(user.updated_at.timestamp());
    }

    if claim_allowed(
        has_email_scope,
        requested_claims,
        requested_claim_requests,
        "email",
        &json!(user.email),
    ) {
        claims["email"] = json!(user.email);
    }
    if claim_allowed(
        has_email_scope,
        requested_claims,
        requested_claim_requests,
        "email_verified",
        &json!(user.email_verified),
    ) {
        claims["email_verified"] = json!(user.email_verified);
    }
    let address = address_claim(user);
    if let Some(address) = address
        && claim_allowed(
            has_address_scope,
            requested_claims,
            requested_claim_requests,
            "address",
            &address,
        )
    {
        claims["address"] = address;
    }
    if optional_string_claim_allowed(
        has_phone_scope,
        requested_claims,
        requested_claim_requests,
        "phone_number",
        user.phone_number.as_deref(),
    ) {
        optional_string_claim(&mut claims, "phone_number", user.phone_number.as_deref());
    }
    if claim_allowed(
        has_phone_scope,
        requested_claims,
        requested_claim_requests,
        "phone_number_verified",
        &json!(user.phone_number_verified),
    ) {
        claims["phone_number_verified"] = json!(user.phone_number_verified);
    }

    claims
}

fn address_claim(user: &UserRow) -> Option<Value> {
    let mut address = json!({});
    optional_string_claim(&mut address, "formatted", user.address_formatted.as_deref());
    optional_string_claim(
        &mut address,
        "street_address",
        user.address_street_address.as_deref(),
    );
    optional_string_claim(&mut address, "locality", user.address_locality.as_deref());
    optional_string_claim(&mut address, "region", user.address_region.as_deref());
    optional_string_claim(
        &mut address,
        "postal_code",
        user.address_postal_code.as_deref(),
    );
    optional_string_claim(&mut address, "country", user.address_country.as_deref());
    address
        .as_object()
        .is_some_and(|object| !object.is_empty())
        .then_some(address)
}

fn optional_string_claim(claims: &mut Value, name: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        claims[name] = json!(value);
    }
}

fn requested_claim(requested_claims: &[String], name: &str) -> bool {
    requested_claims.iter().any(|claim| claim == name)
}

fn claim_requested(
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
) -> bool {
    requested_claim(requested_claims, name)
        || requested_claim_requests
            .iter()
            .any(|request| request.name == name)
}

fn claim_allowed(
    scope_allowed: bool,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
    actual: &Value,
) -> bool {
    if let Some(request) = requested_claim_requests
        .iter()
        .find(|request| request.name == name)
    {
        return claim_value_matches_request(request, actual);
    }
    scope_allowed || requested_claim(requested_claims, name)
}

fn optional_string_claim_allowed(
    scope_allowed: bool,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
    actual: Option<&str>,
) -> bool {
    let Some(actual) = actual.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    claim_allowed(
        scope_allowed,
        requested_claims,
        requested_claim_requests,
        name,
        &json!(actual),
    )
}

fn claim_value_matches_request(request: &OidcClaimRequest, actual: &Value) -> bool {
    match (&request.value, request.values.as_slice()) {
        (Some(expected), _) => expected == actual,
        (None, []) => true,
        (None, values) => values.iter().any(|expected| expected == actual),
    }
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
    requested_claim_requests: &[OidcClaimRequest],
) -> Value {
    let mut claims = oidc_user_claims(
        user,
        scopes,
        subject,
        requested_claims,
        requested_claim_requests,
    );
    if let Some(object) = claims.as_object_mut() {
        if !claim_requested(requested_claims, requested_claim_requests, "email") {
            object.remove("email");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "email_verified") {
            object.remove("email_verified");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "address") {
            object.remove("address");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "phone_number") {
            object.remove("phone_number");
        }
        if !claim_requested(
            requested_claims,
            requested_claim_requests,
            "phone_number_verified",
        ) {
            object.remove("phone_number_verified");
        }
    }
    claims
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{
        AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings,
        RateLimitSettings, RequestObjectJtiPolicy,
    };
    use crate::support::ClientIpHeaderMode;

    fn user() -> UserRow {
        let now = Utc::now();
        UserRow {
            id: Uuid::now_v7(),
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
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
            address_formatted: Some(
                "100 Universal City Plaza\nUniversal City, CA 91608\nUS".to_owned(),
            ),
            address_street_address: Some("100 Universal City Plaza".to_owned()),
            address_locality: Some("Universal City".to_owned()),
            address_region: Some("CA".to_owned()),
            address_postal_code: Some("91608".to_owned()),
            address_country: Some("US".to_owned()),
            phone_number: Some("+15555550000".to_owned()),
            phone_number_verified: true,
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
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://frontend.example".to_owned(),
            cors_allowed_origins: vec!["https://frontend.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
            dpop_nonce_policy: DpopNoncePolicy::Required,
            request_object_jti_policy: RequestObjectJtiPolicy::Optional,
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
            signing_external_command: Vec::new(),
            signing_external_timeout_ms: 2_000,
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
                "address".to_owned(),
                "phone".to_owned(),
            ],
            "subject-1",
            &[],
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
        assert_eq!(
            claims["address"]["formatted"],
            "100 Universal City Plaza\nUniversal City, CA 91608\nUS"
        );
        assert_eq!(
            claims["address"]["street_address"],
            "100 Universal City Plaza"
        );
        assert_eq!(claims["address"]["locality"], "Universal City");
        assert_eq!(claims["address"]["region"], "CA");
        assert_eq!(claims["address"]["postal_code"], "91608");
        assert_eq!(claims["address"]["country"], "US");
        assert_eq!(claims["phone_number"], "+15555550000");
        assert_eq!(claims["phone_number_verified"], true);
    }

    #[test]
    fn userinfo_claims_omit_unrequested_profile_and_email() {
        let user = user();
        let claims = oidc_user_claims(&user, &["openid".to_owned()], "subject-1", &[], &[]);

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
        assert!(claims.get("address").is_none());
        assert!(claims.get("phone_number").is_none());
        assert!(claims.get("phone_number_verified").is_none());
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
            &[],
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["preferred_username"], "alice");
        assert!(claims.get("email").is_none());
        assert!(claims.get("email_verified").is_none());
        assert!(claims.get("address").is_none());
        assert!(claims.get("phone_number").is_none());
        assert!(claims.get("phone_number_verified").is_none());
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
            &[],
        );

        assert_eq!(claims["sub"], "subject-1");
        assert_eq!(claims["name"], "alice");
        assert!(claims.get("preferred_username").is_none());
    }

    #[test]
    fn requested_contact_claims_are_returned_without_contact_scopes() {
        let user = user();
        let claims = oidc_user_claims(
            &user,
            &["openid".to_owned()],
            "subject-1",
            &[
                "address".to_owned(),
                "phone_number".to_owned(),
                "phone_number_verified".to_owned(),
            ],
            &[],
        );

        assert_eq!(claims["address"]["country"], "US");
        assert_eq!(claims["phone_number"], "+15555550000");
        assert_eq!(claims["phone_number_verified"], true);
    }

    #[test]
    fn requested_userinfo_claim_values_filter_output_even_when_scope_allows_claim() {
        let user = user();
        let claims = oidc_user_claims(
            &user,
            &["openid".to_owned(), "email".to_owned(), "phone".to_owned()],
            "subject-1",
            &[
                "email".to_owned(),
                "email_verified".to_owned(),
                "phone_number".to_owned(),
            ],
            &[
                OidcClaimRequest {
                    name: "email".to_owned(),
                    essential: true,
                    value: Some(json!("other@example.com")),
                    values: Vec::new(),
                },
                OidcClaimRequest {
                    name: "email_verified".to_owned(),
                    essential: false,
                    value: Some(json!(true)),
                    values: Vec::new(),
                },
                OidcClaimRequest {
                    name: "phone_number".to_owned(),
                    essential: false,
                    value: None,
                    values: vec![json!("+15555550000"), json!("+15555550001")],
                },
            ],
        );

        assert!(claims.get("email").is_none());
        assert_eq!(claims["email_verified"], true);
        assert_eq!(claims["phone_number"], "+15555550000");
    }

    #[test]
    fn id_token_claim_values_filter_output_and_allow_matching_contact_claims() {
        let user = user();
        let claims = oidc_id_token_user_claims(
            &user,
            &["openid".to_owned(), "email".to_owned(), "phone".to_owned()],
            "subject-1",
            &[
                "email".to_owned(),
                "email_verified".to_owned(),
                "phone_number".to_owned(),
            ],
            &[
                OidcClaimRequest {
                    name: "email".to_owned(),
                    essential: false,
                    value: Some(json!("alice@example.com")),
                    values: Vec::new(),
                },
                OidcClaimRequest {
                    name: "email_verified".to_owned(),
                    essential: false,
                    value: None,
                    values: vec![json!(false)],
                },
                OidcClaimRequest {
                    name: "phone_number".to_owned(),
                    essential: false,
                    value: None,
                    values: vec![json!("+15555550000")],
                },
            ],
        );

        assert_eq!(claims["email"], "alice@example.com");
        assert!(claims.get("email_verified").is_none());
        assert_eq!(claims["phone_number"], "+15555550000");
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
