//! OIDC 标准 claims 构造。
//! 只从已授权 scope、显式授权的 claims 请求和本地用户事实源生成声明，不为缺失字段写入 null。

use serde_json::{Value, json};

use nazo_auth::OidcClaimRequest;

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

pub fn user_claims_are_covered_by_scopes(
    scopes: &[String],
    requested_claims: &[OidcClaimRequest],
) -> bool {
    requested_claims.iter().all(|claim| {
        let required_scope = if PROFILE_CLAIMS.contains(&claim.name.as_str()) {
            "profile"
        } else if EMAIL_CLAIMS.contains(&claim.name.as_str()) {
            "email"
        } else if ADDRESS_CLAIMS.contains(&claim.name.as_str()) {
            "address"
        } else if PHONE_CLAIMS.contains(&claim.name.as_str()) {
            "phone"
        } else {
            return false;
        };
        scopes.iter().any(|scope| scope == required_scope)
    })
}

pub fn oidc_user_claims(
    user: &nazo_identity::SubjectClaims,
    scopes: &[String],
    subject: &str,
    requested_claims: &[OidcClaimRequest],
) -> serde_json::Map<String, Value> {
    user_claims(user, subject, requested_claims, |scope| {
        scopes.iter().any(|value| value == scope)
    })
}

pub fn oidc_id_token_user_claims(
    user: &nazo_identity::SubjectClaims,
    scopes: &[String],
    subject: &str,
    requested_claims: &[OidcClaimRequest],
) -> serde_json::Map<String, Value> {
    user_claims(user, subject, requested_claims, |scope| {
        scope == "profile" && scopes.iter().any(|value| value == "profile")
    })
}

fn user_claims(
    user: &nazo_identity::SubjectClaims,
    subject: &str,
    requests: &[OidcClaimRequest],
    scope_allowed: impl Fn(&str) -> bool,
) -> serde_json::Map<String, Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_owned(), json!(subject));
    let profile = scope_allowed("profile");
    let email = scope_allowed("email");
    let phone = scope_allowed("phone");
    for (name, value, allowed) in [
        (
            "preferred_username",
            user.preferred_username.as_str(),
            profile,
        ),
        ("name", user_display_name(user), profile),
        ("email", user.email.as_str(), email),
    ] {
        insert_claim(&mut claims, requests, name, allowed, || Some(json!(value)));
    }
    for (name, value, allowed) in [
        ("given_name", user.given_name.as_deref(), profile),
        ("family_name", user.family_name.as_deref(), profile),
        ("middle_name", user.middle_name.as_deref(), profile),
        ("nickname", user.nickname.as_deref(), profile),
        ("profile", user.profile.as_deref(), profile),
        ("picture", user.picture.as_deref(), profile),
        ("website", user.website.as_deref(), profile),
        ("gender", user.gender.as_deref(), profile),
        ("birthdate", user.birthdate.as_deref(), profile),
        ("zoneinfo", user.zoneinfo.as_deref(), profile),
        ("locale", user.locale.as_deref(), profile),
        ("phone_number", user.phone_number.as_deref(), phone),
    ] {
        insert_claim(&mut claims, requests, name, allowed, || {
            value
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| json!(value))
        });
    }
    insert_claim(&mut claims, requests, "updated_at", profile, || {
        Some(json!(user.updated_at))
    });
    insert_claim(&mut claims, requests, "email_verified", email, || {
        Some(json!(user.email_verified))
    });
    insert_claim(
        &mut claims,
        requests,
        "phone_number_verified",
        phone,
        || Some(json!(user.phone_number_verified)),
    );
    insert_claim(
        &mut claims,
        requests,
        "address",
        scope_allowed("address"),
        || address_claim(user),
    );
    claims
}

fn insert_claim(
    claims: &mut serde_json::Map<String, Value>,
    requests: &[OidcClaimRequest],
    name: &str,
    scope_allowed: bool,
    value: impl FnOnce() -> Option<Value>,
) {
    let request = requests.iter().find(|request| request.name == name);
    if !scope_allowed && request.is_none() {
        return;
    }
    if let Some(actual) = value()
        && request.is_none_or(|request| request.matches_value(&actual))
    {
        claims.insert(name.to_owned(), actual);
    }
}

fn address_claim(user: &nazo_identity::SubjectClaims) -> Option<Value> {
    let source = user.address.as_ref()?;
    let address: serde_json::Map<String, Value> = [
        ("formatted", source.formatted.as_deref()),
        ("street_address", source.street_address.as_deref()),
        ("locality", source.locality.as_deref()),
        ("region", source.region.as_deref()),
        ("postal_code", source.postal_code.as_deref()),
        ("country", source.country.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| (name.to_owned(), json!(value)))
    })
    .collect();
    (!address.is_empty()).then_some(Value::Object(address))
}

fn user_display_name(user: &nazo_identity::SubjectClaims) -> &str {
    user.name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&user.preferred_username)
}

#[cfg(test)]
#[path = "../../tests/unit/domain/oidc_claims.rs"]
mod tests;
