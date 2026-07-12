//! OIDC 标准 claims 构造。
//! 只从已授权 scope、显式授权的 claims 请求和本地用户事实源生成声明，不为缺失字段写入 null。

use hmac::{Hmac, KeyInit, Mac};

use super::prelude::*;
use nazo_auth::OidcClaimRequest;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn oidc_subject(
    pairwise_subject_secret: &[u8],
    issuer: &str,
    sector_identifier_host: &str,
    user_id: Uuid,
) -> String {
    debug_assert!(pairwise_subject_secret.len() >= 32);
    let mut mac = HmacSha256::new_from_slice(pairwise_subject_secret)
        .expect("pairwise_subject_secret should be valid");
    mac.update(issuer.as_bytes());
    mac.update(b"\x1f");
    mac.update(sector_identifier_host.as_bytes());
    mac.update(b"\x1f");
    mac.update(user_id.to_string().as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn sector_host_from_redirect_uri(redirect_uri: &str) -> String {
    url::Url::parse(redirect_uri)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

pub(crate) fn compute_subject_for_client(
    settings: &Settings,
    user_id: Uuid,
    client_subject_type: &str,
    sector_identifier_host: Option<&str>,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    match client_subject_type {
        "public" => Ok(user_id.to_string()),
        "pairwise" => {
            let host = sector_identifier_host
                .filter(|h| !h.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| sector_host_from_redirect_uri(redirect_uri));
            let secret = settings
                .pairwise_subject_secret
                .as_deref()
                .filter(|secret| secret.len() >= 32)
                .ok_or_else(|| anyhow::anyhow!("PAIRWISE_SUBJECT_SECRET is required"))?;
            Ok(oidc_subject(
                secret.as_bytes(),
                &settings.issuer,
                &host,
                user_id,
            ))
        }
        value => anyhow::bail!("unsupported client subject_type {value}"),
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
    _sector_identifier_host: Option<&str>,
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
    if requested_claim(requested_claims, name) {
        return true;
    }
    scope_allowed && !claim_requested(requested_claims, requested_claim_requests, name)
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
    sector_identifier_host: Option<&str>,
) -> Value {
    let mut claims = oidc_user_claims(
        user,
        scopes,
        subject,
        requested_claims,
        requested_claim_requests,
        sector_identifier_host,
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
#[path = "../../tests/in_source/src/support/tests/oidc_claims.rs"]
mod tests;
