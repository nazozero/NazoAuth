//! JSON view 组装函数。
use nazo_oauth_server::domain::rows::ClientRow;

use actix_web::http::header::HeaderMap;

use nazo_identity::PublicAccount;
use serde::{Serialize, Serializer, ser::SerializeMap};
use std::collections::HashMap;

// 将数据库行转换为前端和管理端直接消费的 JSON 形状。

pub(crate) struct AccountOverviewView<'a> {
    user: &'a PublicAccount,
    count: i64,
}

pub(crate) fn auth_me_json_with_count(user: &PublicAccount, count: i64) -> AccountOverviewView<'_> {
    AccountOverviewView { user, count }
}

impl Serialize for AccountOverviewView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self { user, count } = self;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("id", &user.id())?;
        map.serialize_entry("email", &user.account.email)?;
        map.serialize_entry("display_name", &user.profile.display_name)?;
        map.serialize_entry("avatar_url", &user.profile.avatar_url)?;
        map.serialize_entry("given_name", &user.profile.given_name)?;
        map.serialize_entry("family_name", &user.profile.family_name)?;
        map.serialize_entry("middle_name", &user.profile.middle_name)?;
        map.serialize_entry("nickname", &user.profile.nickname)?;
        map.serialize_entry("profile_url", &user.profile.profile_url)?;
        map.serialize_entry("website_url", &user.profile.website_url)?;
        map.serialize_entry("gender", &user.profile.gender)?;
        map.serialize_entry("birthdate", &user.profile.birthdate)?;
        map.serialize_entry("zoneinfo", &user.profile.zoneinfo)?;
        map.serialize_entry("locale", &user.profile.locale)?;
        map.serialize_entry("address_formatted", &user.profile.address.formatted)?;
        map.serialize_entry(
            "address_street_address",
            &user.profile.address.street_address,
        )?;
        map.serialize_entry("address_locality", &user.profile.address.locality)?;
        map.serialize_entry("address_region", &user.profile.address.region)?;
        map.serialize_entry("address_postal_code", &user.profile.address.postal_code)?;
        map.serialize_entry("address_country", &user.profile.address.country)?;
        map.serialize_entry("phone_number", &user.profile.phone_number)?;
        map.serialize_entry("phone_number_verified", &user.profile.phone_number_verified)?;
        map.serialize_entry("mfa_enabled", &user.account.mfa_enabled)?;
        map.serialize_entry("role", &user.role_name())?;
        map.serialize_entry("admin_level", &user.admin_level())?;
        map.serialize_entry("authorized_app_count", &count)?;
        map.end()
    }
}

pub(crate) fn is_cross_site_fetch(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false)
}

pub(crate) struct AdminUserView<'a>(&'a PublicAccount);

pub(crate) fn admin_user_json(user: &PublicAccount) -> AdminUserView<'_> {
    AdminUserView(user)
}

impl Serialize for AdminUserView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let user = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("id", &user.id())?;
        map.serialize_entry("email", &user.account.email)?;
        map.serialize_entry("display_name", &user.profile.display_name)?;
        map.serialize_entry("given_name", &user.profile.given_name)?;
        map.serialize_entry("family_name", &user.profile.family_name)?;
        map.serialize_entry("middle_name", &user.profile.middle_name)?;
        map.serialize_entry("nickname", &user.profile.nickname)?;
        map.serialize_entry("profile_url", &user.profile.profile_url)?;
        map.serialize_entry("website_url", &user.profile.website_url)?;
        map.serialize_entry("gender", &user.profile.gender)?;
        map.serialize_entry("birthdate", &user.profile.birthdate)?;
        map.serialize_entry("zoneinfo", &user.profile.zoneinfo)?;
        map.serialize_entry("locale", &user.profile.locale)?;
        map.serialize_entry("address_formatted", &user.profile.address.formatted)?;
        map.serialize_entry(
            "address_street_address",
            &user.profile.address.street_address,
        )?;
        map.serialize_entry("address_locality", &user.profile.address.locality)?;
        map.serialize_entry("address_region", &user.profile.address.region)?;
        map.serialize_entry("address_postal_code", &user.profile.address.postal_code)?;
        map.serialize_entry("address_country", &user.profile.address.country)?;
        map.serialize_entry("phone_number", &user.profile.phone_number)?;
        map.serialize_entry("phone_number_verified", &user.profile.phone_number_verified)?;
        map.serialize_entry("mfa_enabled", &user.account.mfa_enabled)?;
        map.serialize_entry("is_active", &user.principal.active)?;
        map.serialize_entry("role", &user.role_name())?;
        map.serialize_entry("admin_level", &user.admin_level())?;
        map.serialize_entry("created_at", &user.created_at)?;
        map.end()
    }
}

pub(crate) struct ClientView<'a>(&'a ClientRow);

pub(crate) fn client_json(client: &ClientRow) -> ClientView<'_> {
    ClientView(client)
}

impl Serialize for ClientView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let client = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("client_id", &client.client_id)?;
        map.serialize_entry("client_name", &client.client_name)?;
        map.serialize_entry("client_type", &client.client_type)?;
        map.serialize_entry("redirect_uris", &client.redirect_uris)?;
        map.serialize_entry(
            "post_logout_redirect_uris",
            &client.post_logout_redirect_uris,
        )?;
        map.serialize_entry("scopes", &client.scopes)?;
        map.serialize_entry("allowed_audiences", &client.allowed_audiences)?;
        map.serialize_entry("grant_types", &client.grant_types)?;
        map.serialize_entry(
            "token_endpoint_auth_method",
            &client.token_endpoint_auth_method,
        )?;
        map.serialize_entry(
            "require_dpop_bound_tokens",
            &client.require_dpop_bound_tokens,
        )?;
        map.serialize_entry("subject_type", &client.subject_type)?;
        map.serialize_entry("sector_identifier_uri", &client.sector_identifier_uri)?;
        map.serialize_entry("sector_identifier_host", &client.sector_identifier_host)?;
        map.serialize_entry("jwks_uri", &client.jwks_uri)?;
        map.serialize_entry("request_uris", &client.request_uris)?;
        map.serialize_entry("initiate_login_uri", &client.initiate_login_uri)?;
        map.serialize_entry(
            "require_mtls_bound_tokens",
            &client.require_mtls_bound_tokens,
        )?;
        map.serialize_entry(
            "tls_client_auth_subject_dn",
            &client.tls_client_auth_subject_dn,
        )?;
        map.serialize_entry(
            "tls_client_auth_cert_sha256",
            &client.tls_client_auth_cert_sha256,
        )?;
        map.serialize_entry("tls_client_auth_san_dns", &client.tls_client_auth_san_dns)?;
        map.serialize_entry("tls_client_auth_san_uri", &client.tls_client_auth_san_uri)?;
        map.serialize_entry("tls_client_auth_san_ip", &client.tls_client_auth_san_ip)?;
        map.serialize_entry(
            "tls_client_auth_san_email",
            &client.tls_client_auth_san_email,
        )?;
        map.serialize_entry(
            "allow_client_assertion_audience_array",
            &client.allow_client_assertion_audience_array,
        )?;
        map.serialize_entry(
            "allow_client_assertion_endpoint_audience",
            &client.allow_client_assertion_endpoint_audience,
        )?;
        map.serialize_entry(
            "require_par_request_object",
            &client.require_par_request_object,
        )?;
        map.serialize_entry("backchannel_logout_uri", &client.backchannel_logout_uri)?;
        map.serialize_entry(
            "backchannel_logout_session_required",
            &client.backchannel_logout_session_required,
        )?;
        map.serialize_entry("frontchannel_logout_uri", &client.frontchannel_logout_uri)?;
        map.serialize_entry(
            "frontchannel_logout_session_required",
            &client.frontchannel_logout_session_required,
        )?;
        map.serialize_entry("is_active", &client.is_active)?;
        map.serialize_entry("jwks", &client.jwks)?;
        map.serialize_entry(
            "introspection_encrypted_response_alg",
            &client.introspection_encrypted_response_alg,
        )?;
        map.serialize_entry(
            "introspection_encrypted_response_enc",
            &client.introspection_encrypted_response_enc,
        )?;
        map.serialize_entry(
            "userinfo_signed_response_alg",
            &client.userinfo_signed_response_alg,
        )?;
        map.serialize_entry(
            "userinfo_encrypted_response_alg",
            &client.userinfo_encrypted_response_alg,
        )?;
        map.serialize_entry(
            "userinfo_encrypted_response_enc",
            &client.userinfo_encrypted_response_enc,
        )?;
        map.serialize_entry(
            "authorization_signed_response_alg",
            &client.authorization_signed_response_alg,
        )?;
        map.serialize_entry(
            "authorization_encrypted_response_alg",
            &client.authorization_encrypted_response_alg,
        )?;
        map.serialize_entry(
            "authorization_encrypted_response_enc",
            &client.authorization_encrypted_response_enc,
        )?;
        map.serialize_entry(
            "id_token_signed_response_alg",
            &client.id_token_signed_response_alg,
        )?;
        map.serialize_entry(
            "id_token_encrypted_response_alg",
            &client.id_token_encrypted_response_alg,
        )?;
        map.serialize_entry(
            "id_token_encrypted_response_enc",
            &client.id_token_encrypted_response_enc,
        )?;
        map.serialize_entry(
            "request_object_signing_alg",
            &client.request_object_signing_alg,
        )?;
        map.serialize_entry(
            "request_object_encryption_alg",
            &client.request_object_encryption_alg,
        )?;
        map.serialize_entry(
            "request_object_encryption_enc",
            &client.request_object_encryption_enc,
        )?;
        map.serialize_entry(
            "token_endpoint_auth_signing_alg",
            &client.token_endpoint_auth_signing_alg,
        )?;
        map.serialize_entry(
            "introspection_signed_response_alg",
            &client.introspection_signed_response_alg,
        )?;
        map.serialize_entry(
            "backchannel_token_delivery_mode",
            &client.backchannel_token_delivery_mode,
        )?;
        map.serialize_entry(
            "backchannel_client_notification_endpoint",
            &client.backchannel_client_notification_endpoint,
        )?;
        map.serialize_entry(
            "backchannel_authentication_request_signing_alg",
            &client.backchannel_authentication_request_signing_alg,
        )?;
        map.serialize_entry("security_policy", &client.security_policy)?;
        map.serialize_entry("backchannel_user_code_parameter", &false)?;
        map.end()
    }
}

pub(crate) fn pagination(q: &HashMap<String, String>) -> (i32, i32, i32) {
    let page = q
        .get("page")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1);
    let page_size = q
        .get("page_size")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20)
        .min(100);
    let offset = (page - 1) * page_size;
    (page, page_size, offset)
}

#[cfg(test)]
#[path = "../../tests/unit/http/views.rs"]
mod tests;
