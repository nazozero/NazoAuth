//! 跨 HTTP handler 复用的领域支撑模块。
// 子模块按职责拆分；调用方显式导入所需能力。
pub(crate) mod audit;
pub(crate) mod client_ip;
pub(crate) mod dpop;
pub(crate) mod email;
mod email_templates;
pub(crate) mod fapi_http_signatures;
pub(crate) mod jwe;
pub(crate) mod mfa;
pub(crate) mod mtls;
pub(crate) mod oauth;
pub(crate) mod oidc_claims;
pub(crate) mod rate_limit;
pub(crate) mod sector_identifier;
pub(crate) mod security;
pub(crate) mod sessions;
pub(crate) mod tenancy;
#[cfg(test)]
pub(crate) mod valkey;
pub(crate) mod views;

#[cfg(test)]
pub(crate) use crate::test_support::{ClientSigningFixture, client_signing_fixture};
#[cfg(test)]
pub(crate) use client_ip::IpCidr;
#[cfg(test)]
pub(crate) use email::normalize_email_address;
#[cfg(test)]
pub(crate) use mfa::{
    MFA_REMEMBERED_COOKIE_NAME, remember_mfa_device, replace_backup_codes, verify_user_mfa_code,
};
#[cfg(test)]
pub(crate) use mtls::request_mtls_thumbprint;
#[cfg(test)]
pub(crate) use oauth::json_array_to_strings;
#[cfg(test)]
pub(crate) use oidc_claims::oidc_subject;
#[cfg(test)]
pub(crate) use rate_limit::{RateLimitPolicy, TokenManagementRequestLimiter, enforce_rate_limit};
#[cfg(test)]
pub(crate) use security::{
    LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER, SUPPORTED_CLIENT_JWT_SIGNING_ALGS, blake3_hex,
    client_secret_digest, hash_client_secret, hash_password, jwt_decoding_key_from_jwk, pkce_s256,
    random_urlsafe_token,
};
#[cfg(test)]
pub(crate) use sessions::{SessionPayload, current_session};
#[cfg(test)]
pub(crate) use tenancy::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, default_tenant_context,
};
#[cfg(test)]
pub(crate) use valkey::{
    valkey_atomic_snapshot, valkey_del, valkey_eval_string, valkey_get, valkey_set_ex,
};
