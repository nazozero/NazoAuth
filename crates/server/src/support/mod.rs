//! 跨 HTTP handler 复用的领域支撑模块。
// 子模块按职责拆分；调用方显式导入所需能力。
mod audit;
mod avatars;
pub(crate) mod client_ip;
pub(crate) mod dpop;
mod email;
mod email_templates;
mod fapi_http_signatures;
mod jwe;
mod mfa;
pub(crate) mod mtls;
mod oauth;
mod oidc_claims;
mod rate_limit;
mod sector_identifier;
pub(crate) mod security;
pub(crate) mod sessions;
mod tenancy;
#[cfg(test)]
mod valkey;
mod views;

#[cfg(test)]
pub(crate) use crate::test_support::{ClientSigningFixture, client_signing_fixture};
pub(crate) use audit::{audit_event, audit_fields};
pub(crate) use avatars::{
    avatar_meta_path, avatar_path, avatar_user_dir, detect_avatar_content_type, read_avatar_meta,
};
pub(crate) use client_ip::{
    ClientIpConfig, ClientIpHeaderMode, IpCidr, client_ip, client_ip_with_config,
    client_ip_with_context, parse_trusted_proxy_cidrs,
};
pub(crate) use dpop::{
    AccessTokenAuthScheme, DpopError, DpopErrorContext, dpop_error_response, dpop_proof_present,
    issue_dpop_nonce, validate_dpop_proof,
};
pub(crate) use email::{
    SmtpVerificationEmailDelivery, email_delivery_configured, normalize_email_address,
};
pub(crate) use fapi_http_signatures::verify_client_http_message;
pub(crate) use jwe::{ClientJweKey, JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
#[cfg(test)]
pub(crate) use mfa::MFA_BACKUP_CODE_COUNT;
pub(crate) use mfa::{
    MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS, MFA_TOTP_DIGITS,
    MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod, clear_user_mfa_state_with_repository,
    generate_backup_codes_and_hashes, remember_mfa_device_with_repository,
    replace_backup_codes_with_repository, verify_user_mfa_code_with_repository,
};
#[cfg(test)]
pub(crate) use mfa::{
    remember_mfa_device, remembered_mfa_device_valid, replace_backup_codes, verify_user_mfa_code,
};
pub(crate) use mtls::{
    client_mtls_certificate_matches, request_mtls_client_certificate,
    request_mtls_client_certificate_from_headers, request_mtls_thumbprint,
    request_mtls_thumbprint_from_trusted_proxy,
};
pub(crate) use nazo_key_management::{signing_algorithm_from_name, signing_algorithm_name};
#[cfg(test)]
pub(crate) use oauth::authorization_code_key;
pub(crate) use oauth::{
    ClientMetadata, ClientMtlsMetadata, RedirectUriError, audiences_allowed, client_supports_grant,
    encoded_resource_indicators, has_duplicate_oauth_parameter, is_subset, is_valid_pkce_value,
    json_array_to_strings, parse_resource_indicators, parse_scope, registered_redirect_uri,
    resource_indicators_from_parameter_value, token_audience_contains, validate_client_metadata,
};
#[cfg(test)]
pub(crate) use oidc_claims::oidc_subject;
pub(crate) use oidc_claims::{
    compute_subject_for_client, oidc_id_token_user_claims, oidc_user_claims, supported_user_claim,
};
pub(crate) use rate_limit::{
    AuthRequestLimiter, RateLimitPolicy, enforce_rate_limit, enforce_rate_limit_with_store,
    rate_limited_response,
};
pub(crate) use sector_identifier::{fetch_sector_identifier_uris, sector_identifier_hostname};
#[cfg(test)]
pub(crate) use security::{
    AccessTokenJwtInput, CLIENT_ASSERTION_TYPE_JWT_BEARER, IssuedAccessToken,
    SUPPORTED_CLIENT_JWT_SIGNING_ALGS, make_jwt,
};
pub(crate) use security::{
    BackchannelLogoutTokenInput, ClientAssertionError, ClientCredentials,
    LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER, PasswordHashingError, PasswordVerificationError,
    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    ValidatedClientAssertion, access_delivery_token, access_token_tenant_id, blake3_hex,
    client_jwt_algorithm_from_name, client_jwt_decoding_key, client_secret_digest,
    configure_password_hash_limits, constant_time_eq, consume_private_key_jwt,
    consume_private_key_jwt_with_authorization_service, decode_access_claims,
    default_password_hash_max_concurrency, default_password_hash_queue_timeout_ms,
    dummy_password_hash, extract_client_credentials,
    extract_client_credentials_with_trusted_proxies, has_basic_authorization_scheme,
    hash_client_secret, hash_password, hash_password_blocking_limited,
    initialize_dummy_password_hash, jwt_decoding_key_from_jwk, make_backchannel_logout_token,
    pkce_s256, random_urlsafe_token, sign_response_jwt, supported_client_jwt_algorithm_name,
    verify_password_blocking_limited, verify_private_key_jwt_claims,
    verify_private_key_jwt_claims_for_issuer,
};
pub(crate) use sessions::{
    CurrentSession, SessionRotation, current_session, current_user_or_login_required,
    has_valid_csrf_token, require_admin_or_forbidden,
};
#[cfg(test)]
pub(crate) use sessions::{SessionPayload, require_active_session_principal, store_session};
#[cfg(test)]
pub(crate) use tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID};
pub(crate) use tenancy::{DEFAULT_TENANT_ID, default_tenant_context};
#[cfg(test)]
pub(crate) use valkey::{
    valkey_atomic_snapshot, valkey_del, valkey_eval_string, valkey_get, valkey_set_ex,
};
pub(crate) use views::{
    admin_user_json, append_query, auth_me_json, auth_me_json_with_count, client_json,
    is_cross_site_fetch, pagination,
};
