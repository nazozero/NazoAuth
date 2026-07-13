//! 跨 HTTP handler 复用的领域支撑模块。
// 子模块按职责拆分；调用方显式导入所需能力。
mod audit;
mod avatars;
pub(crate) mod client_ip;
mod cookies;
pub(crate) mod dpop;
mod email;
mod email_templates;
mod fapi_http_signatures;
mod jwe;
mod mfa;
pub(crate) mod mtls;
mod oauth;
mod oidc_claims;
mod passkeys;
mod rate_limit;
pub(crate) mod responses;
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
    ClientIpHeaderMode, IpCidr, client_ip, client_ip_with_context, parse_trusted_proxy_cidrs,
};
pub(crate) use cookies::{clear_cookie, cookie_value, make_cookie, with_cookie_headers};
pub(crate) use dpop::{
    AccessTokenAuthScheme, DpopError, DpopErrorContext, dpop_error_response, dpop_proof_present,
    issue_dpop_nonce, validate_dpop_proof,
};
pub(crate) use email::{
    email_delivery_configured, normalize_email_address, parse_email_recipient,
    send_verification_email,
};
pub(crate) use fapi_http_signatures::verify_client_http_message;
pub(crate) use jwe::{ClientJweKey, JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
#[cfg(test)]
pub(crate) use mfa::MFA_BACKUP_CODE_COUNT;
pub(crate) use mfa::{
    MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS, MFA_TOTP_DIGITS,
    MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod, clear_user_mfa_state,
    generate_backup_codes_and_hashes, remember_mfa_device, remembered_mfa_device_valid,
    replace_backup_codes, verify_user_mfa_code,
};
pub(crate) use mtls::{
    client_mtls_certificate_matches, request_mtls_client_certificate, request_mtls_thumbprint,
};
pub(crate) use nazo_key_management::{signing_algorithm_from_name, signing_algorithm_name};
#[cfg(test)]
pub(crate) use oauth::authorization_code_key;
pub(crate) use oauth::{
    ClientMetadata, ClientMtlsMetadata, RedirectUriError, audiences_allowed, client_supports_grant,
    encoded_resource_indicators, has_duplicate_oauth_parameter, is_subset, is_valid_pkce_value,
    json_array_to_strings, parse_resource_indicators, parse_scope, registered_redirect_uri,
    resource_indicators_from_parameter_value, token_audience_allowed, token_audience_contains,
    validate_client_metadata,
};
#[cfg(test)]
pub(crate) use oidc_claims::oidc_subject;
pub(crate) use oidc_claims::{
    compute_subject_for_client, oidc_id_token_user_claims, oidc_user_claims, supported_user_claim,
};
#[cfg(test)]
pub(crate) use passkeys::PASSKEY_CEREMONY_TTL_SECONDS;
pub(crate) use passkeys::{
    StoredPasskeyAuthentication, StoredPasskeyRegistration, authentication_key,
    credential_id_from_response, normalize_ceremony_id, normalize_passkey_label,
    passkey_credential_from_row, passkey_credential_id, passkey_credential_ids,
    passkey_public_json, passkey_user_handle, passkey_webauthn, registration_key,
    store_passkey_ceremony, take_passkey_ceremony,
};
pub(crate) use rate_limit::{
    RateLimitPolicy, clear_login_failures, enforce_login_failure_throttle, enforce_rate_limit,
    enforce_rate_limit_with_store, record_login_failure,
};
pub(crate) use responses::{
    OAuthJsonErrorFields, ResourceAccessToken, authorization_error_response, bytes_response,
    csrf_error, empty_response, empty_response_no_store, has_valid_csrf_token, json_response,
    json_response_no_store, json_response_status, json_response_status_no_store,
    login_required_response, oauth_bearer_error, oauth_error, oauth_token_error, redirect_found,
    request_uses_form_urlencoded, resource_access_token,
};
pub(crate) use sector_identifier::{fetch_sector_identifier_uris, sector_identifier_hostname};
pub(crate) use security::{
    AccessTokenJwtInput, AuthorizationResponseJwtInput, BackchannelLogoutTokenInput,
    ClientAssertionError, ClientCredentials, IdTokenInput, LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    PasswordVerificationError, SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS, ValidatedClientAssertion, access_delivery_token,
    access_token_tenant_id, blake3_hex, client_jwt_algorithm_from_name, client_jwt_decoding_key,
    client_secret_digest, configure_password_hash_limits, constant_time_eq,
    consume_private_key_jwt, decode_access_claims, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, dummy_password_hash, extract_client_credentials,
    has_basic_authorization_scheme, hash_client_secret, hash_password,
    initialize_dummy_password_hash, jwt_decoding_key_from_jwk, make_authorization_response_jwt,
    make_backchannel_logout_token, make_id_token, make_jwt, pkce_s256, random_numeric_code,
    random_urlsafe_token, sign_response_jwt, supported_client_jwt_algorithm_name, verify_password,
    verify_password_blocking_limited, verify_private_key_jwt_claims,
};
#[cfg(test)]
pub(crate) use security::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, IssuedAccessToken, SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
};
pub(crate) use sessions::{
    CurrentSession, SessionPayload, SessionRotation, complete_mfa_session,
    current_pending_mfa_session, current_session, current_user, current_user_or_login_required,
    require_active_session_principal, require_admin_or_forbidden, step_up_current_session,
    store_session,
};
#[cfg(test)]
pub(crate) use tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID};
pub(crate) use tenancy::{DEFAULT_TENANT_ID, default_tenant_context};
#[cfg(test)]
pub(crate) use valkey::{
    valkey_atomic_snapshot, valkey_del, valkey_eval_string, valkey_get, valkey_set_ex,
};
pub(crate) use views::{
    admin_user_json, append_query, auth_me_json, client_json, is_cross_site_fetch, pagination,
};
