#![forbid(unsafe_code)]

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::{Connection, PgConnection, RunQueryDsl, sql_query};
use hmac::{Hmac, KeyInit, Mac};
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_oauth_server::config::{ConfigSource, database_url};
use nazo_oauth_server::oidf_seed::{
    callback_uris, config::client_scopes, config::mtls_thumbprint, config::plan_config_files,
    config::public_jwks, config::read_plan_config, config::string_value, seed_client_secret_pepper,
    suite_base_urls, test_endpoint_uri, test_endpoint_uris,
};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeSet, env, path::Path};
use uuid::Uuid;

const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
const DEFAULT_REALM_ID: &str = "00000000-0000-0000-0000-000000000002";
const DEFAULT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000003";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct FapiClientPolicy {
    auth_method: &'static str,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    client_credentials_only: bool,
    ciba: bool,
}

struct FapiClientSeed {
    client_id: String,
    jwks: Value,
    scopes: Value,
    policy: FapiClientPolicy,
    tls_client_auth_cert_sha256: Option<String>,
}

struct ClientUpsert<'a> {
    client_id: &'a str,
    client_name: &'a str,
    auth_method: &'a str,
    redirect_uris: &'a Value,
    post_logout_redirect_uris: &'a Value,
    scopes: &'a Value,
    allowed_audiences: &'a Value,
    grant_types: &'a Value,
    require_dpop_bound_tokens: bool,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    allow_authorization_code_without_pkce: bool,
    require_mtls_bound_tokens: bool,
    tls_client_auth_subject_dn: Option<&'a str>,
    tls_client_auth_cert_sha256: Option<&'a str>,
    frontchannel_logout_uri: Option<&'a str>,
    frontchannel_logout_session_required: bool,
    jwks: Option<&'a Value>,
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("password hash failed: {error}"))?
        .to_string())
}

fn hash_client_secret(secret: &str, pepper: &str) -> String {
    let salt = env_or(
        "OIDF_LOCAL_CLIENT_SECRET_SALT",
        "oidf-local-client-secret-salt",
    );
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(secret.as_bytes());
    format!(
        "client-secret-v1:{salt}:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn upsert_user(
    connection: &mut PgConnection,
    email: &str,
    password_hash: &str,
) -> anyhow::Result<()> {
    sql_query(
        r#"
        INSERT INTO users (
            tenant_id,
            realm_id,
            organization_id,
            username,
            email,
            password_hash,
            is_active,
            email_verified,
            role,
            admin_level,
            display_name,
            given_name,
            family_name,
            middle_name,
            nickname,
            profile_url,
            avatar_url,
            website_url,
            gender,
            birthdate,
            zoneinfo,
            locale,
            address_formatted,
            address_street_address,
            address_locality,
            address_region,
            address_postal_code,
            address_country,
            phone_number,
            phone_number_verified
        )
        VALUES (
            $3::uuid,
            $4::uuid,
            $5::uuid,
            'oidf_local_user',
            $1,
            $2,
            TRUE,
            TRUE,
            'user',
            0,
            'OIDF Local User',
            'OIDF',
            'Local',
            'Conformance',
            'oidf',
            'https://auth.nazo.run/profile/oidf-local',
            'https://auth.nazo.run/avatar/oidf-local.png',
            'https://auth.nazo.run/',
            'unspecified',
            '2000-01-01',
            'Asia/Shanghai',
            'en-US',
            'OIDF Local Test Address',
            '1 Conformance Way',
            'Test City',
            'CA',
            '94000',
            'US',
            '+15555550100',
            TRUE
        )
        ON CONFLICT (tenant_id, email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            is_active = TRUE,
            email_verified = TRUE,
            display_name = 'OIDF Local User',
            given_name = 'OIDF',
            family_name = 'Local',
            middle_name = 'Conformance',
            nickname = 'oidf',
            profile_url = 'https://auth.nazo.run/profile/oidf-local',
            avatar_url = 'https://auth.nazo.run/avatar/oidf-local.png',
            website_url = 'https://auth.nazo.run/',
            gender = 'unspecified',
            birthdate = '2000-01-01',
            zoneinfo = 'Asia/Shanghai',
            locale = 'en-US',
            address_formatted = 'OIDF Local Test Address',
            address_street_address = '1 Conformance Way',
            address_locality = 'Test City',
            address_region = 'CA',
            address_postal_code = '94000',
            address_country = 'US',
            phone_number = '+15555550100',
            phone_number_verified = TRUE,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind::<diesel::sql_types::VarChar, _>(email)
    .bind::<diesel::sql_types::VarChar, _>(password_hash)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_REALM_ID)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_ORGANIZATION_ID)
    .execute(connection)?;
    Ok(())
}

async fn upsert_client(
    repository: &nazo_postgres::OAuthClientRepository,
    client: ClientUpsert<'_>,
    client_secret_hash: Option<&str>,
) -> anyhow::Result<()> {
    let string_array = |value: &Value| -> anyhow::Result<Vec<String>> {
        serde_json::from_value(value.clone()).map_err(Into::into)
    };
    let client = OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID.parse()?,
        realm_id: DEFAULT_REALM_ID.parse()?,
        organization_id: DEFAULT_ORGANIZATION_ID.parse()?,
        registration: ValidatedClientRegistration {
            client_id: client.client_id.to_owned(),
            client_name: client.client_name.to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: string_array(client.redirect_uris)?,
            post_logout_redirect_uris: string_array(client.post_logout_redirect_uris)?,
            scopes: string_array(client.scopes)?,
            allowed_audiences: string_array(client.allowed_audiences)?,
            grant_types: string_array(client.grant_types)?,
            token_endpoint_auth_method: client.auth_method.to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: client.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: client.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience: client
                .allow_client_assertion_endpoint_audience,
            require_par_request_object: client.require_par_request_object,
            allow_authorization_code_without_pkce: client.allow_authorization_code_without_pkce,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            frontchannel_logout_uri: client.frontchannel_logout_uri.map(ToOwned::to_owned),
            frontchannel_logout_session_required: client.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: client.tls_client_auth_subject_dn.map(ToOwned::to_owned),
            tls_client_auth_cert_sha256: client.tls_client_auth_cert_sha256.map(ToOwned::to_owned),
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks: client.jwks.cloned(),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        },
        require_mtls_bound_tokens: client.require_mtls_bound_tokens,
        is_active: true,
    };
    repository.upsert(&client, client_secret_hash).await?;
    Ok(())
}

fn fapi_client_policy(file_name: &str, plan: &Value) -> FapiClientPolicy {
    let nazo = plan.get("nazo").and_then(Value::as_object);
    let ciba = file_name.starts_with("oidf-fapi-ciba-");
    let client_auth_type = nazo
        .and_then(|value| value.get("client_auth_type"))
        .and_then(Value::as_str)
        .unwrap_or("private_key_jwt");
    let sender_constrain = nazo
        .and_then(|value| value.get("sender_constrain"))
        .and_then(Value::as_str)
        .unwrap_or(if ciba { "mtls" } else { "dpop" });
    let fapi_profile = nazo
        .and_then(|value| value.get("fapi_profile"))
        .and_then(Value::as_str)
        .unwrap_or("plain_fapi");
    let auth_method = match client_auth_type {
        "mtls" => "tls_client_auth",
        _ => "private_key_jwt",
    };
    FapiClientPolicy {
        auth_method,
        require_dpop_bound_tokens: sender_constrain == "dpop",
        require_mtls_bound_tokens: sender_constrain == "mtls",
        allow_client_assertion_audience_array: file_name.contains("-id"),
        allow_client_assertion_endpoint_audience: ciba && auth_method == "private_key_jwt",
        require_par_request_object: ciba
            || file_name.contains("-message-")
            || nazo
                .and_then(|value| value.get("fapi_request_method"))
                .and_then(Value::as_str)
                .is_some(),
        client_credentials_only: fapi_profile == "fapi_client_credentials_grant",
        ciba,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let database_url = database_url(&config);
    let suite_base_url = env_or("OIDF_LOCAL_SUITE_BASE_URL", "https://nginx:8443");
    let suite_base_urls = suite_base_urls(&suite_base_url);
    let issuer = config.string("ISSUER", "https://auth.nazo.run");
    let runtime_dir = env_or("OIDF_LOCAL_RUNTIME_DIR", "runtime/oidf");
    let runtime_dir = Path::new(&runtime_dir);
    let alias = env_or("OIDF_LOCAL_BASIC_ALIAS", "local-nazo-oauth-oidf");
    let frontchannel_alias = format!("{alias}-frontchannel-logout");
    let session_alias = format!("{alias}-session-management");
    let user_email = env_or("OIDF_LOCAL_USER_EMAIL", "oidf-local@example.test");
    let user_password = env_or("OIDF_LOCAL_USER_PASSWORD", "oidf-local-password");
    let client_secret = env_or("OIDF_LOCAL_CLIENT_SECRET", "oidf-local-client-secret");
    let client_secret_pepper = seed_client_secret_pepper(&config);
    let basic_redirect_uris = json!(callback_uris(&suite_base_urls, &alias));
    let empty_post_logout_redirect_uris = json!([]);
    let frontchannel_redirect_uris = json!(callback_uris(&suite_base_urls, &frontchannel_alias));
    let frontchannel_post_logout_redirect_uris = json!(test_endpoint_uris(
        &suite_base_urls,
        &frontchannel_alias,
        "post_logout_redirect"
    ));
    let frontchannel_logout_uri =
        test_endpoint_uri(&suite_base_url, &frontchannel_alias, "frontchannel_logout");
    let session_redirect_uris = json!(callback_uris(&suite_base_urls, &session_alias));
    let session_post_logout_redirect_uris = json!(test_endpoint_uris(
        &suite_base_urls,
        &session_alias,
        "post_logout_redirect"
    ));

    let user_password_hash = hash_password(&user_password)?;
    let client_secret_hash = hash_client_secret(&client_secret, &client_secret_pepper);
    let mut connection = PgConnection::establish(&database_url)?;
    let client_repository =
        nazo_postgres::OAuthClientRepository::new(nazo_postgres::create_pool(&database_url, 2)?);
    let default_scopes = json!([
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access"
    ]);
    let allowed_audiences = json!(["resource://default", format!("{issuer}/userinfo")]);
    let grant_types = json!(["authorization_code", "refresh_token"]);

    upsert_user(&mut connection, &user_email, &user_password_hash)?;
    upsert_client(
        &client_repository,
        ClientUpsert {
            client_id: "local-oidf-basic-client",
            client_name: "Local OIDF Basic Client",
            auth_method: "client_secret_basic",
            redirect_uris: &basic_redirect_uris,
            post_logout_redirect_uris: &empty_post_logout_redirect_uris,
            scopes: &default_scopes,
            allowed_audiences: &allowed_audiences,
            grant_types: &grant_types,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            jwks: None,
        },
        Some(&client_secret_hash),
    )
    .await?;
    upsert_client(
        &client_repository,
        ClientUpsert {
            client_id: "local-oidf-basic-client-2",
            client_name: "Local OIDF Basic Client 2",
            auth_method: "client_secret_basic",
            redirect_uris: &basic_redirect_uris,
            post_logout_redirect_uris: &empty_post_logout_redirect_uris,
            scopes: &default_scopes,
            allowed_audiences: &allowed_audiences,
            grant_types: &grant_types,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            jwks: None,
        },
        Some(&client_secret_hash),
    )
    .await?;
    upsert_client(
        &client_repository,
        ClientUpsert {
            client_id: "local-oidf-post-client",
            client_name: "Local OIDF Post Client",
            auth_method: "client_secret_post",
            redirect_uris: &basic_redirect_uris,
            post_logout_redirect_uris: &empty_post_logout_redirect_uris,
            scopes: &default_scopes,
            allowed_audiences: &allowed_audiences,
            grant_types: &grant_types,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            jwks: None,
        },
        Some(&client_secret_hash),
    )
    .await?;
    upsert_client(
        &client_repository,
        ClientUpsert {
            client_id: "local-oidf-frontchannel-client",
            client_name: "Local OIDF Front-Channel Logout Client",
            auth_method: "client_secret_basic",
            redirect_uris: &frontchannel_redirect_uris,
            post_logout_redirect_uris: &frontchannel_post_logout_redirect_uris,
            scopes: &default_scopes,
            allowed_audiences: &allowed_audiences,
            grant_types: &grant_types,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            frontchannel_logout_uri: Some(&frontchannel_logout_uri),
            frontchannel_logout_session_required: true,
            jwks: None,
        },
        Some(&client_secret_hash),
    )
    .await?;
    upsert_client(
        &client_repository,
        ClientUpsert {
            client_id: "local-oidf-session-client",
            client_name: "Local OIDF Session Management Client",
            auth_method: "client_secret_basic",
            redirect_uris: &session_redirect_uris,
            post_logout_redirect_uris: &session_post_logout_redirect_uris,
            scopes: &default_scopes,
            allowed_audiences: &allowed_audiences,
            grant_types: &grant_types,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: true,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            jwks: None,
        },
        Some(&client_secret_hash),
    )
    .await?;

    let mut fapi_redirect_uris = BTreeSet::new();
    let mut fapi_clients = Vec::<FapiClientSeed>::new();
    let plan_config_files = plan_config_files(runtime_dir)?;
    for file_name in &plan_config_files {
        let plan = read_plan_config(runtime_dir, file_name)?;
        let alias = string_value(&plan, "alias")?;
        if file_name != "oidf-oidcc-config-plan-config.json" {
            for callback in callback_uris(&suite_base_urls, alias) {
                fapi_redirect_uris.insert(callback.clone());
                fapi_redirect_uris.insert(format!("{callback}?dummy1=lorem&dummy2=ipsum"));
            }
        }
        for key in ["client", "client2"] {
            let Some(client) = plan.get(key).and_then(Value::as_object) else {
                continue;
            };
            let Some(jwks) = client.get("jwks") else {
                continue;
            };
            let policy = fapi_client_policy(file_name, &plan);
            let client_id = client
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{file_name}.{key}.client_id is missing"))?
                .to_owned();
            fapi_clients.push(FapiClientSeed {
                client_id,
                jwks: public_jwks(jwks)?,
                scopes: client_scopes(client),
                policy,
                tls_client_auth_cert_sha256: mtls_thumbprint(&plan, key)?,
            });
        }
    }
    let fapi_redirect_uris = json!(fapi_redirect_uris.into_iter().collect::<Vec<_>>());
    fapi_clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
    fapi_clients.dedup_by(|left, right| left.client_id == right.client_id);
    for seed in &fapi_clients {
        let grant_types = if seed.policy.client_credentials_only {
            json!(["client_credentials"])
        } else if seed.policy.ciba {
            json!(["urn:openid:params:grant-type:ciba", "refresh_token"])
        } else {
            grant_types.clone()
        };
        let client_name = format!("Local OIDF FAPI Client {}", seed.client_id);
        upsert_client(
            &client_repository,
            ClientUpsert {
                client_id: &seed.client_id,
                client_name: &client_name,
                auth_method: seed.policy.auth_method,
                redirect_uris: &fapi_redirect_uris,
                post_logout_redirect_uris: &empty_post_logout_redirect_uris,
                scopes: &seed.scopes,
                allowed_audiences: &allowed_audiences,
                grant_types: &grant_types,
                require_dpop_bound_tokens: seed.policy.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: seed
                    .policy
                    .allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: seed
                    .policy
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: seed.policy.require_par_request_object,
                allow_authorization_code_without_pkce: false,
                require_mtls_bound_tokens: seed.policy.require_mtls_bound_tokens,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: seed.tls_client_auth_cert_sha256.as_deref(),
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: true,
                jwks: Some(&seed.jwks),
            },
            None,
        )
        .await?;
    }

    println!("Seeded local OIDF user, OIDC basic clients, and FAPI clients.");
    println!("OIDF_LOCAL_USER_EMAIL={user_email}");
    println!("OIDF_LOCAL_SUITE_BASE_URLS={}", suite_base_urls.join(","));
    println!(
        "OIDF_LOCAL_BASIC_ALIAS={}",
        env_or("OIDF_LOCAL_BASIC_ALIAS", "local-nazo-oauth-oidf")
    );
    println!("OIDF_LOCAL_FAPI_CLIENT_COUNT={}", fapi_clients.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciba_client_policy_without_sender_constrain_defaults_to_mtls_holder_of_key() {
        let policy = fapi_client_policy(
            "oidf-fapi-ciba-plain-private-key-jwt-poll-plan-config.json",
            &json!({"nazo": {"client_auth_type": "private_key_jwt"}}),
        );

        assert!(!policy.require_dpop_bound_tokens);
        assert!(policy.require_mtls_bound_tokens);
        assert!(policy.allow_client_assertion_endpoint_audience);
        assert!(policy.ciba);
    }

    #[test]
    fn fapi_matrix_client_policy_defaults_to_dpop_sender_constraint() {
        let policy = fapi_client_policy(
            "oidf-fapi-matrix-security-final-private-key-jwt-dpop-openid-connect-plain-fapi-plain-response-plan-config.json",
            &json!({"nazo": {"client_auth_type": "private_key_jwt"}}),
        );

        assert!(policy.require_dpop_bound_tokens);
        assert!(!policy.require_mtls_bound_tokens);
        assert!(!policy.allow_client_assertion_endpoint_audience);
        assert!(!policy.ciba);
    }

    #[test]
    fn fapi_matrix_private_key_jwt_mtls_rejects_endpoint_audience() {
        let policy = fapi_client_policy(
            "oidf-fapi-matrix-security-final-private-key-jwt-mtls-openid-connect-plain-fapi-plain-response-plan-config.json",
            &json!({"nazo": {"client_auth_type": "private_key_jwt", "sender_constrain": "mtls"}}),
        );

        assert!(!policy.require_dpop_bound_tokens);
        assert!(policy.require_mtls_bound_tokens);
        assert!(!policy.allow_client_assertion_endpoint_audience);
        assert!(!policy.ciba);
    }
}
