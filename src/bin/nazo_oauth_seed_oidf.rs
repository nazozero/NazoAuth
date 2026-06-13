#![forbid(unsafe_code)]

use argon2::{Argon2, PasswordHasher};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use diesel::{Connection, PgConnection, RunQueryDsl, sql_query};
use nazo_oauth_server::{config::ConfigSource, database_config::normalize_database_url};
use password_hash::{SaltString, rand_core::OsRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs, path::Path};

const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
const DEFAULT_REALM_ID: &str = "00000000-0000-0000-0000-000000000002";
const DEFAULT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000003";

#[derive(Clone, Copy)]
struct FapiClientPolicy {
    auth_method: &'static str,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    client_credentials_only: bool,
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
    client_secret_hash: Option<&'a str>,
    auth_method: &'a str,
    redirect_uris: &'a Value,
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

fn upsert_client(connection: &mut PgConnection, client: ClientUpsert<'_>) -> anyhow::Result<()> {
    sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id,
            realm_id,
            organization_id,
            client_id,
            client_name,
            client_type,
            client_secret_argon2_hash,
            redirect_uris,
            scopes,
            allowed_audiences,
            grant_types,
            token_endpoint_auth_method,
            require_dpop_bound_tokens,
            require_mtls_bound_tokens,
            tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience,
            require_par_request_object,
            allow_authorization_code_without_pkce,
            jwks,
            is_active
        )
        VALUES (
            $17::uuid, $18::uuid, $19::uuid,
            $1, $2, 'confidential', $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13, $14, $15, $20, $16, TRUE
        )
        ON CONFLICT (tenant_id, client_id) DO UPDATE
        SET client_name = EXCLUDED.client_name,
            client_type = EXCLUDED.client_type,
            client_secret_argon2_hash = EXCLUDED.client_secret_argon2_hash,
            redirect_uris = EXCLUDED.redirect_uris,
            scopes = EXCLUDED.scopes,
            allowed_audiences = EXCLUDED.allowed_audiences,
            grant_types = EXCLUDED.grant_types,
            token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
            require_dpop_bound_tokens = EXCLUDED.require_dpop_bound_tokens,
            require_mtls_bound_tokens = EXCLUDED.require_mtls_bound_tokens,
            tls_client_auth_subject_dn = EXCLUDED.tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256 = EXCLUDED.tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array = EXCLUDED.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience = EXCLUDED.allow_client_assertion_endpoint_audience,
            require_par_request_object = EXCLUDED.require_par_request_object,
            allow_authorization_code_without_pkce = EXCLUDED.allow_authorization_code_without_pkce,
            jwks = EXCLUDED.jwks,
            is_active = TRUE,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind::<diesel::sql_types::VarChar, _>(client.client_id)
    .bind::<diesel::sql_types::VarChar, _>(client.client_name)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(client.client_secret_hash)
    .bind::<diesel::sql_types::Jsonb, _>(client.redirect_uris)
    .bind::<diesel::sql_types::Jsonb, _>(client.scopes)
    .bind::<diesel::sql_types::Jsonb, _>(client.allowed_audiences)
    .bind::<diesel::sql_types::Jsonb, _>(client.grant_types)
    .bind::<diesel::sql_types::VarChar, _>(client.auth_method)
    .bind::<diesel::sql_types::Bool, _>(client.require_dpop_bound_tokens)
    .bind::<diesel::sql_types::Bool, _>(client.require_mtls_bound_tokens)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        client.tls_client_auth_subject_dn,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        client.tls_client_auth_cert_sha256,
    )
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_audience_array)
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_endpoint_audience)
    .bind::<diesel::sql_types::Bool, _>(client.require_par_request_object)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(client.jwks)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_REALM_ID)
    .bind::<diesel::sql_types::VarChar, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<diesel::sql_types::Bool, _>(client.allow_authorization_code_without_pkce)
    .execute(connection)?;
    Ok(())
}

fn string_value<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("OIDF config is missing string field {key}"))
}

fn public_jwks(jwks: &Value) -> anyhow::Result<Value> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("generated OIDF client jwks must contain keys array"))?;
    let public_keys = keys
        .iter()
        .map(|key| {
            let mut object = key
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("generated OIDF jwks key must be an object"))?
                .clone();
            for private_field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
                object.remove(private_field);
            }
            Ok(Value::Object(object))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(json!({ "keys": public_keys }))
}

fn fapi_client_policy(file_name: &str, plan: &Value) -> FapiClientPolicy {
    let nazo = plan.get("nazo").and_then(Value::as_object);
    let client_auth_type = nazo
        .and_then(|value| value.get("client_auth_type"))
        .and_then(Value::as_str)
        .unwrap_or("private_key_jwt");
    let sender_constrain = nazo
        .and_then(|value| value.get("sender_constrain"))
        .and_then(Value::as_str)
        .unwrap_or("dpop");
    let fapi_profile = nazo
        .and_then(|value| value.get("fapi_profile"))
        .and_then(Value::as_str)
        .unwrap_or("plain_fapi");
    FapiClientPolicy {
        auth_method: match client_auth_type {
            "mtls" => "tls_client_auth",
            _ => "private_key_jwt",
        },
        require_dpop_bound_tokens: sender_constrain == "dpop",
        require_mtls_bound_tokens: sender_constrain == "mtls",
        allow_client_assertion_audience_array: file_name.contains("-id"),
        allow_client_assertion_endpoint_audience: file_name.contains("-id"),
        require_par_request_object: file_name.contains("-message-")
            || nazo
                .and_then(|value| value.get("fapi_request_method"))
                .and_then(Value::as_str)
                .is_some(),
        client_credentials_only: fapi_profile == "fapi_client_credentials_grant",
    }
}

fn plan_config_files(runtime_dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(runtime_dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if name.ends_with("-plan-config.json") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn certificate_pem_thumbprint(value: &str) -> anyhow::Result<String> {
    let start = value
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| anyhow::anyhow!("mTLS certificate is missing BEGIN marker"))?;
    let end = value
        .find("-----END CERTIFICATE-----")
        .ok_or_else(|| anyhow::anyhow!("mTLS certificate is missing END marker"))?;
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    let body = value[body_start..end]
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    let der = STANDARD
        .decode(body)
        .map_err(|error| anyhow::anyhow!("mTLS certificate base64 decode failed: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

fn mtls_thumbprint(plan: &Value, key: &str) -> anyhow::Result<Option<String>> {
    let mtls_key = if key == "client2" { "mtls2" } else { "mtls" };
    let Some(cert) = plan
        .get(mtls_key)
        .and_then(|value| value.get("cert"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    Ok(Some(certificate_pem_thumbprint(cert)?))
}

fn client_scopes(client: &serde_json::Map<String, Value>) -> Value {
    let scopes = client
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("openid profile email offline_access")
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    json!(scopes)
}

fn callback_uri(suite_base_url: &str, alias: &str) -> String {
    format!(
        "{}/test/a/{}/callback",
        suite_base_url.trim_end_matches('/'),
        alias
    )
}

fn suite_base_urls(primary_suite_base_url: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    urls.insert(primary_suite_base_url.trim_end_matches('/').to_owned());
    urls.insert("https://www.certification.openid.net".to_owned());

    if let Ok(extra_urls) = env::var("OIDF_LOCAL_EXTRA_SUITE_BASE_URLS") {
        for url in extra_urls.split(',') {
            let url = url.trim().trim_end_matches('/');
            if !url.is_empty() {
                urls.insert(url.to_owned());
            }
        }
    }

    urls.into_iter().collect()
}

fn callback_uris(suite_base_urls: &[String], alias: &str) -> Vec<String> {
    suite_base_urls
        .iter()
        .map(|suite_base_url| callback_uri(suite_base_url, alias))
        .collect()
}

fn read_plan_config(runtime_dir: &Path, file_name: &str) -> anyhow::Result<Value> {
    let path = runtime_dir.join(file_name);
    let body = fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&body)
        .map_err(|error| anyhow::anyhow!("failed to parse {}: {error}", path.display()))
}

fn main() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let database_url = normalize_database_url(&config.string(
        "DATABASE_URL",
        "postgresql://postgres:postgres@127.0.0.1:5432/oauth",
    ));
    let suite_base_url = env_or("OIDF_LOCAL_SUITE_BASE_URL", "https://nginx:8443");
    let suite_base_urls = suite_base_urls(&suite_base_url);
    let issuer = config.string("ISSUER", "https://auth.nazo.run");
    let runtime_dir = env_or("OIDF_LOCAL_RUNTIME_DIR", "runtime/oidf");
    let runtime_dir = Path::new(&runtime_dir);
    let alias = env_or("OIDF_LOCAL_BASIC_ALIAS", "local-nazo-oauth-oidf");
    let user_email = env_or("OIDF_LOCAL_USER_EMAIL", "oidf-local@example.test");
    let user_password = env_or("OIDF_LOCAL_USER_PASSWORD", "oidf-local-password");
    let client_secret = env_or("OIDF_LOCAL_CLIENT_SECRET", "oidf-local-client-secret");
    let basic_redirect_uris = json!(callback_uris(&suite_base_urls, &alias));

    let user_password_hash = hash_password(&user_password)?;
    let client_secret_hash = hash_password(&client_secret)?;
    let mut connection = PgConnection::establish(&database_url)?;
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
        &mut connection,
        ClientUpsert {
            client_id: "local-oidf-basic-client",
            client_name: "Local OIDF Basic Client",
            client_secret_hash: Some(&client_secret_hash),
            auth_method: "client_secret_basic",
            redirect_uris: &basic_redirect_uris,
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
            jwks: None,
        },
    )?;
    upsert_client(
        &mut connection,
        ClientUpsert {
            client_id: "local-oidf-basic-client-2",
            client_name: "Local OIDF Basic Client 2",
            client_secret_hash: Some(&client_secret_hash),
            auth_method: "client_secret_basic",
            redirect_uris: &basic_redirect_uris,
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
            jwks: None,
        },
    )?;
    upsert_client(
        &mut connection,
        ClientUpsert {
            client_id: "local-oidf-post-client",
            client_name: "Local OIDF Post Client",
            client_secret_hash: Some(&client_secret_hash),
            auth_method: "client_secret_post",
            redirect_uris: &basic_redirect_uris,
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
            jwks: None,
        },
    )?;

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
        } else {
            grant_types.clone()
        };
        let client_name = format!("Local OIDF FAPI Client {}", seed.client_id);
        upsert_client(
            &mut connection,
            ClientUpsert {
                client_id: &seed.client_id,
                client_name: &client_name,
                client_secret_hash: None,
                auth_method: seed.policy.auth_method,
                redirect_uris: &fapi_redirect_uris,
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
                jwks: Some(&seed.jwks),
            },
        )?;
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
#[path = "tests/nazo_oauth_seed_oidf.rs"]
mod tests;
