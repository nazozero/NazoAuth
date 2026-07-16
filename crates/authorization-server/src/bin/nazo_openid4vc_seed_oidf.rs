#![forbid(unsafe_code)]

//! Deployment-time seeding of the two bounded OpenID4VC OIDF client classes.
//!
//! This binary is intentionally excluded from the production runtime image.
//! It consumes the exact materialized plan bundle used by the runner and
//! atomically upserts only those clients.

use std::{env, fs};

use nazo_oauth_server::{
    config::{ConfigSource, database_url},
    oidf_seed::{
        client::{OidfClientSpec, oauth_client},
        openid4vc::client_seeds,
        suite_base_urls,
    },
};
use nazo_postgres::OidfSeedClient;
use serde_json::{Value, json};

fn required_env(name: &str) -> anyhow::Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let database_url = database_url(&config);
    let issuer = config.string("ISSUER", "https://auth.nazo.run");
    let suite_base_url = env::var("OIDF_LOCAL_SUITE_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://localhost:8443".to_owned());
    let plan_bundle_path = required_env("OPENID4VC_OIDF_PLAN_CONFIG_JSON_FILE")?;
    let bundle: Value = serde_json::from_str(&fs::read_to_string(&plan_bundle_path)?)?;
    let seeds = client_seeds(&bundle, &suite_base_urls(&suite_base_url))?;
    let allowed_audiences = json!([
        issuer,
        format!("{issuer}/openid4vci/credential"),
        format!("{issuer}/openid4vci/batch_credential")
    ]);
    let grant_types = json!([
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ]);
    let empty = json!([]);
    let mut clients = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let redirect_uris = json!(seed.redirect_uris);
        let scopes = json!(seed.scopes);
        let client_name = format!("OpenID4VC OIDF {} client", seed.auth_method);
        clients.push(OidfSeedClient {
            client: oauth_client(OidfClientSpec {
                client_id: &seed.client_id,
                client_name: &client_name,
                auth_method: &seed.auth_method,
                redirect_uris: &redirect_uris,
                post_logout_redirect_uris: &empty,
                scopes: &scopes,
                allowed_audiences: &allowed_audiences,
                grant_types: &grant_types,
                require_dpop_bound_tokens: true,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                require_mtls_bound_tokens: false,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                jwks: seed.jwks.as_ref(),
                authorization_signed_response_alg: None,
                backchannel_token_delivery_mode: "poll",
                backchannel_client_notification_endpoint: None,
                backchannel_authentication_request_signing_alg: None,
            })?,
            client_secret_hash: None,
        });
    }

    let pool = nazo_postgres::create_pool(&database_url, 2)?;
    nazo_postgres::seed_oidf_clients_atomically(&pool, &clients).await?;
    println!(
        "Seeded {} bounded OpenID4VC OIDF client classes.",
        clients.len()
    );
    Ok(())
}
