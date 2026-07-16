//! OpenID4VC OIDF client materialization for deployment-time seeding.
//!
//! The official suite uses one client class for private-key JWT plans and a
//! different class for attestation-based HAIP plans. Keeping those identities
//! distinct is required because an OAuth client has one registered token
//! endpoint authentication method.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{callback_uris, config::client_scopes, config::public_jwks};

pub const PRIVATE_KEY_CLIENT_ID: &str = "nazo-openid4vc-oidf-private-key-jwt";
pub const ATTESTED_CLIENT_ID: &str = "nazo-openid4vc-oidf-client-attestation";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Openid4vcOidfClientSeed {
    pub client_id: String,
    pub auth_method: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub jwks: Option<Value>,
}

#[derive(Default)]
struct Accumulator {
    auth_method: Option<String>,
    redirect_uris: BTreeSet<String>,
    scopes: BTreeSet<String>,
    jwks: Option<Value>,
}

pub fn client_seeds(
    bundle: &Value,
    suite_base_urls: &[String],
) -> anyhow::Result<Vec<Openid4vcOidfClientSeed>> {
    let configs = bundle
        .get("configs")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("OpenID4VC plan bundle requires a configs object"))?;
    let mut clients = BTreeMap::<String, Accumulator>::new();

    for (filename, config) in configs {
        let nazo = config.get("nazo").and_then(Value::as_object);
        if nazo
            .and_then(|value| value.get("openid4vc_role"))
            .and_then(Value::as_str)
            != Some("issuer")
        {
            continue;
        }
        let alias = config
            .get("alias")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{filename}.alias is missing"))?;
        let client = config
            .get("client")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("{filename}.client is missing"))?;
        let client_id = client
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{filename}.client.client_id is missing"))?;
        let requested_auth = nazo
            .and_then(|value| value.get("client_auth_type"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{filename}.nazo.client_auth_type is missing"))?;
        let auth_method = match requested_auth {
            "private_key_jwt" => "private_key_jwt",
            "client_attestation" => "attest_jwt_client_auth",
            other => anyhow::bail!("{filename} uses unsupported client auth type {other}"),
        };
        let expected_id = if auth_method == "private_key_jwt" {
            PRIVATE_KEY_CLIENT_ID
        } else {
            ATTESTED_CLIENT_ID
        };
        if client_id != expected_id {
            anyhow::bail!("{filename} client_id must be {expected_id} for {requested_auth}");
        }

        let entry = clients.entry(client_id.to_owned()).or_default();
        if entry
            .auth_method
            .as_deref()
            .is_some_and(|existing| existing != auth_method)
        {
            anyhow::bail!("{client_id} is assigned conflicting authentication methods");
        }
        entry.auth_method = Some(auth_method.to_owned());
        entry
            .redirect_uris
            .extend(callback_uris(suite_base_urls, alias));
        let scopes: Vec<String> = serde_json::from_value(client_scopes(client))?;
        entry.scopes.extend(scopes);

        if auth_method == "private_key_jwt" {
            let jwks = client
                .get("jwks")
                .ok_or_else(|| anyhow::anyhow!("{filename}.client.jwks is missing"))?;
            let public = public_jwks(jwks)?;
            if entry
                .jwks
                .as_ref()
                .is_some_and(|existing| existing != &public)
            {
                anyhow::bail!("{client_id} is assigned conflicting client JWK sets");
            }
            entry.jwks = Some(public);
        }
    }

    if clients.len() != 2 {
        anyhow::bail!(
            "OpenID4VC OIDF seed requires exactly private-key and attested client classes"
        );
    }
    clients
        .into_iter()
        .map(|(client_id, entry)| {
            Ok(Openid4vcOidfClientSeed {
                client_id,
                auth_method: entry
                    .auth_method
                    .ok_or_else(|| anyhow::anyhow!("client authentication method is missing"))?,
                redirect_uris: entry.redirect_uris.into_iter().collect(),
                scopes: entry.scopes.into_iter().collect(),
                jwks: entry.jwks,
            })
        })
        .collect()
}
