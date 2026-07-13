#![cfg_attr(not(test), allow(dead_code))]

use anyhow::{Context, bail};
use uuid::Uuid;

use crate::domain::ClientRow;

pub(crate) fn verify_client_http_message(
    client: &ClientRow,
    tenant_id: Uuid,
    client_id: &str,
    kid: &str,
    algorithm: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    if client.tenant_id != tenant_id || client.client_id != client_id {
        bail!("HTTP signature client binding mismatch");
    }
    let jwks = client
        .jwks
        .as_ref()
        .context("client has no usable JWK set")?;
    nazo_http_signatures::verify_jwk_signature(jwks, kid, algorithm, signing_input, signature)
        .context("client JWK HTTP signature verification failed")
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/fapi_http_signatures.rs"]
mod tests;
