//! External signer boundary for active JWT signing keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time;

use super::signing_algorithm_name;
use crate::domain::ExternalSigningKey;

pub(super) async fn sign_external_jwt_input(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
    public_jwk: &Value,
) -> jsonwebtoken::errors::Result<String> {
    let alg_name =
        signing_algorithm_name(alg).ok_or(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
    let request = json!({
        "version": 1,
        "kid": kid,
        "alg": alg_name,
        "key_ref": external.key_ref,
        "signing_input": signing_input
    });
    let mut child = Command::new(
        external
            .command
            .as_slice()
            .first()
            .ok_or_else(|| jwt_provider_error("external signer command is empty"))?,
    )
    .args(external.command.iter().skip(1))
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .map_err(|error| jwt_provider_error(format!("failed to spawn external signer: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdin unavailable"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdout unavailable"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stderr unavailable"))?;
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).await.map(|_| output)
    });
    stdin
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .await
        .map_err(|error| {
            jwt_provider_error(format!("failed to write external signer request: {error}"))
        })?;
    drop(stdin);
    let status = match time::timeout(external.timeout, child.wait()).await {
        Ok(result) => result
            .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?,
        Err(_) => {
            let _ = child.kill().await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stdout join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    let stderr = stderr_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stderr join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    if !status.success() {
        return Err(jwt_provider_error(format!(
            "external signer exited with status {}: {}",
            status,
            String::from_utf8_lossy(&stderr)
        )));
    }
    let response: Value = serde_json::from_slice(&stdout)?;
    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| jwt_provider_error("external signer response missing signature"))?;
    let decoded = URL_SAFE_NO_PAD.decode(signature).map_err(|error| {
        jwt_provider_error(format!(
            "external signer returned invalid signature: {error}"
        ))
    })?;
    if decoded.is_empty() {
        return Err(jwt_provider_error(
            "external signer returned empty signature",
        ));
    }
    verify_external_jwt_signature(external, kid, alg, signing_input, signature, public_jwk)?;
    Ok(signature.to_owned())
}

fn verify_external_jwt_signature(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
    signature: &str,
    public_jwk: &Value,
) -> jsonwebtoken::errors::Result<()> {
    let decoding_key =
        super::super::jwt_decoding_key_from_jwk(public_jwk, alg).ok_or_else(|| {
            jwt_provider_error("active external signer public JWK is not usable for verification")
        })?;
    match jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), &decoding_key, alg) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => {
            tracing::error!(
                kid,
                alg = ?alg,
                key_ref = %external.key_ref,
                "external signer returned a signature that failed local verification"
            );
            Err(jwt_provider_error(
                "external signer returned signature that does not verify with active public JWK",
            ))
        }
    }
}

pub(super) fn jwt_provider_error(message: impl Into<String>) -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::ErrorKind::Provider(message.into()).into()
}
