#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod config;
mod db;
mod domain;
mod http;
pub mod keyctl;
pub mod oidf_seed;
pub use nazo_resource_server as resource_server;
mod schema;
mod settings;
mod support;

#[cfg(test)]
pub(crate) mod test_support {
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::jwk::Jwk;
    use openssl::rsa::Rsa;
    use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as _};
    use serde_json::{Value, json};

    pub(crate) struct GeneratedKeyMaterial {
        pub(crate) private_pkcs8_der: Vec<u8>,
    }

    pub(crate) fn test_key_manager() -> nazo_key_management::KeyManager {
        nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA)
    }

    pub(crate) fn test_key_manager_with_algorithm(
        algorithm: jsonwebtoken::Algorithm,
    ) -> nazo_key_management::KeyManager {
        nazo_key_management::KeyManager::for_test(algorithm)
    }

    pub(crate) fn failing_key_manager() -> nazo_key_management::KeyManager {
        nazo_key_management::KeyManager::for_test_behavior(
            jsonwebtoken::Algorithm::EdDSA,
            nazo_key_management::TestSigningBehavior::Failing,
        )
    }

    pub(crate) fn external_failure_key_manager(stderr: &str) -> nazo_key_management::KeyManager {
        nazo_key_management::KeyManager::for_test_behavior(
            jsonwebtoken::Algorithm::EdDSA,
            nazo_key_management::TestSigningBehavior::ExternalFailure {
                stderr: stderr.to_owned(),
            },
        )
    }

    pub(crate) fn test_key_manager_with_auxiliary(
        algorithm: jsonwebtoken::Algorithm,
    ) -> nazo_key_management::KeyManager {
        nazo_key_management::KeyManager::for_test_with_auxiliary(algorithm)
    }

    pub(crate) fn generate_key_material(
        algorithm: jsonwebtoken::Algorithm,
    ) -> anyhow::Result<GeneratedKeyMaterial> {
        let private_pkcs8_der = match algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                let seed: [u8; 32] = rand::random();
                let mut der = vec![
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ];
                der.extend_from_slice(&seed);
                der
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                Rsa::generate(2048)?.private_key_to_der()?
            }
            jsonwebtoken::Algorithm::ES256 => p256::SecretKey::try_generate()?
                .to_pkcs8_der()?
                .as_bytes()
                .to_vec(),
            _ => anyhow::bail!("unsupported test signing algorithm"),
        };
        Ok(GeneratedKeyMaterial { private_pkcs8_der })
    }

    pub(crate) fn public_jwk_from_private_der(
        kid: &str,
        algorithm: jsonwebtoken::Algorithm,
        private_key: &[u8],
    ) -> anyhow::Result<Value> {
        let mut value = match algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                const PREFIX: &[u8] = &[
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ];
                anyhow::ensure!(
                    private_key.len() == PREFIX.len() + 32 && private_key.starts_with(PREFIX),
                    "invalid Ed25519 private key"
                );
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&private_key[PREFIX.len()..]);
                let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(public)})
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                serde_json::to_value(Jwk::from_encoding_key(
                    &jsonwebtoken::EncodingKey::from_rsa_der(private_key),
                    algorithm,
                )?)?
            }
            jsonwebtoken::Algorithm::ES256 => serde_json::to_value(Jwk::from_encoding_key(
                &jsonwebtoken::EncodingKey::from_ec_der(private_key),
                algorithm,
            )?)?,
            _ => anyhow::bail!("unsupported test signing algorithm"),
        };
        value["kid"] = json!(kid);
        value["alg"] = json!(match algorithm {
            jsonwebtoken::Algorithm::EdDSA => "EdDSA",
            jsonwebtoken::Algorithm::RS256 => "RS256",
            jsonwebtoken::Algorithm::PS256 => "PS256",
            jsonwebtoken::Algorithm::ES256 => "ES256",
            _ => unreachable!(),
        });
        value["use"] = json!("sig");
        Ok(value)
    }

    pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
        let encoded = STANDARD.encode(der);
        let mut pem = format!("-----BEGIN {label}-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {label}-----\n"));
        pem
    }
}
