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
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::jwk::Jwk;
    use openssl::rsa::Rsa;
    use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as _};
    use serde_json::{Value, json};

    pub(crate) struct ClientSigningFixture {
        algorithm: jsonwebtoken::Algorithm,
        private_pkcs8_der: Vec<u8>,
    }

    impl ClientSigningFixture {
        pub(crate) fn generate(algorithm: jsonwebtoken::Algorithm) -> anyhow::Result<Self> {
            let private_pkcs8_der = match algorithm {
                jsonwebtoken::Algorithm::EdDSA => {
                    let seed: [u8; 32] = rand::random();
                    let mut der = vec![
                        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                        0x04, 0x22, 0x04, 0x20,
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
            Ok(Self {
                algorithm,
                private_pkcs8_der,
            })
        }

        pub(crate) fn public_jwk(&self, kid: &str) -> Value {
            let mut value = match self.algorithm {
                jsonwebtoken::Algorithm::EdDSA => {
                    const PREFIX: &[u8] = &[
                        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                        0x04, 0x22, 0x04, 0x20,
                    ];
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&self.private_pkcs8_der[PREFIX.len()..]);
                    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                    json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(public)})
                }
                jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                    serde_json::to_value(
                        Jwk::from_encoding_key(
                            &jsonwebtoken::EncodingKey::from_rsa_der(&self.private_pkcs8_der),
                            self.algorithm,
                        )
                        .expect("generated RSA fixture must derive a public JWK"),
                    )
                    .expect("public JWK must serialize")
                }
                jsonwebtoken::Algorithm::ES256 => serde_json::to_value(
                    Jwk::from_encoding_key(
                        &jsonwebtoken::EncodingKey::from_ec_der(&self.private_pkcs8_der),
                        self.algorithm,
                    )
                    .expect("generated EC fixture must derive a public JWK"),
                )
                .expect("public JWK must serialize"),
                _ => panic!("unsupported client signing fixture algorithm"),
            };
            value["kid"] = json!(kid);
            value["alg"] = json!(match self.algorithm {
                jsonwebtoken::Algorithm::EdDSA => "EdDSA",
                jsonwebtoken::Algorithm::RS256 => "RS256",
                jsonwebtoken::Algorithm::PS256 => "PS256",
                jsonwebtoken::Algorithm::ES256 => "ES256",
                _ => unreachable!(),
            });
            value["use"] = json!("sig");
            value
        }

        pub(crate) fn encode_jwt<T: serde::Serialize>(
            &self,
            header: &jsonwebtoken::Header,
            claims: &T,
        ) -> String {
            let encoding_key = match self.algorithm {
                jsonwebtoken::Algorithm::EdDSA => {
                    jsonwebtoken::EncodingKey::from_ed_der(&self.private_pkcs8_der)
                }
                jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                    jsonwebtoken::EncodingKey::from_rsa_der(&self.private_pkcs8_der)
                }
                jsonwebtoken::Algorithm::ES256 => {
                    jsonwebtoken::EncodingKey::from_ec_der(&self.private_pkcs8_der)
                }
                _ => panic!("unsupported client signing fixture algorithm"),
            };
            jsonwebtoken::encode(header, claims, &encoding_key)
                .expect("client fixture JWT should sign")
        }

        pub(crate) fn sign_http_message(&self, signing_input: &[u8]) -> Vec<u8> {
            let encoding_key = match self.algorithm {
                jsonwebtoken::Algorithm::EdDSA => {
                    jsonwebtoken::EncodingKey::from_ed_der(&self.private_pkcs8_der)
                }
                jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                    jsonwebtoken::EncodingKey::from_rsa_der(&self.private_pkcs8_der)
                }
                jsonwebtoken::Algorithm::ES256 => {
                    jsonwebtoken::EncodingKey::from_ec_der(&self.private_pkcs8_der)
                }
                _ => panic!("unsupported client signing fixture algorithm"),
            };
            let encoded = jsonwebtoken::crypto::sign(signing_input, &encoding_key, self.algorithm)
                .expect("client fixture HTTP message should sign");
            URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("fixture signature must be base64url")
        }
    }

    pub(crate) fn client_signing_fixture(
        algorithm: jsonwebtoken::Algorithm,
    ) -> ClientSigningFixture {
        ClientSigningFixture::generate(algorithm).expect("client signing fixture should generate")
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
}
