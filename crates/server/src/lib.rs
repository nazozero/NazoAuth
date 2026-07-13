#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod config;
mod domain;
mod http;
pub mod keyctl;
pub mod oidf_seed;
mod runtime_modules;
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

    pub(crate) fn profile_sessions(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::support::sessions::SessionProfileHandles> {
        actix_web::web::Data::new(
            crate::support::sessions::SessionProfileHandles::from_test_state(state),
        )
    }

    pub(crate) fn account_profiles(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::AccountProfileService> {
        actix_web::web::Data::new(crate::bootstrap::AccountProfileService::new(
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            nazo_postgres::GrantRepository::new(state.diesel_db.clone()),
            nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
        ))
    }

    pub(crate) fn access_request_profiles(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::ClientAccessProfileService> {
        actix_web::web::Data::new(crate::bootstrap::ClientAccessProfileService::new(
            nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone()),
            nazo_valkey::DeliveryStore::new(&state.valkey_connection()),
            &state.settings.protocol.client_secret_pepper,
            &state.settings.endpoint.frontend_base_url,
        ))
    }

    pub(crate) fn delivery_profiles(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::ClientAccessProfileService> {
        access_request_profiles(state)
    }

    pub(crate) fn registration_service(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::LocalRegistrationService> {
        let identity = &state.settings.identity;
        actix_web::web::Data::new(crate::bootstrap::LocalRegistrationService::new(
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
            crate::bootstrap::RegistrationSecretHasher,
            crate::support::SmtpVerificationEmailDelivery::new(state.settings.clone()),
            crate::support::default_tenant_context()
                .as_identity_context()
                .expect("default tenant identifiers are valid"),
            nazo_identity::RegistrationServiceConfig {
                delivery_enabled: crate::support::email_delivery_configured(&state.settings),
                send_peer_cooldown_seconds: identity.email.send_peer_cooldown_seconds,
                send_cooldown_seconds: identity.email.send_cooldown_seconds,
                code_ttl_seconds: identity.email.code_ttl_seconds,
            },
        ))
    }

    pub(crate) fn email_code_http_config(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::http::auth::email_code::EmailCodeHttpConfig> {
        actix_web::web::Data::new(crate::http::auth::email_code::EmailCodeHttpConfig::new(
            state.settings.identity.email_code_dev_response_enabled,
        ))
    }

    pub(crate) fn authentication_service(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::LocalAuthenticationService> {
        let identity = &state.settings.identity;
        let session = &state.settings.session;
        actix_web::web::Data::new(crate::bootstrap::LocalAuthenticationService::new(
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            crate::bootstrap::LoginPasswordVerifier,
            nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            crate::bootstrap::TracingAuthenticationAudit,
            nazo_identity::AuthenticationServiceConfig {
                tenant_id: nazo_identity::TenantId::new(crate::support::DEFAULT_TENANT_ID).unwrap(),
                dummy_password_hash: nazo_identity::PasswordHash::new(
                    crate::support::dummy_password_hash().unwrap(),
                )
                .unwrap(),
                failure_window_seconds: identity.rate_limit.login_failure_window_seconds,
                failure_email_max_attempts: identity.rate_limit.login_failure_email_max_attempts,
                failure_ip_email_max_attempts: identity
                    .rate_limit
                    .login_failure_ip_email_max_attempts,
                session_ttl_seconds: session.session_ttl_seconds,
            },
        ))
    }

    pub(crate) fn login_http_config(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::http::auth::login::LoginHttpConfig> {
        let session = &state.settings.session;
        actix_web::web::Data::new(crate::http::auth::login::LoginHttpConfig::new(
            state.settings.endpoint.issuer.as_str(),
            state.settings.endpoint.frontend_base_url.as_str(),
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.session_ttl_seconds,
            session.cookie_secure,
        ))
    }

    pub(crate) fn passkey_service(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::bootstrap::LocalPasskeyService> {
        let passkey = &state.settings.identity.passkey;
        let session = &state.settings.session;
        actix_web::web::Data::new(crate::bootstrap::LocalPasskeyService::new(
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            nazo_postgres::PasskeyRepository::new(state.diesel_db.clone()),
            nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
            nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            crate::bootstrap::TracingPasskeyAudit,
            nazo_identity::PasskeyServiceConfig {
                tenant_id: nazo_identity::TenantId::new(crate::support::DEFAULT_TENANT_ID).unwrap(),
                rp_id: passkey.rp_id.to_owned(),
                rp_name: passkey.rp_name.to_owned(),
                origin: passkey.origin.to_owned(),
                require_user_verification: passkey.require_user_verification,
                require_user_handle: passkey.require_user_handle,
                strict_base64: passkey.strict_base64,
                ceremony_ttl_seconds: crate::bootstrap::PASSKEY_CEREMONY_TTL_SECONDS,
                session_ttl_seconds: session.session_ttl_seconds,
            },
        ))
    }

    pub(crate) fn passkey_http_config(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::http::auth::passkey::PasskeyHttpConfig> {
        let session = &state.settings.session;
        actix_web::web::Data::new(crate::http::auth::passkey::PasskeyHttpConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.session_ttl_seconds,
            session.cookie_secure,
        ))
    }

    pub(crate) fn auth_request_limiter(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::support::AuthRequestLimiter> {
        let rate_limit = &state.settings.identity.rate_limit;
        actix_web::web::Data::new(crate::support::AuthRequestLimiter::new(
            nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            rate_limit.window_seconds,
            rate_limit.auth_max_requests,
            client_ip_config(state).get_ref().clone(),
        ))
    }

    pub(crate) fn client_ip_config(
        state: &crate::domain::AppState,
    ) -> actix_web::web::Data<crate::support::client_ip::ClientIpConfig> {
        let endpoint = &state.settings.endpoint;
        actix_web::web::Data::new(crate::support::client_ip::ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ))
    }

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
