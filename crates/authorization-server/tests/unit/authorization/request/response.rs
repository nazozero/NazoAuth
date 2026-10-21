use super::*;
use crate::crypto::jwt_decoding_key_from_jwk;
use crate::policy::AuthorizationServerProfile;
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rsa::{
        KeyPair, KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
    },
    signature::KeyPair as _,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_executor::block_on;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};

use crate::test_support::authorization as authorization_fixture;
use authorization_fixture::Fixture;

fn fixture() -> Fixture {
    let fixture = Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        Ok(None),
    )
    .with_algorithm(jsonwebtoken::Algorithm::RS256);
    fixture
        .snapshots
        .compare_and_publish(
            nazo_runtime_modules::ModuleRevision::new(1),
            nazo_runtime_modules::ActiveModuleSnapshot {
                revision: nazo_runtime_modules::ModuleRevision::new(2),
                accepting: BTreeSet::from([nazo_runtime_modules::ModuleId::Jarm]),
                draining: BTreeSet::new(),
            },
        )
        .expect("JARM module publication should advance the fixture generation");
    fixture
}

#[derive(Default)]
struct AuthorizationResponseProtection<'a> {
    signing_alg: Option<&'a str>,
    encryption_alg: Option<&'a str>,
    encryption_enc: Option<&'a str>,
    jwks: Option<&'a Value>,
}

async fn authorization_response_redirect_with_protection(
    fixture: &Fixture,
    client_id: &str,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> Result<AuthorizationOutcome, OAuthEndpointError> {
    let application = fixture.make_application();
    let mut client = authorization_fixture::client(true);
    client.client_id = client_id.to_owned();
    client.authorization_signed_response_alg = protection.signing_alg.map(str::to_owned);
    client.authorization_encrypted_response_alg = protection.encryption_alg.map(str::to_owned);
    client.authorization_encrypted_response_enc = protection.encryption_enc.map(str::to_owned);
    client.jwks = protection.jwks.cloned().map(std::sync::Arc::new);
    authorization_response_redirect_with_context(&application.context(), &mut client, input).await
}
fn authorization_location(result: &Result<AuthorizationOutcome, OAuthEndpointError>) -> url::Url {
    let Ok(AuthorizationOutcome::Redirect { location }) = result else {
        panic!("expected typed redirect outcome, got {result:?}")
    };
    url::Url::parse(location).expect("authorization redirect should be an absolute URL")
}
fn assert_unavailable_without_redirect(result: Result<AuthorizationOutcome, OAuthEndpointError>) {
    let Err(OAuthEndpointError::Json(fields)) = result else {
        panic!("failure must not emit any redirect containing code or state")
    };
    assert_eq!(fields.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fields.error, "server_error");
}

struct TestRsaKey {
    private_pkcs8_der: Vec<u8>,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl TestRsaKey {
    fn generate() -> Self {
        let key = KeyPair::generate(KeySize::Rsa2048).expect("AWS-LC RSA fixture key");
        let private_pkcs8_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&key)
            .expect("RSA fixture PKCS#8")
            .as_ref()
            .to_vec();
        Self {
            private_pkcs8_der,
            modulus: key
                .public_key()
                .modulus()
                .big_endian_without_leading_zero()
                .to_vec(),
            exponent: key
                .public_key()
                .exponent()
                .big_endian_without_leading_zero()
                .to_vec(),
        }
    }

    fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let private = PrivateDecryptingKey::from_pkcs8(&self.private_pkcs8_der)
            .map_err(|_| anyhow::anyhow!("invalid RSA fixture private key"))?;
        let private = OaepPrivateDecryptingKey::new(private)
            .map_err(|_| anyhow::anyhow!("invalid RSA-OAEP fixture key"))?;
        let mut plaintext = vec![0; private.min_output_size()];
        Ok(private
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
            .map_err(|_| anyhow::anyhow!("RSA-OAEP fixture decryption failed"))?
            .to_vec())
    }
}

fn decode_jarm_claims(state: &Fixture, response_jwt: &str, audience: &str) -> Value {
    let header =
        jsonwebtoken::decode_header(response_jwt).expect("JARM response header should decode");
    let decoding_key =
        jwt_decoding_key_from_jwk(&state.keys.snapshot().jwks()["keys"][0], header.alg)
            .expect("JARM decoding key should derive from test JWKS");
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_exp = false;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[state.config.issuer.as_ref()]);
    nazo_crypto::jwt::decode::<Value>(response_jwt, &decoding_key, &validation)
        .expect("JARM response should verify with the active key")
        .claims
}

fn rsa_jarm_jwe_keypair(kid: &str) -> (TestRsaKey, Value) {
    let rsa = TestRsaKey::generate();
    let jwk = json!({
        "kty": "RSA",
        "kid": kid,
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "n": URL_SAFE_NO_PAD.encode(&rsa.modulus),
        "e": URL_SAFE_NO_PAD.encode(&rsa.exponent)
    });
    (rsa, jwk)
}

fn decrypt_jarm_jwe(
    private_key: &TestRsaKey,
    compact_jwe: &str,
) -> anyhow::Result<(Value, String)> {
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    anyhow::ensure!(parts.len() == 5, "compact JWE must have five parts");
    let protected_header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let encrypted_key = URL_SAFE_NO_PAD.decode(parts[1])?;
    let iv = URL_SAFE_NO_PAD.decode(parts[2])?;
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[3])?;
    let tag = URL_SAFE_NO_PAD.decode(parts[4])?;
    let cek = private_key.decrypt_oaep_sha256(&encrypted_key)?;
    let plaintext = crate::crypto_test_support::aes_256_gcm_decrypt(
        &cek,
        &iv,
        parts[0].as_bytes(),
        &ciphertext,
        &tag,
    )?;
    Ok((protected_header, String::from_utf8(plaintext)?))
}

#[test]
fn authorization_response_redirect_emits_signed_jarm_response() {
    block_on(async {
        let state = fixture();

        let response = authorization_response_redirect_with_protection(
            &state,
            "client-jarm",
            AuthorizationResponseRedirect {
                redirect_uri: "https://client.example/callback?existing=1",

                response_mode: Some("jwt"),
                code: Some("code-123"),
                error: None,
                state: Some("state-123"),
                oidc_sid: None,
            },
            AuthorizationResponseProtection::default(),
        )
        .await;

        assert!(matches!(
            &response,
            Ok(AuthorizationOutcome::Redirect { .. })
        ));
        let location = authorization_location(&response);
        let pairs = location.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(pairs.get("existing").map(|value| value.as_ref()), Some("1"));
        assert!(pairs.contains_key("response"));
        assert!(!pairs.contains_key("code"));
        assert!(!pairs.contains_key("state"));
        assert!(!pairs.contains_key("iss"));

        let claims = decode_jarm_claims(
            &state,
            pairs
                .get("response")
                .expect("JARM response parameter should be present"),
            "client-jarm",
        );
        assert_eq!(claims["iss"], "https://issuer.example");
        assert_eq!(claims["aud"], "client-jarm");
        assert_eq!(claims["code"], "code-123");
        assert_eq!(claims["state"], "state-123");
    });
}

#[test]
fn response_uses_admitted_client_without_another_repository_query() {
    block_on(async {
        let state = fixture();
        for mode in [None, Some("jwt")] {
            let response = authorization_response_redirect_with_protection(
                &state,
                "client-admitted",
                AuthorizationResponseRedirect {
                    redirect_uri: "https://client.example/callback",
                    response_mode: mode,
                    code: None,
                    error: Some("login_required"),
                    state: Some("state"),
                    oidc_sid: None,
                },
                AuthorizationResponseProtection::default(),
            )
            .await;
            assert!(response.is_ok(), "{response:?}");
        }
        assert!(!state.ports.calls().contains(&"client"));
    });
}

#[test]
fn authorization_response_redirect_jarm_profile_signs_without_response_mode() {
    block_on(async {
        let mut state = fixture().with_algorithm(jsonwebtoken::Algorithm::PS256);
        state.config.profile = AuthorizationServerProfile::Fapi2MessageSigningJarm;

        let response = authorization_response_redirect_with_protection(
            &state,
            "client-jarm-profile",
            AuthorizationResponseRedirect {
                redirect_uri: "https://client.example/callback",

                response_mode: None,
                code: Some("code-456"),
                error: None,
                state: Some("state-456"),
                oidc_sid: None,
            },
            AuthorizationResponseProtection::default(),
        )
        .await;

        assert!(matches!(
            &response,
            Ok(AuthorizationOutcome::Redirect { .. })
        ));
        let location = authorization_location(&response);
        let pairs = location.query_pairs().collect::<HashMap<_, _>>();
        assert!(pairs.contains_key("response"));
        assert!(!pairs.contains_key("code"));
        assert!(!pairs.contains_key("state"));
        assert!(!pairs.contains_key("iss"));

        assert_eq!(
            jsonwebtoken::decode_header(pairs["response"].as_ref())
                .unwrap()
                .alg,
            jsonwebtoken::Algorithm::PS256
        );
        let rejected = authorization_response_redirect_with_protection(
            &state,
            "client-jarm-profile",
            AuthorizationResponseRedirect {
                redirect_uri: "https://client.example/callback",
                response_mode: None,
                code: Some("code"),
                error: None,
                state: None,
                oidc_sid: None,
            },
            AuthorizationResponseProtection {
                signing_alg: Some("RS256"),
                ..Default::default()
            },
        )
        .await;
        assert_unavailable_without_redirect(rejected);
        let claims = decode_jarm_claims(
            &state,
            pairs
                .get("response")
                .expect("JARM response parameter should be present"),
            "client-jarm-profile",
        );
        assert_eq!(claims["iss"], "https://issuer.example");
        assert_eq!(claims["aud"], "client-jarm-profile");
        assert_eq!(claims["code"], "code-456");
        assert_eq!(claims["state"], "state-456");
    });
}

#[test]
fn authorization_response_redirect_signs_then_encrypts_jarm_for_client_policy() {
    block_on(async {
        let state = fixture();
        let (private_key, public_jwk) = rsa_jarm_jwe_keypair("jarm-enc");
        let (wrong_private_key, _) = rsa_jarm_jwe_keypair("wrong-jarm-enc");
        let jwks = json!({"keys": [public_jwk]});

        let response = authorization_response_redirect_with_protection(
            &state,
            "client-encrypted-jarm",
            AuthorizationResponseRedirect {
                redirect_uri: "https://client.example/callback?existing=1",

                response_mode: Some("jwt"),
                code: Some("encrypted-code"),
                error: None,
                state: Some("encrypted-state"),
                oidc_sid: None,
            },
            AuthorizationResponseProtection {
                signing_alg: Some("RS256"),
                encryption_alg: Some("RSA-OAEP-256"),
                encryption_enc: Some("A256GCM"),
                jwks: Some(&jwks),
            },
        )
        .await;

        assert!(matches!(
            &response,
            Ok(AuthorizationOutcome::Redirect { .. })
        ));
        let location = authorization_location(&response);
        let pairs = location.query_pairs().collect::<HashMap<_, _>>();
        assert_eq!(pairs.get("existing").map(|value| value.as_ref()), Some("1"));
        assert!(!pairs.contains_key("code"));
        assert!(!pairs.contains_key("state"));
        let encrypted = pairs
            .get("response")
            .expect("encrypted JARM response parameter should be present");
        assert!(
            decrypt_jarm_jwe(&wrong_private_key, encrypted).is_err(),
            "an unrelated private key must not decrypt JARM"
        );
        let (protected, nested_jwt) =
            decrypt_jarm_jwe(&private_key, encrypted).expect("matching key should decrypt JARM");
        assert_eq!(protected["alg"], "RSA-OAEP-256");
        assert_eq!(protected["enc"], "A256GCM");
        assert_eq!(protected["kid"], "jarm-enc");
        assert_eq!(protected["cty"], "JWT");
        let claims = decode_jarm_claims(&state, &nested_jwt, "client-encrypted-jarm");
        assert_eq!(claims["code"], "encrypted-code");
        assert_eq!(claims["state"], "encrypted-state");
    });
}

#[test]
fn authorization_response_crypto_failure_never_falls_back_to_plain_query() {
    block_on(async {
        let state = fixture();
        for protection in [
            AuthorizationResponseProtection {
                signing_alg: Some("none"),
                ..AuthorizationResponseProtection::default()
            },
            AuthorizationResponseProtection {
                encryption_alg: Some("RSA-OAEP-256"),
                encryption_enc: Some("A256GCM"),
                jwks: None,
                ..AuthorizationResponseProtection::default()
            },
        ] {
            let response = authorization_response_redirect_with_protection(
                &state,
                "client-failed-jarm",
                AuthorizationResponseRedirect {
                    redirect_uri: "https://client.example/callback",

                    response_mode: Some("jwt"),
                    code: Some("must-not-leak"),
                    error: None,
                    state: Some("must-not-leak-state"),
                    oidc_sid: None,
                },
                protection,
            )
            .await;

            assert_unavailable_without_redirect(response);
        }
    });
}
