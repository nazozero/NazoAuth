use super::*;
use futures_util::future::{Ready, ready};
use http::header;
use jsonwebtoken::{
    EncodingKey, Header,
    jwk::{Jwk, PublicKeyUse},
};
use openssl::rsa::Rsa;
use serde_json::json;
use std::task::{Context, Poll};
use tower::{Layer, Service};

struct Fixture {
    verifier: ResourceServerVerifier,
    jwks: Value,
    encoding_key: EncodingKey,
}

struct DpopFixture {
    encoding_key: EncodingKey,
    public_jwk: Jwk,
    jkt: String,
}

fn fixture() -> Fixture {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(&der);
    let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    jwk.common.key_id = Some("test-rs256".to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    let jwks = json!({"keys": [serde_json::to_value(jwk).unwrap()]});
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        jwks.clone(),
    );
    config.required_scopes = vec!["read".to_owned()];
    Fixture {
        verifier: ResourceServerVerifier::new(config).unwrap(),
        jwks,
        encoding_key,
    }
}

fn dpop_fixture() -> DpopFixture {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(&der);
    let mut public_jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    public_jwk.common.key_id = Some("dpop-rs256".to_owned());
    public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    let public_jwk_value = serde_json::to_value(&public_jwk).unwrap();
    let jkt = dpop_jwk_thumbprint(&public_jwk_value).unwrap();
    DpopFixture {
        encoding_key,
        public_jwk,
        jkt,
    }
}

fn token(fixture: &Fixture, claim_overrides: Value, header_overrides: Option<Header>) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": "https://issuer.example",
        "sub": "subject-1",
        "aud": "resource://default",
        "client_id": "client-1",
        "scope": "read write",
        "authorization_details": [],
        "token_use": "access",
        "jti": "jti-1",
        "iat": now,
        "nbf": now,
        "exp": now + 300
    });
    merge_object(&mut claims, claim_overrides);
    let mut header = header_overrides.unwrap_or_else(|| {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".to_owned());
        header.kid = Some("test-rs256".to_owned());
        header
    });
    if header.kid.is_none() {
        header.kid = Some("test-rs256".to_owned());
    }
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

fn dpop_proof(
    fixture: &DpopFixture,
    access_token: &str,
    method: &str,
    htu: &str,
    jti: &str,
    nonce: Option<&str>,
    ath_override: Option<&str>,
) -> String {
    let mut claims = json!({
        "htu": htu,
        "htm": method,
        "iat": Utc::now().timestamp(),
        "jti": jti,
        "ath": ath_override
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| access_token_hash(access_token)),
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(fixture.public_jwk.clone());
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

fn merge_object(target: &mut Value, overrides: Value) {
    let target = target.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        target.insert(key.clone(), value.clone());
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn dpop(token: &str) -> String {
    format!("DPoP {token}")
}

#[test]
fn verifies_jwt_access_token_with_required_scope() {
    let fixture = fixture();
    let verified = fixture
        .verifier
        .verify(&token(&fixture, json!({}), None))
        .unwrap();

    assert_eq!(verified.issuer, "https://issuer.example");
    assert_eq!(verified.subject, "subject-1");
    assert_eq!(verified.audiences, vec!["resource://default"]);
    assert_eq!(verified.scopes, vec!["read", "write"]);
}

#[test]
fn rejects_wrong_audience() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"aud": "resource://other"}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::AudienceMismatch);
}

#[test]
fn rejects_missing_required_scope() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"scope": "write"}), None))
        .unwrap_err();

    assert_eq!(
        error,
        ResourceServerVerifierError::MissingScope("read".to_owned())
    );
}

#[test]
fn rejects_id_token_typ() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    header.kid = Some("test-rs256".to_owned());
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({}), Some(header)))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::WrongTokenType);
}

#[test]
fn enforces_dpop_jkt_binding() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let verified = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None))
        .unwrap();
    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
}

#[test]
fn rejects_dpop_jkt_mismatch() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let error = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-2"}}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::DpopBindingMismatch);
}

#[test]
fn request_authorizer_rejects_query_access_tokens() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str()],
        Some("access_token=query-token"),
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_rejects_duplicate_authorization_headers() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str(), token.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_requires_verified_dpop_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
    let header = dpop(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: Some("jkt-1".to_owned()),
            mtls_x5t_s256: None,
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
}

#[test]
fn dpop_proof_verifier_produces_verified_sender_context() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-1",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let proof = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            &access_token,
        )
        .unwrap();
    let header = dpop(&access_token);
    let verified =
        authorize_resource_request(&fixture.verifier, &[header.as_str()], None, &proof).unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt));
}

#[test]
fn dpop_http_authorizer_verifies_proof_and_inserts_extensions() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-http",
        None,
        None,
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let mut request = http::Request::builder()
        .method("GET")
        .uri("/orders")
        .header(header::AUTHORIZATION, dpop(&access_token))
        .header("DPoP", proof_jwt)
        .body(())
        .unwrap();

    let verified = authorize_dpop_http_request(
        &fixture.verifier,
        &dpop_verifier,
        &mut request,
        "https://api.example/orders",
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt.clone()));
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedSenderConstraintProof>()
            .unwrap()
            .dpop_jkt,
        Some(dpop_fixture.jkt)
    );
    assert!(request.extensions().get::<VerifiedAccessToken>().is_some());
}

#[test]
fn dpop_authorizer_rejects_invalid_proof_before_token_binding() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-invalid",
        None,
        Some("wrong-ath"),
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let authorization = dpop(&access_token);

    let error = authorize_dpop_resource_request(
        &fixture.verifier,
        &dpop_verifier,
        &[authorization.as_str()],
        &proof_jwt,
        None,
        "GET",
        "https://api.example/orders",
    )
    .unwrap_err();

    assert_eq!(
        error,
        ResourceServerRequestError::InvalidDpopProof(
            DpopProofVerifierError::AccessTokenHashMismatch
        )
    );
}

#[test]
fn dpop_proof_verifier_rejects_replayed_jti() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-replay",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::ReplayDetected);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_ath() {
    let dpop = dpop_fixture();
    let proof_jwt = dpop_proof(
        &dpop,
        "access-token",
        "GET",
        "https://api.example/orders",
        "proof-jti-ath",
        None,
        Some("wrong-ath"),
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            "access-token",
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::AccessTokenHashMismatch);
}

#[test]
fn dpop_proof_verifier_enforces_required_nonce() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-nonce",
        Some("nonce-1"),
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-1".to_owned()),
        ..DpopProofVerifierConfig::default()
    });

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();

    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-2".to_owned()),
        ..DpopProofVerifierConfig::default()
    });
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::NonceMismatch);
}

#[test]
fn request_authorizer_requires_verified_mtls_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"x5t#S256": "thumb-1"}}), None);
    let header = bearer(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: None,
            mtls_x5t_s256: Some("thumb-1".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));
}

#[test]
fn http_request_authorizer_inserts_verified_claims_for_tower_and_axum() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let mut request = http::Request::builder()
        .uri("https://api.example/orders")
        .header(header::AUTHORIZATION, token)
        .body(())
        .unwrap();

    let verified = authorize_http_request(&fixture.verifier, &mut request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}

#[actix_web::test]
async fn actix_request_authorizer_inserts_verified_claims() {
    use actix_web::HttpMessage;

    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let request = actix_web::test::TestRequest::get()
        .uri("/orders")
        .insert_header((actix_web::http::header::AUTHORIZATION, token))
        .to_http_request();

    let verified = authorize_actix_request(&fixture.verifier, &request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}

#[tokio::test]
async fn tower_layer_inserts_verified_claims_before_inner_service() {
    #[derive(Clone)]
    struct ExtensionCheckService;

    impl Service<http::Request<()>> for ExtensionCheckService {
        type Response = bool;
        type Error = ();
        type Future = Ready<Result<bool, ()>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<()>) -> Self::Future {
            ready(Ok(request
                .extensions()
                .get::<VerifiedAccessToken>()
                .is_some()))
        }
    }

    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let request = http::Request::builder()
        .uri("https://api.example/orders")
        .header(header::AUTHORIZATION, token)
        .body(())
        .unwrap();
    let mut service = TowerResourceServerLayer::new(fixture.verifier).layer(ExtensionCheckService);

    let saw_claims = service.call(request).await.unwrap();

    assert!(saw_claims);
}

#[test]
fn bearer_error_response_does_not_leak_internal_verifier_reason() {
    let response = http_bearer_error_response(&ResourceServerRequestError::InvalidToken(
        ResourceServerVerifierError::UnknownKeyId,
    ));

    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap(),
        r#"Bearer error="invalid_token", error_description="Access token is invalid.""#
    );
    assert_eq!(
        response.body(),
        r#"{"error":"invalid_token","error_description":"Access token is invalid."}"#
    );
    assert!(!response.body().contains("UnknownKeyId"));
}

#[test]
fn tonic_request_authorizer_inserts_verified_claims() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", token.parse().unwrap());

    let verified = authorize_tonic_request(&fixture.verifier, &mut request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}
