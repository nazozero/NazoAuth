use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    jwk::{Jwk, PublicKeyUse},
};
use nazo_oauth_server::resource_server::{ResourceServerVerifier, ResourceServerVerifierConfig};
use openssl::rsa::Rsa;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) struct Fixture {
    pub(crate) verifier: ResourceServerVerifier,
    pub(crate) jwks: Value,
    encoding_key: EncodingKey,
}

pub(crate) struct DpopFixture {
    pub(crate) encoding_key: EncodingKey,
    pub(crate) public_jwk: Jwk,
    pub(crate) jkt: String,
}

pub(crate) fn fixture() -> Fixture {
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

pub(crate) fn dpop_fixture() -> DpopFixture {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(&der);
    let mut public_jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    public_jwk.common.key_id = Some("dpop-rs256".to_owned());
    public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    let public_jwk_value = serde_json::to_value(&public_jwk).unwrap();
    let jkt = jwk_thumbprint(&public_jwk_value);
    DpopFixture {
        encoding_key,
        public_jwk,
        jkt,
    }
}

pub(crate) fn token(
    fixture: &Fixture,
    claim_overrides: Value,
    header_overrides: Option<Header>,
) -> String {
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

pub(crate) fn token_with_exact_header(
    fixture: &Fixture,
    claim_overrides: Value,
    header: Header,
) -> String {
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
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

pub(crate) fn dpop_proof(
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

pub(crate) fn signed_dpop_proof_with_overrides(
    fixture: &DpopFixture,
    access_token: &str,
    overrides: Value,
    header: Option<Header>,
) -> String {
    let mut claims = json!({
        "htu": "https://api.example/orders",
        "htm": "GET",
        "iat": Utc::now().timestamp(),
        "jti": "proof-jti-overrides",
        "ath": access_token_hash(access_token),
    });
    merge_object(&mut claims, overrides);
    let header = header.unwrap_or_else(|| {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(fixture.public_jwk.clone());
        header
    });
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

pub(crate) fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub(crate) fn dpop(token: &str) -> String {
    format!("DPoP {token}")
}

fn merge_object(target: &mut Value, overrides: Value) {
    let target = target.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        target.insert(key.clone(), value.clone());
    }
}

fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

fn jwk_thumbprint(key: &Value) -> String {
    let mut members = BTreeMap::new();
    match key.get("kty").and_then(Value::as_str).unwrap() {
        "RSA" => {
            members.insert("e", key.get("e").unwrap().as_str().unwrap());
            members.insert("kty", "RSA");
            members.insert("n", key.get("n").unwrap().as_str().unwrap());
        }
        "EC" => {
            members.insert("crv", key.get("crv").unwrap().as_str().unwrap());
            members.insert("kty", "EC");
            members.insert("x", key.get("x").unwrap().as_str().unwrap());
            members.insert("y", key.get("y").unwrap().as_str().unwrap());
        }
        "OKP" => {
            members.insert("crv", key.get("crv").unwrap().as_str().unwrap());
            members.insert("kty", "OKP");
            members.insert("x", key.get("x").unwrap().as_str().unwrap());
        }
        other => panic!("unsupported test key type {other}"),
    }
    let canonical = serde_json::to_string(&members).unwrap();
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}
