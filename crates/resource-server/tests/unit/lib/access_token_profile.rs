use super::fixtures::{Fixture, fixture};
use super::*;
use jsonwebtoken::Header;
use serde_json::json;

fn claims(now: i64) -> Value {
    json!({
        "iss": "https://issuer.example",
        "sub": "subject-1",
        "aud": "resource://default",
        "client_id": "client-1",
        "scope": "read",
        "jti": "profile-test",
        "iat": now,
        "exp": now + 300,
    })
}

fn sign(fixture: &Fixture, claims: &Value, typ: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-rs256".to_owned());
    header.typ = typ.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, &fixture.encoding_key).unwrap()
}

#[test]
fn standard_profile_does_not_require_a_private_token_use_claim() {
    let fixture = fixture();
    let now = Utc::now().timestamp();
    for typ in ["at+jwt", "application/at+jwt"] {
        let token = sign(&fixture, &claims(now), Some(typ));
        assert!(fixture.verifier.verify_at(&token, now).is_ok());
    }
}

#[test]
fn access_token_issuance_time_is_required_and_must_be_numeric() {
    let fixture = fixture();
    let now = Utc::now().timestamp();
    let mut missing = claims(now);
    missing["token_use"] = json!("access");
    missing.as_object_mut().unwrap().remove("iat");
    let token = sign(&fixture, &missing, Some("at+jwt"));
    assert_eq!(
        fixture.verifier.verify_at(&token, now),
        Err(ResourceServerVerifierError::InvalidToken)
    );
    for invalid in [
        Value::Null,
        json!("1700000000"),
        json!(true),
        json!([]),
        json!({}),
    ] {
        let mut claims = claims(now);
        claims["token_use"] = json!("access");
        claims["iat"] = invalid;
        let token = sign(&fixture, &claims, Some("at+jwt"));
        assert_eq!(
            fixture.verifier.verify_at(&token, now),
            Err(ResourceServerVerifierError::InvalidToken)
        );
    }
    let mut fractional = claims(now);
    fractional["token_use"] = json!("access");
    fractional["iat"] = json!(1_700_000_000.5);
    let token = sign(&fixture, &fractional, Some("at+jwt"));
    assert!(fixture.verifier.verify_at(&token, now).is_ok());
}

#[test]
fn absent_private_marker_does_not_allow_other_token_types() {
    let fixture = fixture();
    let now = Utc::now().timestamp();
    for typ in [None, Some("JWT"), Some("application/jwt"), Some("id+jwt")] {
        let token = sign(&fixture, &claims(now), typ);
        assert_eq!(
            fixture.verifier.verify_at(&token, now),
            Err(ResourceServerVerifierError::WrongTokenType)
        );
    }
    let mut contradictory = claims(now);
    contradictory["token_use"] = json!("id");
    let token = sign(&fixture, &contradictory, Some("application/at+jwt"));
    assert_eq!(
        fixture.verifier.verify_at(&token, now),
        Err(ResourceServerVerifierError::WrongTokenType)
    );
}
