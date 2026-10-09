use nazo_auth::{Claims, IdTokenClaimRequests, OidcClaimRequest, UserinfoClaimRequests};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Debug, Deserialize, Serialize)]
struct SelectionPair {
    #[serde(flatten)]
    userinfo: UserinfoClaimRequests,
    #[serde(flatten)]
    id_token: IdTokenClaimRequests,
}
#[test]
fn legacy_names_are_read_without_weakening_full_requests_or_crossing_targets() {
    let decoded: SelectionPair = serde_json::from_value(json!({
        "userinfo_claims": ["email", "name", "email"],
        "userinfo_claim_requests": [{"name":"email","essential":true,"value":"allowed@example.test"}],
        "id_token_claims": ["sid"],
        "id_token_claim_requests": [{"name":"acr","essential":true,"values":["urn:acr:2"]}]
    })).unwrap();
    assert_eq!(decoded.userinfo.names(), ["email", "name"]);
    assert!(decoded.userinfo[0].essential);
    assert_eq!(
        decoded.userinfo[0].value,
        Some(json!("allowed@example.test"))
    );
    assert_eq!(decoded.userinfo[1], OidcClaimRequest::named("name"));
    assert_eq!(decoded.id_token.names(), ["acr", "sid"]);
    assert_eq!(decoded.id_token[0].values, [json!("urn:acr:2")]);
    let encoded = serde_json::to_value(&decoded).unwrap();
    assert!(encoded.get("userinfo_claims").is_none());
    assert!(encoded.get("id_token_claims").is_none());
    assert_eq!(encoded.as_object().unwrap().len(), 2);
    let round_trip: SelectionPair = serde_json::from_value(encoded).unwrap();
    assert_eq!(round_trip.userinfo, decoded.userinfo);
    assert_eq!(round_trip.id_token, decoded.id_token);
}
#[test]
fn current_and_legacy_fields_reject_malformed_inputs() {
    for invalid in [
        json!({"userinfo_claims": [false]}),
        json!({"userinfo_claim_requests": ["email"]}),
        json!({"userinfo_claim_requests": [{"name":"email","essential":"true"}]}),
        json!({"id_token_claims": null}),
        json!({"id_token_claim_requests": [{"name":"sid","values":false}]}),
    ] {
        assert!(
            serde_json::from_value::<SelectionPair>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}
#[test]
fn old_access_token_claim_selection_is_not_lost_on_decode() {
    let wire = json!({
        "iss":"https://issuer.example", "sub":"pairwise-user", "tenant_id":"tenant",
        "subject_type":"user", "aud":"https://issuer.example/userinfo", "client_id":"client",
        "scope":"openid", "token_use":"access", "jti":"token", "iat":100, "nbf":100,"exp":200,
        "userinfo_claims":["email","name"],
        "userinfo_claim_requests":[{"name":"email","essential":true,"values":["a@example.test"]}]
    });
    let claims: Claims = serde_json::from_value(wire).unwrap();
    assert_eq!(claims.userinfo_claim_requests.names(), ["email", "name"]);
    assert_eq!(
        claims.userinfo_claim_requests[0].values,
        [json!("a@example.test")]
    );
    let new_wire: Value = serde_json::to_value(claims).unwrap();
    assert!(new_wire.get("userinfo_claims").is_none());
}
