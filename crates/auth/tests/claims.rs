use nazo_auth::{
    AccessTokenClaimsInput, AuthorizationResponseClaimsInput, BackchannelLogoutClaimsInput,
    IdTokenClaimsInput, OidcClaimRequest, access_token_claims, authorization_response_jwt_claims,
    backchannel_logout_token_claims, id_token_claims,
};
use serde_json::{Value, json};
use uuid::Uuid;

fn normalize_generated_jti(mut claims: serde_json::Map<String, Value>) -> Value {
    let jti = claims.get("jti").and_then(Value::as_str).unwrap();
    assert_eq!(Uuid::parse_str(jti).unwrap().get_version_num(), 7);
    claims.insert("jti".to_owned(), json!("<generated-uuid-v7>"));
    Value::Object(claims)
}

#[test]
fn token_claim_constructors_preserve_complete_reviewed_shapes() {
    let tenant_id = Uuid::parse_str("01890f3c-7b00-7000-8000-000000000000").unwrap();
    let user_id = Uuid::parse_str("01890f3c-7b00-7000-8000-000000000001").unwrap();
    let subject = user_id.to_string();
    let audiences = vec![
        "resource://default".to_owned(),
        "https://api.example".to_owned(),
    ];
    let scopes = vec!["write".to_owned(), "read".to_owned()];
    let authorization_details = json!([{"type":"payment_initiation","actions":["write"]}]);
    let actor = json!({"sub":"delegating-client"});
    let requests = vec![OidcClaimRequest {
        name: "email".to_owned(),
        essential: true,
        value: Some(json!("alice@example.com")),
        values: vec![],
    }];
    let access = access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            tenant_id,
            subject: &subject,
            user_id: Some(user_id),
            subject_type: "user",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &authorization_details,
            userinfo_claims: &["email".to_owned()],
            userinfo_claim_requests: &requests,
            ttl: 300,
            dpop_jkt: Some("thumbprint-jkt"),
            mtls_x5t_s256: None,
            actor: Some(&actor),
        },
        1_000,
        "access-jti-1",
    );
    assert_eq!(
        serde_json::to_value(access).unwrap(),
        json!({
            "iss":"https://issuer.example","sub":subject,
            "tenant_id":tenant_id.to_string(),"user_id":user_id.to_string(),
            "subject_type":"user","aud":["resource://default","https://api.example"],
            "client_id":"client-1","scope":"read write",
            "authorization_details":[{"type":"payment_initiation","actions":["write"]}],
            "token_use":"access","jti":"access-jti-1","iat":1000,"nbf":1000,"exp":1300,
            "cnf":{"jkt":"thumbprint-jkt"},"act":{"sub":"delegating-client"},
            "userinfo_claims":["email"],
            "userinfo_claim_requests":[{"name":"email","essential":true,"value":"alice@example.com"}]
        })
    );

    let logout = normalize_generated_jti(backchannel_logout_token_claims(
        "https://issuer.example",
        &BackchannelLogoutClaimsInput {
            client_id: "client-1",
            subject: Some("subject-1"),
            sid: Some("sid-1"),
            ttl: 120,
        },
        1_000,
    ));
    assert_eq!(logout["exp"], json!(1_120));
    assert_eq!(
        logout["events"],
        json!({"http://schemas.openid.net/event/backchannel-logout":{}})
    );

    let response = normalize_generated_jti(authorization_response_jwt_claims(
        "https://issuer.example",
        &AuthorizationResponseClaimsInput {
            client_id: "client-1",
            code: Some("code-1"),
            error: None,
            state: Some(""),
            ttl: 60,
        },
        1_000,
    ));
    assert_eq!(response["state"], json!(""));
    assert_eq!(response["exp"], json!(1_060));
}

#[test]
fn id_token_extra_claims_cannot_override_registered_or_session_claims() {
    let extra = json!({
        "iss":"https://attacker.example","sub":"attacker","aud":"attacker",
        "exp":9999999,"sid":"attacker-sid","azp":"attacker-azp",
        "email":"alice@example.com"
    });
    let input = IdTokenClaimsInput {
        subject: "subject-1",
        client_id: "client-1",
        nonce: Some("nonce-1"),
        auth_time: Some(900),
        amr: &["password".to_owned(), "otp".to_owned()],
        sid: Some("server-sid"),
        acr: Some("urn:acr:2"),
        extra_claims: Some(&extra),
        ttl: 600,
    };

    let claims = id_token_claims("https://issuer.example", &input, 1_000);
    assert_eq!(claims["iss"], json!("https://issuer.example"));
    assert_eq!(claims["sub"], json!("subject-1"));
    assert_eq!(claims["aud"], json!("client-1"));
    assert_eq!(claims["exp"], json!(1_600));
    assert_eq!(claims["sid"], json!("server-sid"));
    assert_eq!(claims["email"], json!("alice@example.com"));
    assert!(!claims.contains_key("azp"));
}
