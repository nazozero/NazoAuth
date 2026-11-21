use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jiff::Timestamp;
use nazo_crypto::{jwt::Algorithm, signature::PreparedSigningKey};
use nazo_identity::{
    OidcFederationStart,
    federation::oidc::{
        OidcError, OidcTokenResponse, OidcUserInfo, authorization_url, verify_id_token,
    },
};
use serde_json::{Value, json};

const ISSUER: &str = "https://issuer.example";
const CLIENT: &str = "client-1";
const NONCE: &str = "nonce-1";

struct Fixture {
    key: PreparedSigningKey,
    algorithm: Algorithm,
    jwks: Value,
}

impl Fixture {
    fn new(algorithm: Algorithm) -> Self {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../crypto/tests/fixtures/portable-jose.json"
        ))
        .unwrap();
        let vector = vectors["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["algorithm"] == json!(algorithm))
            .unwrap();
        let private = URL_SAFE_NO_PAD
            .decode(vector["private_der"].as_str().unwrap())
            .unwrap();
        let key = PreparedSigningKey::new(algorithm, &private).unwrap();
        let mut jwk = key.public_jwk();
        jwk["kid"] = json!("oidc-kid");
        Self {
            key,
            algorithm,
            jwks: json!({"keys": [jwk]}),
        }
    }

    fn token(&self, overrides: Value, remove: &[&str], kid: Option<&str>) -> String {
        let now = Timestamp::now().as_second();
        let mut claims = json!({
            "iss": ISSUER,
            "sub": "subject-1",
            "aud": CLIENT,
            "exp": now + 300,
            "iat": now,
            "nonce": NONCE,
            "email": "user@example.com",
            "email_verified": true,
            "name": "User One",
            "given_name": "User",
            "family_name": "One"
        });
        for (key, value) in overrides.as_object().unwrap() {
            claims[key] = value.clone();
        }
        for key in remove {
            claims.as_object_mut().unwrap().remove(*key);
        }
        let mut header = json!({"alg": self.algorithm});
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).unwrap())
        )
    }

    fn valid_token(&self) -> String {
        self.token(json!({}), &[], Some("oidc-kid"))
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn authorization_request_preserves_endpoint_query_and_binds_state_nonce_and_pkce() {
    let start = OidcFederationStart {
        state: "state-1".into(),
        nonce: NONCE.into(),
        pkce_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
    };
    let location = authorization_url(
        "https://issuer.example/authorize/?tenant=example",
        CLIENT,
        "https://auth.example/callback?provider=oidc",
        "openid email profile",
        &start,
    );
    let url = url::Url::parse(&location).unwrap();
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    for (name, value) in [
        ("tenant", "example"),
        ("response_type", "code"),
        ("client_id", CLIENT),
        (
            "redirect_uri",
            "https://auth.example/callback?provider=oidc",
        ),
        ("scope", "openid email profile"),
        ("state", "state-1"),
        ("nonce", NONCE),
        ("code_challenge_method", "S256"),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
    ] {
        assert_eq!(params.get(name).map(|v| v.as_ref()), Some(value));
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn supported_signatures_produce_only_verified_identity_claims() {
    for algorithm in [
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::EdDSA,
    ] {
        let fixture = Fixture::new(algorithm);
        let token = fixture.token(
            json!({"email": " User@Example.COM "}),
            &[],
            Some("oidc-kid"),
        );
        let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
        let identity = claims.into_identity("test-oidc", None).unwrap();
        assert_eq!(identity.provider_type, "oidc");
        assert_eq!(identity.provider_id, "test-oidc");
        assert_eq!(identity.subject, "subject-1");
        assert_eq!(identity.email.as_deref(), Some("user@example.com"));
        assert_eq!(identity.display_name.as_deref(), Some("User One"));
        assert_eq!(
            identity.claims,
            json!({
                "iss": ISSUER, "sub": "subject-1", "email": "user@example.com",
                "name": "User One", "given_name": "User", "family_name": "One"
            })
        );
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn issuer_audience_nonce_and_time_mismatches_are_rejected() {
    let fixture = Fixture::new(Algorithm::RS256);
    for invalid in [
        json!({"iss": "https://attacker.example"}),
        json!({"iss": "https://issuer.example/"}),
        json!({"aud": "other-client"}),
        json!({"aud": [CLIENT, "other-client"]}),
        json!({"aud": [CLIENT, "other-client"], "azp": "other-client"}),
        json!({"nonce": "other-nonce"}),
        json!({"exp": Timestamp::now().as_second()}),
        json!({"iat": Timestamp::now().as_second() + 120}),
    ] {
        let token = fixture.token(invalid, &[], Some("oidc-kid"));
        assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_err());
    }
    let token = fixture.token(
        json!({"aud": [CLIENT, "other-client"], "azp": CLIENT}),
        &[],
        Some("oidc-kid"),
    );
    assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_ok());
    let token = fixture.token(
        json!({"iss": "https://issuer.example/"}),
        &[],
        Some("oidc-kid"),
    );
    assert!(
        verify_id_token(
            "https://issuer.example/",
            CLIENT,
            &fixture.jwks,
            &token,
            NONCE
        )
        .is_ok()
    );
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn required_and_malformed_claims_are_rejected_independently() {
    let fixture = Fixture::new(Algorithm::RS256);
    for claim in ["iss", "sub", "aud", "exp", "iat", "nonce"] {
        let token = fixture.token(json!({}), &[claim], Some("oidc-kid"));
        assert!(
            verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_err(),
            "missing {claim}"
        );
    }
    for audience in [
        json!(null),
        json!(42),
        json!({"client": CLIENT}),
        json!([]),
        json!([CLIENT, 42]),
    ] {
        let token = fixture.token(json!({"aud": audience}), &[], Some("oidc-kid"));
        assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_err());
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn subject_is_a_nonempty_ascii_identifier_of_at_most_255_bytes() {
    let fixture = Fixture::new(Algorithm::RS256);
    let subject = "s".repeat(255);
    let token = fixture.token(json!({"sub": subject}), &[], Some("oidc-kid"));
    let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
    assert_eq!(
        claims.into_identity("test-oidc", None).unwrap().subject,
        subject
    );

    for subject in [String::new(), "s".repeat(256), "subject-é".into()] {
        let token = fixture.token(json!({"sub": subject}), &[], Some("oidc-kid"));
        assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_err());
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn missing_kid_requires_one_usable_verification_key() {
    let fixture = Fixture::new(Algorithm::RS256);
    let token = fixture.token(json!({}), &[], None);
    assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_ok());

    let incompatible = Fixture::new(Algorithm::ES256);
    let mut encryption_key = fixture.jwks["keys"][0].clone();
    encryption_key["use"] = json!("enc");
    let mixed = json!({"keys": [
        incompatible.jwks["keys"][0],
        encryption_key,
        fixture.jwks["keys"][0]
    ]});
    assert!(verify_id_token(ISSUER, CLIENT, &mixed, &token, NONCE).is_ok());

    let mut second_key = fixture.jwks["keys"][0].clone();
    second_key["kid"] = json!("another-kid");
    let ambiguous = json!({"keys": [fixture.jwks["keys"][0], second_key]});
    assert!(verify_id_token(ISSUER, CLIENT, &ambiguous, &token, NONCE).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn verification_keys_reject_unknown_ambiguous_private_or_incompatible_material() {
    let fixture = Fixture::new(Algorithm::RS256);
    let token = fixture.token(json!({}), &[], Some("unknown-kid"));
    assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).is_err());
    let token = fixture.valid_token();
    let duplicate = json!({"keys": [&fixture.jwks["keys"][0], &fixture.jwks["keys"][0]]});
    assert!(verify_id_token(ISSUER, CLIENT, &duplicate, &token, NONCE).is_err());
    for (member, value) in [
        ("d", json!("private")),
        ("p", json!("private")),
        ("key_ops", json!(["sign"])),
        ("use", json!(false)),
        ("alg", json!(1)),
    ] {
        let mut jwks = fixture.jwks.clone();
        jwks["keys"][0][member] = value;
        assert!(verify_id_token(ISSUER, CLIENT, &jwks, &token, NONCE).is_err());
    }
    let (input, signature) = token.rsplit_once('.').unwrap();
    let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    signature[0] ^= 1;
    let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
    assert!(verify_id_token(ISSUER, CLIENT, &fixture.jwks, &tampered, NONCE).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn unverified_or_missing_email_does_not_create_a_provisionable_identity() {
    let fixture = Fixture::new(Algorithm::RS256);
    for (overrides, remove) in [
        (json!({}), &["email"][..]),
        (json!({}), &["email_verified"][..]),
        (json!({"email": null}), &[][..]),
        (json!({"email": "not-an-email"}), &[][..]),
        (json!({"email_verified": false}), &[][..]),
        (json!({"email_verified": null}), &[][..]),
    ] {
        let token = fixture.token(overrides, remove, Some("oidc-kid"));
        let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
        let identity = claims.into_identity("test-oidc", None).unwrap();
        assert_eq!(identity.subject, "subject-1");
        assert_eq!(identity.email, None);
        assert_eq!(identity.claims["email"], Value::Null);
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn userinfo_subject_must_exactly_match_the_verified_id_token() {
    let fixture = Fixture::new(Algorithm::RS256);
    let token = fixture.valid_token();
    let userinfo: OidcUserInfo = serde_json::from_value(json!({
        "sub": "subject-1",
        "email": " UserInfo@Example.COM ",
        "email_verified": true,
        "name": "UserInfo Name"
    }))
    .unwrap();
    let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
    let identity = claims.into_identity("test-oidc", Some(userinfo)).unwrap();
    assert_eq!(identity.subject, "subject-1");
    assert_eq!(identity.email.as_deref(), Some("userinfo@example.com"));
    assert_eq!(identity.display_name.as_deref(), Some("UserInfo Name"));
    assert_eq!(identity.claims["iss"], ISSUER);
    assert_eq!(identity.claims["given_name"], Value::Null);

    for subject in ["other-subject", "Subject-1", "subject-1 "] {
        let userinfo = serde_json::from_value(json!({
            "sub": subject,
            "email": "user@example.com",
            "email_verified": true
        }))
        .unwrap();
        let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
        assert_eq!(
            claims
                .into_identity("test-oidc", Some(userinfo))
                .unwrap_err(),
            OidcError::InvalidUserInfo
        );
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn email_and_verification_must_come_from_the_same_profile() {
    let fixture = Fixture::new(Algorithm::RS256);
    let token = fixture.valid_token();
    for profile in [
        json!({"sub": "subject-1", "email": "userinfo@example.com"}),
        json!({"sub": "subject-1", "email_verified": true}),
        json!({
            "sub": "subject-1",
            "email": "userinfo@example.com",
            "email_verified": false
        }),
    ] {
        let userinfo = serde_json::from_value(profile).unwrap();
        let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
        let identity = claims.into_identity("test-oidc", Some(userinfo)).unwrap();
        assert_eq!(identity.email, None);
        assert_eq!(identity.claims["email"], Value::Null);
    }

    let token = fixture.token(json!({"email_verified": false}), &[], Some("oidc-kid"));
    let userinfo = serde_json::from_value(json!({
        "sub": "subject-1",
        "email": "userinfo@example.com",
        "email_verified": true
    }))
    .unwrap();
    let claims = verify_id_token(ISSUER, CLIENT, &fixture.jwks, &token, NONCE).unwrap();
    let identity = claims.into_identity("test-oidc", Some(userinfo)).unwrap();
    assert_eq!(identity.email.as_deref(), Some("userinfo@example.com"));
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn userinfo_requires_a_nonempty_bearer_access_token() {
    for token_type in ["Bearer", "bearer", "bEaReR"] {
        let response: OidcTokenResponse = serde_json::from_value(json!({
            "id_token": "id-token",
            "access_token": "access-token+/=",
            "token_type": token_type
        }))
        .unwrap();
        assert_eq!(response.userinfo_access_token().unwrap(), "access-token+/=");
    }

    for response in [
        json!({"id_token": "id-token", "access_token": "access-token"}),
        json!({"id_token": "id-token", "token_type": "Bearer"}),
        json!({"id_token": "id-token", "access_token": "", "token_type": "Bearer"}),
        json!({"id_token": "id-token", "access_token": "access-token", "token_type": "MAC"}),
        json!({"id_token": "id-token", "access_token": "access-token", "token_type": "Bearer "}),
    ] {
        let response: OidcTokenResponse = serde_json::from_value(response).unwrap();
        assert_eq!(
            response.userinfo_access_token().unwrap_err(),
            OidcError::InvalidTokenResponse
        );
    }
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn discovery_binds_the_exact_issuer_and_only_usable_https_endpoints() {
    use nazo_identity::federation::oidc::{OidcProviderMetadata, discovery_url};
    let issuer = "https://issuer.example/acme/";
    assert_eq!(
        discovery_url(issuer).as_deref(),
        Some("https://issuer.example/acme/.well-known/openid-configuration")
    );
    assert!(discovery_url("http://issuer.example").is_none());
    assert!(discovery_url("https://@issuer.example").is_none());
    assert!(discovery_url("https://issuer.example/acme?query").is_none());
    let document = json!({
        "issuer": issuer,
        "authorization_endpoint": "https://login.example/authorize",
        "token_endpoint": "https://api.example/token",
        "jwks_uri": "https://keys.example/jwks",
        "response_types_supported": ["code"]
    });
    let metadata: OidcProviderMetadata = serde_json::from_value(document).unwrap();
    assert!(metadata.validate(issuer));
    assert!(!metadata.validate(issuer.trim_end_matches('/')));
    let mut wrong = metadata.clone();
    wrong.token_endpoint = "http://api.example/token".to_owned();
    assert!(!wrong.validate(issuer));
    let mut incompatible = metadata;
    incompatible.token_endpoint_auth_methods_supported = Some(vec!["private_key_jwt".into()]);
    assert!(!incompatible.validate(issuer));
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn logout_requires_a_current_signed_token_for_this_client_and_a_logout_target() {
    use nazo_identity::federation::oidc::verify_logout_token;
    let fixture = Fixture::new(Algorithm::ES256);
    let now = Timestamp::now();
    let signed = |overrides, remove: &[&str]| {
        let mut claims = json!({
            "sid": "upstream-session",
            "jti": "logout-event",
            "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
        });
        for (key, value) in
            serde_json::from_value::<serde_json::Map<String, Value>>(overrides).unwrap()
        {
            claims[key] = value;
        }
        fixture.token(claims, remove, Some("oidc-kid"))
    };
    let verify =
        |token: &str| verify_logout_token("provider", ISSUER, CLIENT, &fixture.jwks, token, now);
    assert!(verify(&signed(json!({}), &["nonce"])).is_ok());
    assert!(verify(&signed(json!({}), &["nonce", "sid"])).is_ok());
    assert!(verify(&signed(json!({}), &[])).is_err());
    assert!(verify(&signed(json!({"nonce": null}), &[])).is_err());
    assert!(verify(&signed(json!({}), &["nonce", "sub", "sid"])).is_err());
    assert!(verify(&signed(json!({}), &["nonce", "exp"])).is_err());
    assert!(verify(&signed(json!({"aud": "other-client"}), &["nonce"])).is_err());
    assert!(
        verify(&signed(
            json!({"aud": [CLIENT, "other-client"]}),
            &["nonce"]
        ))
        .is_err()
    );
    assert!(
        verify(&signed(
            json!({"aud": [CLIENT, "other-client"], "azp": CLIENT}),
            &["nonce"]
        ))
        .is_ok()
    );
    assert!(verify(&signed(json!({"iss": "https://other.example"}), &["nonce"])).is_err());
    assert!(verify(&signed(json!({"iat": now.as_second() - 301}), &["nonce"])).is_err());
    assert!(
        verify(&signed(
            json!({"events": {"http://schemas.openid.net/event/backchannel-logout": null}}),
            &["nonce"]
        ))
        .is_err()
    );
}
