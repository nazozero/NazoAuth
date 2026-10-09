use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{AccessTokenSignInput, IdTokenSignInput, IntrospectionSignInput, TokenSignerPort};
use serde_json::json;

use crate::KeyManager;

fn access_input(authorization_details: &serde_json::Value) -> AccessTokenSignInput<'_> {
    AccessTokenSignInput {
        authorization_id: None,
        client_epoch: None,
        user_epoch: None,
        issuer: "https://issuer.example",
        tenant_id: uuid::Uuid::from_u128(1),
        subject: "user",
        user_id: Some(uuid::Uuid::from_u128(2)),
        subject_type: "public",
        client_id: "client",
        audiences: &[],
        scopes: &[],
        authorization_details,
        userinfo_claim_requests: &[],
        ttl_seconds: 300,
        sender_constraint: nazo_auth::AppliedSenderConstraint::Bearer,

        actor: None,
    }
}

#[tokio::test]
async fn access_token_header_and_signature_keep_one_generation_during_rotation() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let original = manager.snapshot();
    let details = json!([]);
    let signing = manager.sign_access_token(access_input(&details));

    // Publish a different key and algorithm after the header has been prepared,
    // but before signing. Reloading the generation at signing would mix them.
    let replacement = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
    manager
        .inner
        .generation
        .store(replacement.inner.generation.load_full());

    let issued = signing
        .await
        .expect("in-flight issuance survives key rotation");
    let header = jsonwebtoken::decode_header(&issued.token).unwrap();
    assert_eq!(header.alg, original.active_alg);
    assert_eq!(header.kid.as_deref(), Some(original.active_kid.as_str()));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let original_key = original.verification_key(&original.active_kid).unwrap();
    let mut validation = nazo_crypto::jwt::Validation::new(original.active_alg);
    validation.validate_aud = false;
    validation.set_issuer(&["https://issuer.example"]);
    let claims = nazo_crypto::jwt::decode::<serde_json::Value>(
        &issued.token,
        &original_key.prepared.key,
        &validation,
    )
    .expect("the header must identify the key that actually signed the token")
    .claims;
    assert_eq!(claims["jti"], issued.jti);
    assert_eq!(claims["exp"], issued.expires_at);
    assert_eq!(
        manager.snapshot().active_alg,
        jsonwebtoken::Algorithm::RS256
    );
}

#[tokio::test]
async fn id_token_and_introspection_keep_default_and_registered_keys_during_rotation() {
    // An explicit client algorithm can select an auxiliary key; it must not
    // inherit the active key's kid when pinning the generation.
    for (requested, expected) in [
        (None, jsonwebtoken::Algorithm::EdDSA),
        (Some("PS256"), jsonwebtoken::Algorithm::PS256),
    ] {
        let manager = KeyManager::for_test_with_auxiliary(jsonwebtoken::Algorithm::PS256);
        let original = manager.snapshot();
        let body = json!({"active": true});
        let id_signing = manager.sign_id_token(IdTokenSignInput {
            issuer: "https://issuer.example",
            subject: "user",
            client_id: "client",
            nonce: None,
            auth_time: None,
            amr: &[],
            sid: None,
            acr: None,
            extra_claims: None,
            ttl_seconds: 300,
            signing_algorithm: requested,
        });
        let introspection_signing = manager.sign_introspection_response(IntrospectionSignInput {
            issuer: "https://issuer.example",
            audience: "client",
            body: &body,
            signing_algorithm: requested,
        });

        // Both futures have captured their generation. Replace it before either
        // is polled so this regression is independent of thread scheduling.
        let replacement = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
        manager
            .inner
            .generation
            .store(replacement.inner.generation.load_full());

        let id_token = id_signing
            .await
            .expect("ID-token signing survives rotation");
        let introspection = introspection_signing
            .await
            .expect("introspection signing survives rotation");
        for (token, typ, has_expiry) in [
            (&id_token, "JWT", true),
            (&introspection, "token-introspection+jwt", false),
        ] {
            let header = nazo_crypto::jwt::decode_header(token).unwrap();
            assert_eq!(header.alg, expected);
            assert_eq!(header.typ.as_deref(), Some(typ));
            let key = original
                .verification_key(header.kid.as_deref().unwrap())
                .expect("kid belongs to the captured generation");
            assert_eq!(key.prepared.algorithm, expected);
            let mut validation = nazo_crypto::jwt::Validation::new(expected);
            validation.set_issuer(&["https://issuer.example"]);
            validation.set_audience(&["client"]);
            if !has_expiry {
                validation.required_spec_claims.remove("exp");
            }
            let claims = nazo_crypto::jwt::decode::<serde_json::Value>(
                token,
                &key.prepared.key,
                &validation,
            )
            .expect("the selected captured key verifies the signature")
            .claims;
            if has_expiry {
                assert_eq!(claims["sub"], "user");
            } else {
                assert_eq!(claims["token_introspection"], body);
            }
        }
        assert_eq!(
            manager.snapshot().active_alg,
            jsonwebtoken::Algorithm::RS256
        );
    }
}

#[tokio::test]
async fn introspection_response_uses_registered_algorithm() {
    let manager = KeyManager::for_test_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let token = manager
        .sign_introspection_response(IntrospectionSignInput {
            issuer: "https://issuer.example",
            audience: "client",
            body: &json!({"active": true}),
            signing_algorithm: Some("PS256"),
        })
        .await
        .expect("PS256 introspection response");
    let header = jsonwebtoken::decode_header(&token).expect("JWT header");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
}

#[tokio::test]
async fn decode_rejects_a_header_algorithm_outside_the_keys_prepared_algorithm() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let kid = manager.snapshot().active_kid.clone();
    // The token names the EdDSA key but declares RS256: it must be rejected
    // before signature verification under a mismatched algorithm.
    let header = json!({"alg":"RS256","typ":"at+jwt","kid":kid});
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"iss":"https://issuer.example"})).unwrap()),
        URL_SAFE_NO_PAD.encode([0_u8; 8]),
    );
    assert!(
        manager
            .decode_access_token("https://issuer.example", &token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        manager
            .decode_id_token("https://issuer.example", &token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn logout_hint_prepared_key_preserves_signature_issuer_type_and_expired_policy() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let issuer = "https://issuer.example";
    for typ in [Some("JWT"), None, Some("at+jwt")] {
        let mut header = nazo_crypto::jwt::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.typ = typ.map(str::to_owned);
        let expiry = chrono::Utc::now().timestamp() - 600;
        let token = manager.encode_jwt(nazo_auth::SigningPurpose::IdToken, &header,
            &json!({"iss": issuer, "sub": "subject", "aud": ["client"], "sid": "session", "exp": expiry}),
        ).await.unwrap();
        let decoded = manager.decode_id_token_hint(issuer, &token);
        if typ == Some("at+jwt") {
            assert!(decoded.is_none());
            continue;
        }
        let (claims, expires_at) = decoded.expect("expired signed hint remains a policy input");
        assert_eq!(claims.sub, "subject");
        assert_eq!(claims.aud, json!(["client"]));
        assert_eq!(claims.sid.as_deref(), Some("session"));
        assert_eq!(expires_at, expiry);
        assert!(
            manager
                .decode_id_token_hint("https://wrong-issuer.example", &token)
                .is_none()
        );
        let mut tampered = token.as_bytes().to_vec();
        let signature = token.rfind('.').unwrap() + 1;
        tampered[signature] = if tampered[signature] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            manager
                .decode_id_token_hint(issuer, std::str::from_utf8(&tampered).unwrap())
                .is_none()
        );
        let replacement = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        assert!(replacement.decode_id_token_hint(issuer, &token).is_none());
    }
}

#[tokio::test]
async fn logout_hint_prepared_key_still_observes_retirement_and_algorithm() {
    for drift in ["algorithm", "retirement"] {
        let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let token = manager
            .sign_id_token(IdTokenSignInput {
                issuer: "https://issuer.example",
                subject: "subject",
                client_id: "client",
                nonce: None,
                auth_time: None,
                amr: &[],
                sid: Some("session"),
                acr: None,
                extra_claims: None,
                ttl_seconds: 300,
                signing_algorithm: None,
            })
            .await
            .unwrap();
        // Take exclusive ownership of the old test generation, without exposing
        // a production constructor or manufacturing private lifecycle fields.
        let replacement = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let generation = manager
            .inner
            .generation
            .swap(replacement.inner.generation.load_full());
        let mut generation = match std::sync::Arc::try_unwrap(generation) {
            Ok(generation) => generation,
            Err(_) => panic!("completed signing released its generation"),
        };
        let snapshot = std::sync::Arc::make_mut(&mut generation.snapshot);
        if drift == "algorithm" {
            snapshot.verification_keys[0].prepared.algorithm = jsonwebtoken::Algorithm::RS256;
        } else {
            snapshot.verification_keys[0].retire_at =
                Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        }
        manager
            .inner
            .generation
            .store(std::sync::Arc::new(generation));
        assert!(
            manager
                .decode_id_token_hint("https://issuer.example", &token)
                .is_none()
        );
    }
}

// Test-only reference to the former logout decoder's flat claim representation.
// Rebuild the verification key from admitted fixture JWK components rather than
// reusing the new typed/prepared-key path. Fixture key admission is unchanged.
#[derive(serde::Deserialize)]
struct OriginalLogoutHintClaims {
    sub: String,
    aud: serde_json::Value,
    #[serde(default)]
    sid: Option<String>,
    exp: i64,
}

fn original_logout_hint_decoder(
    manager: &KeyManager,
    issuer: &str,
    token: &str,
) -> Option<(nazo_auth::IdTokenHintClaims, i64)> {
    use nazo_crypto::jwt::{Algorithm, VerificationKey};

    let header = nazo_crypto::jwt::decode_header(token).ok()?;
    if header.typ.as_deref().is_some_and(|typ| typ != "JWT")
        || crate::signing_algorithm_name(header.alg).is_none()
    {
        return None;
    }
    let snapshot = manager.snapshot();
    let key = snapshot.verification_key(header.kid.as_deref()?)?;
    if key.public_jwk["alg"].as_str()? != crate::signing_algorithm_name(header.alg)? {
        return None;
    }
    let jwk = &key.public_jwk;
    let decoding_key = match header.alg {
        Algorithm::EdDSA => VerificationKey::from_ed_components(jwk["x"].as_str()?).ok()?,
        Algorithm::RS256 | Algorithm::PS256 => {
            VerificationKey::from_rsa_components(jwk["n"].as_str()?, jwk["e"].as_str()?).ok()?
        }
        Algorithm::ES256 => {
            VerificationKey::from_ec_components(jwk["x"].as_str()?, jwk["y"].as_str()?).ok()?
        }
        _ => return None,
    };
    let mut validation = nazo_crypto::jwt::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.set_issuer(&[issuer]);
    let claims =
        nazo_crypto::jwt::decode::<OriginalLogoutHintClaims>(token, &decoding_key, &validation)
            .ok()?
            .claims;
    Some((
        nazo_auth::IdTokenHintClaims {
            sub: claims.sub,
            aud: claims.aud,
            sid: claims.sid,
        },
        claims.exp,
    ))
}

async fn sign_raw_logout_hint_fixture(
    manager: &KeyManager,
    header: &serde_json::Value,
    payload: &[u8],
) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(payload),
    );
    // The actual purpose-scoped signer signs the malformed header/payload bytes.
    // Rejection therefore cannot be explained by a deliberately stale signature.
    let signature = nazo_auth::Signer::sign(
        manager,
        nazo_auth::SignRequest {
            purpose: nazo_auth::SigningPurpose::IdToken,
            algorithm: "EdDSA",
            signing_input: signing_input.as_bytes(),
        },
    )
    .await
    .unwrap();
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_bytes())
    )
}

#[tokio::test]
async fn logout_hint_malformed_claims_and_kid_match_original_decoder() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let issuer = "https://issuer.example";
    let valid =
        json!({"iss": issuer, "sub": "subject", "aud": ["client"], "sid": "session", "exp": 1000});
    let header = nazo_crypto::jwt::Header::new(jsonwebtoken::Algorithm::EdDSA);
    for (case, field, replacement) in [
        ("missing sub", "sub", None),
        ("null sub", "sub", Some(json!(null))),
        ("numeric sub", "sub", Some(json!(7))),
        ("missing aud", "aud", None),
        ("missing exp", "exp", None),
        ("null exp", "exp", Some(json!(null))),
        ("string exp", "exp", Some(json!("1000"))),
        ("fractional exp", "exp", Some(json!(1000.5))),
        ("numeric sid", "sid", Some(json!(7))),
    ] {
        let mut claims = valid.clone();
        let object = claims.as_object_mut().unwrap();
        match replacement {
            Some(value) => {
                object.insert(field.to_owned(), value);
            }
            None => {
                object.remove(field);
            }
        }
        let token = manager
            .encode_jwt(nazo_auth::SigningPurpose::IdToken, &header, &claims)
            .await
            .unwrap();
        let original = original_logout_hint_decoder(&manager, issuer, &token);
        assert!(original.is_none(), "original decoder must reject {case}");
        assert_eq!(
            manager.decode_id_token_hint(issuer, &token),
            original,
            "{case}"
        );
    }
    // Preserve optional SID and arbitrary audience representation semantics:
    // the logout policy, rather than this decoder, selects an audience/session.
    for claims in [
        json!({"iss": issuer, "sub": "subject", "aud": "client", "exp": 1000}),
        json!({"iss": issuer, "sub": "subject", "aud": ["client"], "sid": null, "exp": 1000}),
        json!({"iss": issuer, "sub": "subject", "aud": null, "exp": 1000}),
    ] {
        let token = manager
            .encode_jwt(nazo_auth::SigningPurpose::IdToken, &header, &claims)
            .await
            .unwrap();
        assert_eq!(
            manager.decode_id_token_hint(issuer, &token),
            original_logout_hint_decoder(&manager, issuer, &token)
        );
    }
    let valid_payload = serde_json::to_vec(&valid).unwrap();
    for kid in [
        None,
        Some(json!(null)),
        Some(json!(42)),
        Some(json!("")),
        Some(json!("unknown-kid")),
    ] {
        let mut header = json!({"alg": "EdDSA", "typ": "JWT"});
        if let Some(kid) = kid {
            header["kid"] = kid;
        }
        let token = sign_raw_logout_hint_fixture(&manager, &header, &valid_payload).await;
        assert!(original_logout_hint_decoder(&manager, issuer, &token).is_none());
        assert!(manager.decode_id_token_hint(issuer, &token).is_none());
    }
    let header =
        json!({"alg": "EdDSA", "typ": "JWT", "kid": manager.snapshot().active_kid.clone()});
    for payload in [
        br#"{"iss":"https://issuer.example","sub":"first","sub":"second","aud":"client","exp":1000}"#.as_slice(),
        br#"{"iss":"https://issuer.example","sub":"subject","aud":"client","exp":1000,"exp":1001}"#.as_slice(),
        br#"{"iss":"https://issuer.example","sub": "#.as_slice(),
    ] {
        let token = sign_raw_logout_hint_fixture(&manager, &header, payload).await;
        let original = original_logout_hint_decoder(&manager, issuer, &token);
        assert!(original.is_none(), "original flat schema rejects malformed or duplicate claims");
        assert_eq!(manager.decode_id_token_hint(issuer, &token), original);
    }
}

#[tokio::test]
async fn logout_hint_supported_algorithms_match_original_claim_and_expiry_semantics() {
    for algorithm in [
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::Algorithm::PS256,
    ] {
        let manager = KeyManager::for_test(algorithm);
        let issuer = "https://issuer.example";
        let header = nazo_crypto::jwt::Header::new(algorithm);
        let claims = json!({"iss": issuer, "sub": "subject", "aud": ["client"], "sid": "session", "exp": 1000});
        let token = manager
            .encode_jwt(nazo_auth::SigningPurpose::IdToken, &header, &claims)
            .await
            .unwrap();
        let parsed_header = nazo_crypto::jwt::decode_header(&token).unwrap();
        assert_eq!(parsed_header.alg, algorithm);
        let snapshot = manager.snapshot();
        assert_eq!(
            parsed_header.kid.as_deref(),
            Some(snapshot.active_kid.as_str())
        );
        let original = original_logout_hint_decoder(&manager, issuer, &token)
            .expect("original decoder accepts this supported algorithm and expired hint");
        assert_eq!(original.0.sub, "subject");
        assert_eq!(original.0.aud, json!(["client"]));
        assert_eq!(original.0.sid.as_deref(), Some("session"));
        assert_eq!(original.1, 1000);
        assert_eq!(manager.decode_id_token_hint(issuer, &token), Some(original));
        assert!(
            manager
                .decode_id_token_hint("https://wrong-issuer.example", &token)
                .is_none()
        );
        let signature_start = token.rfind('.').unwrap() + 1;
        let mut tampered = token.into_bytes();
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = std::str::from_utf8(&tampered).unwrap();
        assert!(original_logout_hint_decoder(&manager, issuer, tampered).is_none());
        assert!(manager.decode_id_token_hint(issuer, tampered).is_none());
    }
}

#[test]
fn ownership_introspection_envelope_preserves_fixed_time_payload_bytes() {
    let iat = 1_700_000_000;
    for body in [
        json!(null),
        json!(false),
        json!(["", "\u{7b7e}\u{540d}", 1]),
        json!({"active": true, "z": ["", "a", "a"], "nested": {"z": 1, "a": "\n\"\\"}}),
    ] {
        let old = json!({"iss": "https://issuer.example/\u{7b7e}", "aud": "client/\u{540d}", "iat": iat, "token_introspection": &body});
        let borrowed = super::IntrospectionResponseClaims {
            aud: "client/\u{540d}",
            iat,
            iss: "https://issuer.example/\u{7b7e}",
            token_introspection: &body,
        };
        assert_eq!(
            serde_json::to_vec(&borrowed).unwrap(),
            serde_json::to_vec(&old).unwrap()
        );
    }
}

#[tokio::test]
async fn ownership_signed_introspection_payload_matches_original_bytes_and_algorithm() {
    for requested in [None, Some("PS256")] {
        let manager = KeyManager::for_test_with_auxiliary(jsonwebtoken::Algorithm::PS256);
        let body = json!({"active": true, "aud": ["a", "a", "\u{7b7e}\u{540d}"], "nested": {"z": null, "a": false}});
        let token = manager
            .sign_introspection_response(IntrospectionSignInput {
                issuer: "https://issuer.example",
                audience: "client",
                body: &body,
                signing_algorithm: requested,
            })
            .await
            .unwrap();
        let header = nazo_crypto::jwt::decode_header(&token).unwrap();
        let expected_algorithm = if requested.is_some() {
            jsonwebtoken::Algorithm::PS256
        } else {
            jsonwebtoken::Algorithm::EdDSA
        };
        assert_eq!(header.alg, expected_algorithm);
        assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
        let payload = URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let old = json!({"iss": "https://issuer.example", "aud": "client", "iat": decoded["iat"], "token_introspection": &body});
        assert_eq!(payload, serde_json::to_vec(&old).unwrap());
        let snapshot = manager.snapshot();
        let key = snapshot
            .verification_key(header.kid.as_deref().unwrap())
            .unwrap();
        let mut validation = nazo_crypto::jwt::Validation::new(expected_algorithm);
        validation.required_spec_claims.remove("exp");
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_audience(&["client"]);
        assert_eq!(
            nazo_crypto::jwt::decode::<serde_json::Value>(&token, &key.prepared.key, &validation)
                .unwrap()
                .claims,
            old
        );
    }
}

#[tokio::test]
async fn signing_preserves_each_single_sender_binding() {
    use nazo_auth::AppliedSenderConstraint;
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let details = json!([]);
    for (binding, expected) in [
        (AppliedSenderConstraint::Bearer, None),
        (
            AppliedSenderConstraint::Dpop("holder-jkt"),
            Some(json!({"jkt":"holder-jkt"})),
        ),
        (
            AppliedSenderConstraint::MutualTls("certificate-thumbprint"),
            Some(json!({"x5t#S256":"certificate-thumbprint"})),
        ),
    ] {
        let mut input = access_input(&details);
        input.sender_constraint = binding;
        let signed = manager.sign_access_token(input).await.unwrap();
        let claims = manager
            .decode_access_token("https://issuer.example", &signed.token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            claims.cnf.map(|cnf| serde_json::to_value(cnf).unwrap()),
            expected
        );
    }
}
