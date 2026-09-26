use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{AccessTokenSignInput, IdTokenSignInput, IntrospectionSignInput, TokenSignerPort};
use serde_json::json;

use crate::KeyManager;

fn access_input(authorization_details: &serde_json::Value) -> AccessTokenSignInput<'_> {
    AccessTokenSignInput {
        issuer: "https://issuer.example",
        tenant_id: uuid::Uuid::from_u128(1),
        subject: "user",
        user_id: Some(uuid::Uuid::from_u128(2)),
        subject_type: "public",
        client_id: "client",
        audiences: &[],
        scopes: &[],
        authorization_details,
        userinfo_claims: &[],
        userinfo_claim_requests: &[],
        ttl_seconds: 300,
        dpop_jkt: None,
        mtls_x5t_s256: None,
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
