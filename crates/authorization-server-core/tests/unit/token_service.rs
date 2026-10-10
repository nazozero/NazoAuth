use std::sync::Arc;

use serde_json::json;

use crate::{Claims, ConfirmationClaims};

use super::{
    TokenInspection, TokenPortError, TokenStateStorePort, access_token_type,
    validate_sender_constraint,
};

fn access_claims(confirmation: Option<ConfirmationClaims>) -> Claims {
    Claims {
        authorization_id: None,
        client_epoch: None,
        user_epoch: None,
        iss: "https://issuer.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: uuid::Uuid::nil().to_string(),
        user_id: None,
        subject_type: "client".to_owned(),
        aud: json!("resource://default"),
        client_id: "client".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 2,
        cnf: confirmation,
        act: None,
        userinfo_claim_requests: (Vec::new()).into(),
    }
}

#[test]
fn arc_trait_object_is_a_token_state_store() {
    fn assert_state_store<T: TokenStateStorePort>() {}

    assert_state_store::<Arc<dyn TokenStateStorePort>>();
}

#[test]
fn access_token_cannot_bind_two_sender_constraints() {
    assert_eq!(
        validate_sender_constraint(Some("dpop"), Some("mtls")),
        Err(TokenPortError::InvalidSenderConstraint)
    );
    assert!(validate_sender_constraint(Some("dpop"), None).is_ok());
    assert!(validate_sender_constraint(None, Some("mtls")).is_ok());
}

#[test]
fn introspection_reports_dpop_only_for_dpop_bound_tokens() {
    assert_eq!(access_token_type(&access_claims(None)), "Bearer");
    assert_eq!(
        access_token_type(&access_claims(Some(ConfirmationClaims {
            jkt: Some("thumbprint".to_owned()),
            x5t_s256: None,
        }))),
        "DPoP"
    );
    assert_eq!(
        access_token_type(&access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("certificate-thumbprint".to_owned()),
        }))),
        "Bearer"
    );
}

#[test]
fn token_inspection_builds_exact_rfc7662_documents() {
    assert_eq!(
        TokenInspection::Inactive.into_document(),
        json!({"active": false})
    );
    assert_eq!(
        TokenInspection::ActiveRefresh {
            scope: "openid offline_access".to_owned(),
            client_id: "client".to_owned(),
            expires_at: 20,
            issued_at: 10,
            subject: "subject".to_owned(),
        }
        .into_document(),
        json!({
            "active": true,
            "scope": "openid offline_access",
            "client_id": "client",
            "exp": 20,
            "iat": 10,
            "sub": "subject",
        })
    );

    assert_eq!(
        TokenInspection::ActiveAccess {
            scope: "openid".to_owned(),
            client_id: "client".to_owned(),
            token_type: "DPoP",
            expires_at: 20,
            issued_at: 10,
            not_before: 10,
            subject: "subject".to_owned(),
            audience: json!("resource://default"),
            issuer: "https://issuer.example".to_owned(),
            jti: "jti".to_owned(),
            cnf: Some(ConfirmationClaims {
                jkt: Some("thumbprint".to_owned()),
                x5t_s256: None,
            }),
        }
        .into_document(),
        json!({
            "active": true,
            "scope": "openid",
            "client_id": "client",
            "token_type": "DPoP",
            "exp": 20,
            "iat": 10,
            "nbf": 10,
            "sub": "subject",
            "aud": "resource://default",
            "iss": "https://issuer.example",
            "jti": "jti",
            "cnf": {"jkt": "thumbprint"},
        })
    );
}

#[test]
fn token_inspection_preserves_owned_audience_and_confirmation_shapes() {
    for audience in [json!(null), json!(["resource://a", "resource://签名"])] {
        for cnf in [
            None,
            Some(ConfirmationClaims {
                jkt: None,
                x5t_s256: None,
            }),
            Some(ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("certificate-thumbprint".to_owned()),
            }),
        ] {
            let expected_cnf = cnf
                .as_ref()
                .map(|value| serde_json::to_value(value).unwrap());
            let document = TokenInspection::ActiveAccess {
                scope: String::new(),
                client_id: "client".to_owned(),
                token_type: "Bearer",
                expires_at: 20,
                issued_at: 10,
                not_before: 10,
                subject: "subject\"\n签名".to_owned(),
                audience: audience.clone(),
                issuer: "https://issuer.example".to_owned(),
                jti: "jti".to_owned(),
                cnf,
            }
            .into_document();
            assert_eq!(document["aud"], audience);
            assert_eq!(document["scope"], json!(""));
            assert_eq!(document["sub"], json!("subject\"\n签名"));
            assert_eq!(document.get("cnf"), expected_cnf.as_ref());
            assert_eq!(
                document.as_object().unwrap().len(),
                11 + usize::from(expected_cnf.is_some())
            );
        }
    }
}

#[test]
fn authorization_code_holder_serialization_omits_absent_proofs() {
    use super::{AuthorizationCodeClientAuthentication, AuthorizationCodeHolderEvidence};

    for authentication in [
        AuthorizationCodeClientAuthentication::Public,
        AuthorizationCodeClientAuthentication::Authenticated,
    ] {
        for selected in 0_u8..16 {
            let proof = |bit| (selected & bit != 0).then(|| format!("verified-proof-{bit}"));
            let Some(holder) = AuthorizationCodeHolderEvidence::from_verified_requirements(
                authentication,
                proof(1),
                proof(2),
                proof(4),
                proof(8),
            ) else {
                continue;
            };
            let compact = serde_json::to_value(&holder).unwrap();
            assert!(
                compact
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|value| !value.is_null()),
                "an absent proof must not occupy the durable receipt: {compact}"
            );
            assert_eq!(
                AuthorizationCodeHolderEvidence::from_persisted(compact.clone()),
                Some(holder.clone())
            );
            // Existing receipts contain explicit null members. Both encodings
            // restore the same original requirements, never fresh possession.
            let mut historical = compact;
            for name in [
                "pkce_s256",
                "dpop_jkt",
                "mtls_x5t_s256",
                "client_attestation_jkt",
            ] {
                historical
                    .as_object_mut()
                    .unwrap()
                    .entry(name)
                    .or_insert(serde_json::Value::Null);
            }
            assert_eq!(
                AuthorizationCodeHolderEvidence::from_persisted(historical),
                Some(holder)
            );
        }
    }
}

#[test]
fn compact_code_holder_still_rejects_missing_authority_and_invalid_proofs() {
    use super::AuthorizationCodeHolderEvidence;

    for malformed in [
        json!({"authenticated_client": true}),
        json!({"version": 1}),
        json!({"version": 2, "authenticated_client": true}),
        json!({"version": 1, "authenticated_client": false}),
        json!({"version": 1, "authenticated_client": true, "pkce_s256": ""}),
        json!({"version": 1, "authenticated_client": true, "dpop_jkt": "dpop", "mtls_x5t_s256": "mtls"}),
        json!({"version": 1, "authenticated_client": true, "unrecognized_proof": "proof"}),
    ] {
        assert!(AuthorizationCodeHolderEvidence::from_persisted(malformed).is_none());
    }
}
