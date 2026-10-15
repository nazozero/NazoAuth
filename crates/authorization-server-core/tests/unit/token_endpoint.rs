use super::*;

#[test]
fn conflicting_client_authentication_material_is_rejected_before_crypto() {
    let conflicting = TokenClientAuthPresentation {
        http_basic: true,
        form_client_id: true,
        form_client_secret: false,
        client_assertion_type: false,
        client_assertion: false,
    };
    assert_eq!(
        token_client_authentication_context(conflicting),
        Err(TokenEndpointError::InvalidRequest)
    );
    let context = token_client_authentication_context(TokenClientAuthPresentation {
        http_basic: false,
        form_client_id: true,
        form_client_secret: false,
        client_assertion_type: true,
        client_assertion: true,
    })
    .expect("single assertion method");
    assert!(context.has_assertion);
    assert!(context.has_any_client_auth_material);
}

#[test]
fn client_grant_profile_and_sender_constraint_are_admitted_together() {
    let grants = vec!["authorization_code".to_owned()];
    let admitted = admit_token_client(
        GrantType::AuthorizationCode,
        SecurityProfile::Fapi2Security,
        TokenClientPolicy {
            active: true,
            client_type: "confidential",
            enabled_grants: &grants,
            authentication_method: "private_key_jwt",
            require_dpop_bound_tokens: true,
            require_mtls_bound_tokens: false,
        },
    )
    .expect("FAPI client");
    assert_eq!(
        admitted.sender_constraint,
        SenderConstraintPolicy::DpopRequired
    );
    assert_eq!(
        apply_sender_constraint(
            admitted.sender_constraint,
            PresentedSenderConstraint {
                dpop_jkt: Some("thumbprint"),
                mtls_x5t_s256: None,
            }
        ),
        Ok(AppliedSenderConstraint::Dpop("thumbprint"))
    );
}

#[test]
fn sender_constraint_matrix_rejects_missing_mismatched_and_dual_bindings() {
    for (policy, presented) in [
        (
            SenderConstraintPolicy::DpopRequired,
            PresentedSenderConstraint {
                dpop_jkt: None,
                mtls_x5t_s256: None,
            },
        ),
        (
            SenderConstraintPolicy::MtlsRequired,
            PresentedSenderConstraint {
                dpop_jkt: Some("dpop"),
                mtls_x5t_s256: None,
            },
        ),
        (
            SenderConstraintPolicy::DpopOrMtls,
            PresentedSenderConstraint {
                dpop_jkt: Some("dpop"),
                mtls_x5t_s256: Some("mtls"),
            },
        ),
    ] {
        assert_eq!(
            apply_sender_constraint(policy, presented),
            Err(TokenEndpointError::InvalidRequest)
        );
    }
}
