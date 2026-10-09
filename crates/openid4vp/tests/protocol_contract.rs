use nazo_openid4vp::{
    ClientIdPrefix, PresentationPolicy, PresentationPolicyError, RequestMethod, ResponseMode,
};

#[test]
fn haip_requires_signed_x509_hash_and_encrypted_direct_post() {
    let policy = PresentationPolicy {
        client_id_prefix: ClientIdPrefix::X509Hash,
        request_method: RequestMethod::RequestUriSignedPost,
        response_mode: ResponseMode::DirectPostJwt,
        haip: true,
    };
    assert!(policy.validate().is_ok());

    assert_eq!(
        PresentationPolicy {
            response_mode: ResponseMode::DirectPost,
            ..policy
        }
        .validate(),
        Err(PresentationPolicyError::HaipRequirement)
    );
}

#[test]
fn redirect_uri_scheme_cannot_be_combined_with_signed_request_object() {
    let policy = PresentationPolicy {
        client_id_prefix: ClientIdPrefix::RedirectUri,
        request_method: RequestMethod::RequestUriSignedGet,
        response_mode: ResponseMode::DirectPost,
        haip: false,
    };
    assert_eq!(
        policy.validate(),
        Err(PresentationPolicyError::RedirectUriCannotSign)
    );
}

#[test]
fn response_mode_has_one_checked_wire_spelling() {
    for (mode, wire) in [
        (ResponseMode::DirectPost, "direct_post"),
        (ResponseMode::DirectPostJwt, "direct_post.jwt"),
    ] {
        assert_eq!(serde_json::to_value(mode).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<ResponseMode>(serde_json::json!(wire)).unwrap(),
            mode
        );
    }
    for invalid in ["direct_post_jwt", "query", "fragment", ""] {
        assert!(serde_json::from_value::<ResponseMode>(serde_json::json!(invalid)).is_err());
    }
}
