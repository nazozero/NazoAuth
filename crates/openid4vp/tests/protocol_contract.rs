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
