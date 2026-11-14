use super::*;

#[test]
fn ciba_backchannel_preserves_its_invalid_client_status() {
    let token_error = OAuthEndpointError::invalid_client("failed", false);
    assert!(matches!(
        backchannel_profile_error(token_error),
        OAuthEndpointError::Token { fields, basic_challenge: false }
            if fields.status == StatusCode::UNAUTHORIZED && fields.error == "invalid_client"
    ));
    assert!(matches!(
        backchannel_profile_error(OAuthEndpointError::invalid_client("failed", true)),
        OAuthEndpointError::Token { fields, basic_challenge: true }
            if fields.status == StatusCode::UNAUTHORIZED && fields.error == "invalid_client"
    ));
    let other = OAuthEndpointError::token(StatusCode::BAD_REQUEST, "invalid_request", "bad", false);
    assert_eq!(backchannel_profile_error(other.clone()), other);
}
