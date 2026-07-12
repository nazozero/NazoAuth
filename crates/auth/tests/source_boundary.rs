use std::{fs, path::Path};

#[test]
fn server_signing_adapters_do_not_define_or_call_claim_forwarders() {
    let server_tokens =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../server/src/support/security/tokens.rs");
    let source =
        fs::read_to_string(&server_tokens).expect("server token adapter source must exist");

    for forbidden in [
        "pub(super) fn access_token_claims(",
        "pub(super) fn id_token_claims(",
        "pub(super) fn backchannel_logout_token_claims(",
        "pub(super) fn authorization_response_jwt_claims(",
        "let claims = access_token_claims(",
        "let claims = id_token_claims(",
        "let claims = backchannel_logout_token_claims(",
        "let claims = authorization_response_jwt_claims(",
    ] {
        assert!(
            !source.contains(forbidden),
            "server claim forwarding boundary remains: {forbidden}"
        );
    }

    for required in [
        "nazo_auth::access_token_claims(",
        "nazo_auth::id_token_claims(",
        "nazo_auth::backchannel_logout_token_claims(",
        "nazo_auth::authorization_response_jwt_claims(",
    ] {
        assert!(
            source.contains(required),
            "signing adapter must call public auth builder directly: {required}"
        );
    }
}
