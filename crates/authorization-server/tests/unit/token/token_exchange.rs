use super::*;

#[test]
fn token_exchange_binding_claims_preserve_sender_constraint_type() {
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::Bearer),
        (None, None)
    );
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::Dpop("dpop-jkt".to_owned())),
        (Some("dpop-jkt".to_owned()), None)
    );
    assert_eq!(
        token_exchange_binding_claims(TokenExchangeSenderBinding::MutualTls(
            "mtls-thumbprint".to_owned(),
        )),
        (None, Some("mtls-thumbprint".to_owned()))
    );
}
