//! Capability for an externally held signing key.

pub struct ExternalSignRequest<'a> {
    pub kid: &'a str,
    pub algorithm: jsonwebtoken::Algorithm,
    pub key_ref: &'a str,
    pub signing_input: &'a [u8],
}

pub trait ExternalKeySigner: Send + Sync {
    fn sign<'a>(
        &'a self,
        request: ExternalSignRequest<'a>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<nazo_auth::Signature, nazo_auth::SignError>>
                + Send
                + 'a,
        >,
    >;
}
