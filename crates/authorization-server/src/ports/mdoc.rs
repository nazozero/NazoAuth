//! Execution capability for a fully prepared mdoc document and pinned key lease.

pub trait MdocDocumentSigner: Send + Sync {
    fn sign<'a>(
        &'a self,
        builder: mdoc_rs::builder::DocumentBuilder,
        lease: nazo_key_management::Openid4vcSigningLease,
        certificate_der: Vec<u8>,
    ) -> nazo_digital_credentials::CredentialFuture<
        'a,
        Result<
            mdoc_rs::model::document::IssuerSignedDocument,
            nazo_digital_credentials::CredentialTrustError,
        >,
    >;
}
