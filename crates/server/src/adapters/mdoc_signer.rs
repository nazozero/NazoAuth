//! Native execution bridge for a fully prepared mdoc document.

use mdoc_rs::builder::{CoseSigner, DocumentBuilder};
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{CredentialFuture, CredentialTrustError};
use nazo_key_management::Openid4vcSigningLease;
use nazo_oauth_server::ports::mdoc::MdocDocumentSigner;

pub(crate) struct TokioMdocDocumentSigner;

impl MdocDocumentSigner for TokioMdocDocumentSigner {
    fn sign<'a>(
        &'a self,
        builder: DocumentBuilder,
        lease: Openid4vcSigningLease,
        certificate_der: Vec<u8>,
    ) -> CredentialFuture<
        'a,
        Result<mdoc_rs::model::document::IssuerSignedDocument, CredentialTrustError>,
    > {
        Box::pin(async move {
            let signer = AsyncCoseSigner {
                lease,
                certificate_der,
                runtime: tokio::runtime::Handle::current(),
            };
            tokio::task::spawn_blocking(move || builder.sign(&signer))
                .await
                .map_err(|_| CredentialTrustError::Unavailable)?
                .map_err(|_| CredentialTrustError::Unavailable)
        })
    }
}

pub(super) struct AsyncCoseSigner {
    pub(super) lease: nazo_key_management::Openid4vcSigningLease,
    pub(super) certificate_der: Vec<u8>,
    pub(super) runtime: tokio::runtime::Handle,
}

impl CoseSigner for AsyncCoseSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, mdoc_rs::MdocError> {
        self.runtime
            .block_on(self.lease.sign(SignRequest {
                purpose: SigningPurpose::Credential,
                algorithm: "ES256",
                signing_input: tbs,
            }))
            .map(nazo_auth::Signature::into_bytes)
            .map_err(|error| mdoc_rs::MdocError::Issuance(error.to_string()))
    }

    fn algorithm(&self) -> i64 {
        -7
    }
    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/mdoc_signer.rs"]
mod tests;
