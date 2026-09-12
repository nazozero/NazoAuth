//! Local semantic test signer; deliberately runs without a runtime or Native host.

use super::MdocDocumentSigner;
use mdoc_rs::builder::{CoseSigner, DocumentBuilder};
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{CredentialFuture, CredentialTrustError};
use nazo_key_management::Openid4vcSigningLease;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};

pub(crate) struct LocalTestMdocDocumentSigner;

impl MdocDocumentSigner for LocalTestMdocDocumentSigner {
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
            let leaf =
                CertificateDer::pem_slice_iter(lease.material().certificate_chain_pem.as_bytes())
                    .next()
                    .expect("pinned certificate")
                    .expect("pinned certificate PEM");
            assert_eq!(
                certificate_der,
                leaf.as_ref(),
                "builder and signing lease must share the selected certificate"
            );
            builder
                .sign(&LocalLeaseSigner {
                    lease,
                    certificate_der,
                })
                .map_err(|_| CredentialTrustError::Unavailable)
        })
    }
}

struct LocalLeaseSigner {
    lease: Openid4vcSigningLease,
    certificate_der: Vec<u8>,
}

impl CoseSigner for LocalLeaseSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, mdoc_rs::MdocError> {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let mut future = Box::pin(self.lease.sign(SignRequest {
            purpose: SigningPurpose::Credential,
            algorithm: "ES256",
            signing_input: tbs,
        }));
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result
                .map(nazo_auth::Signature::into_bytes)
                .map_err(|error| mdoc_rs::MdocError::Issuance(error.to_string())),
            Poll::Pending => Err(mdoc_rs::MdocError::Issuance(
                "local test lease unexpectedly required external execution".to_owned(),
            )),
        }
    }

    fn algorithm(&self) -> i64 {
        -7
    }
    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}
