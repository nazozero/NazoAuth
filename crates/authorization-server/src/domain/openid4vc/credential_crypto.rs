use crate::ports::mdoc::MdocDocumentSigner;
#[cfg(test)]
use coset::CborSerializable;
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialTrustError, CredentialVerifierPort,
    PresentedCredential, VcIssuerTrustPolicy, VerifiedCredential,
};
use nazo_key_management::KeyManager;
use std::sync::Arc;

mod certificates;
mod mdoc;
mod sd_jwt;
mod signer;

pub use certificates::parse_scoped_credential_trust_anchors;
#[cfg(test)]
pub(crate) use mdoc::{
    mdoc_failed_assessments_accepted, mdoc_holder_key, standard_device_authentication_bytes,
};

#[cfg(test)]
use mdoc::verify_direct_scoped_trust_anchor;
#[cfg(test)]
use mdoc::{mdoc_assessments_accepted, verify_certificate_chain_at};

#[derive(Clone)]
pub struct Openid4vcCredentialCrypto {
    keyset: KeyManager,
    mdoc_signer: Arc<dyn MdocDocumentSigner>,
    issuer_trust_policy: VcIssuerTrustPolicy,
    revocation_policy: crate::policy::Openid4vcRevocationPolicy,
}

impl CredentialVerifierPort for Openid4vcCredentialCrypto {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async move {
            match presentation.format {
                CredentialFormat::SdJwtVc => sd_jwt::verify(self, presentation),
                CredentialFormat::MsoMdoc => mdoc::verify(self, presentation),
            }
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_credential_crypto.rs"]
mod tests;
