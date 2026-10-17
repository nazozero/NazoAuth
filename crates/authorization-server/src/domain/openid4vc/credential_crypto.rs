use crate::ports::mdoc::MdocDocumentSigner;
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialTrustError, CredentialVerifierPort,
    PresentedCredential, VcIssuerTrustPolicy, VerifiedCredential,
};
use nazo_key_management::KeyManager;
use std::sync::Arc;

mod certificates;
pub(super) mod mdoc;
mod sd_jwt;
mod signer;

pub(crate) use certificates::Openid4vcSigningMaterial;
pub use certificates::parse_scoped_credential_trust_anchors;

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
        presentation: &'a PresentedCredential<'_>,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async move {
            let credential = match presentation.format {
                CredentialFormat::SdJwtVc => sd_jwt::verify(self, presentation),
                CredentialFormat::MsoMdoc => mdoc::verify(self, presentation),
            }?;
            // Certificate revocation does not establish the individual
            // credential's status. No credential status mechanism is supported.
            if credential.status.is_some() {
                return Err(CredentialTrustError::InvalidStatus);
            }
            Ok(credential)
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_credential_crypto.rs"]
mod tests;
