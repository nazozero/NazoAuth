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
mod status;

pub(crate) use certificates::Openid4vcSigningMaterial;
pub use certificates::parse_scoped_credential_trust_anchors;

#[derive(Clone)]
pub struct Openid4vcCredentialCrypto {
    keyset: KeyManager,
    mdoc_signer: Arc<dyn MdocDocumentSigner>,
    issuer_trust_policy: VcIssuerTrustPolicy,
    revocation_policy: crate::policy::Openid4vcRevocationPolicy,
    status_resolver: Option<Arc<dyn crate::ports::credential_status::CredentialStatusResolver>>,
}

impl CredentialVerifierPort for Openid4vcCredentialCrypto {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential<'_>,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async move {
            let (credential, issuer_chain) = match presentation.format {
                CredentialFormat::SdJwtVc => sd_jwt::verify(self, presentation),
                CredentialFormat::MsoMdoc => mdoc::verify(self, presentation),
            }?;
            if let Some(reference) = &credential.status {
                status::verify(
                    self,
                    presentation,
                    reference,
                    &credential.issuer,
                    &issuer_chain,
                )
                .await?;
            }
            Ok(credential)
        })
    }
}

impl Openid4vcCredentialCrypto {
    pub fn with_status_resolver(
        mut self,
        resolver: Arc<dyn crate::ports::credential_status::CredentialStatusResolver>,
    ) -> Self {
        self.status_resolver = Some(resolver);
        self
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_credential_crypto.rs"]
mod tests;
