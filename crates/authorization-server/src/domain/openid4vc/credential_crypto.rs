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

/// Controls whether an embedding may issue references to already published mdoc
/// Token Status Lists. Index allocation and publication remain the issuer's job.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MdocStatusIssuancePolicy {
    /// No mdoc status references may be issued. The shipped endpoints use this.
    #[default]
    Disabled,
    /// Validate a caller-allocated reference against its authenticated, available
    /// draft-21 list before incorporating it into the signed MSO.
    PublishedTokenStatusList,
}

#[derive(Clone)]
pub struct Openid4vcCredentialCrypto {
    keyset: KeyManager,
    issuer_trust_policy: VcIssuerTrustPolicy,
    revocation_policy: crate::policy::Openid4vcRevocationPolicy,
    mdoc_status_issuance: MdocStatusIssuancePolicy,
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
                CredentialFormat::MsoMdoc => mdoc::verify(self, presentation, chrono::Utc::now()),
            }?;
            if let Some(reference) = &credential.status {
                status::resolve(self, presentation.format, reference)
                    .await?
                    .verify(
                        self,
                        &presentation.additional_trust_anchors,
                        &credential.issuer,
                        &issuer_chain,
                    )?;
            }
            Ok(credential)
        })
    }
}

impl Openid4vcCredentialCrypto {
    /// Enable only after arranging durable index allocation and list publication.
    /// A resolver is also required; an unreachable or invalid list rejects issuance.
    pub fn with_mdoc_status_issuance(mut self, policy: MdocStatusIssuancePolicy) -> Self {
        self.mdoc_status_issuance = policy;
        self
    }

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
