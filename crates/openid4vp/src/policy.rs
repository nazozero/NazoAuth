use crate::{ClientIdPrefix, RequestMethod, ResponseMode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationPolicy {
    pub client_id_prefix: ClientIdPrefix,
    pub request_method: RequestMethod,
    pub response_mode: ResponseMode,
    pub haip: bool,
}

impl PresentationPolicy {
    pub fn validate(&self) -> Result<(), PresentationPolicyError> {
        if self.client_id_prefix == ClientIdPrefix::RedirectUri
            && self.request_method != RequestMethod::UrlQuery
        {
            return Err(PresentationPolicyError::RedirectUriCannotSign);
        }
        if matches!(
            self.client_id_prefix,
            ClientIdPrefix::X509Hash | ClientIdPrefix::X509SanDns
        ) && self.request_method == RequestMethod::UrlQuery
        {
            return Err(PresentationPolicyError::X509RequiresSignedRequest);
        }
        if self.haip
            && (self.client_id_prefix != ClientIdPrefix::X509Hash
                || !matches!(
                    self.request_method,
                    RequestMethod::RequestUriSignedGet | RequestMethod::RequestUriSignedPost
                )
                || self.response_mode != ResponseMode::DirectPostJwt)
        {
            return Err(PresentationPolicyError::HaipRequirement);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationPolicyError {
    #[error("redirect_uri client identifiers cannot sign request objects")]
    RedirectUriCannotSign,
    #[error("X.509 client identifiers require a signed request object")]
    X509RequiresSignedRequest,
    #[error("HAIP requires x509_hash, signed request_uri, and direct_post.jwt")]
    HaipRequirement,
}
