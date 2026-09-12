use nazo_auth::{PresentedClientCredentials, TokenClientAuthPresentation};

#[derive(Clone, Eq, PartialEq)]
pub enum BasicAuthorizationCredentials {
    Absent,
    Malformed,
    Present {
        client_id: String,
        client_secret: String,
    },
}

impl BasicAuthorizationCredentials {
    #[must_use]
    pub const fn scheme_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// Certificate and possession facts extracted by the deployment-specific HTTP adapter.
///
/// The token-management core receives these facts after the adapter has established that the
/// forwarding peer is trusted. PKI trust and registered-key binding are separate authorization
/// decisions. Keeping the value framework-neutral prevents `HttpRequest` and
/// `HeaderMap` from crossing into authentication policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientCertificateFacts {
    pub thumbprint: Option<String>,
    pub subject_dn: Option<String>,
    pub san_dns: Vec<String>,
    pub san_uri: Vec<String>,
    pub san_ip: Vec<String>,
    pub san_email: Vec<String>,
    pub verified_certificate_expiry: bool,
    /// Public certificates presented by the TLS peer, leaf first. A trusted
    /// forwarding adapter may supply the same RFC 9440 certificate chain.
    pub certificate_chain_der: Vec<Vec<u8>>,
    /// Chain verification against an explicitly configured deployment CA.
    /// This never follows merely from receiving a certificate header.
    pub deployment_trusted_chain: bool,
}

#[derive(Clone)]
pub struct TokenClientAuthTransportFacts {
    basic: BasicAuthorizationCredentials,
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl std::fmt::Debug for TokenClientAuthTransportFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let basic_credentials = match &self.basic {
            BasicAuthorizationCredentials::Absent => "absent",
            BasicAuthorizationCredentials::Malformed => "malformed",
            BasicAuthorizationCredentials::Present { .. } => "[REDACTED]",
        };
        formatter
            .debug_struct("TokenClientAuthTransportFacts")
            .field("basic_scheme_present", &self.basic.scheme_present())
            .field("basic_credentials", &basic_credentials)
            .field("form_client_id", &self.form_client_id)
            .field(
                "form_client_secret",
                &self.form_client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_assertion_type", &self.client_assertion_type)
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl TokenClientAuthTransportFacts {
    #[must_use]
    pub fn from_parts(
        basic: BasicAuthorizationCredentials,
        form_client_id: Option<String>,
        form_client_secret: Option<String>,
        client_assertion_type: Option<String>,
        client_assertion: Option<String>,
    ) -> Self {
        Self {
            basic,
            form_client_id,
            form_client_secret,
            client_assertion_type,
            client_assertion,
        }
    }

    #[must_use]
    pub fn presentation(&self) -> TokenClientAuthPresentation {
        TokenClientAuthPresentation {
            http_basic: self.basic.scheme_present(),
            form_client_id: self.form_client_id.is_some(),
            form_client_secret: self.form_client_secret.is_some(),
            client_assertion_type: self.client_assertion_type.is_some(),
            client_assertion: self.client_assertion.is_some(),
        }
    }

    #[must_use]
    pub fn basic_challenge(&self) -> bool {
        self.basic.scheme_present()
    }

    #[must_use]
    pub fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    #[must_use]
    pub fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    /// Applies the fixed credential-source precedence after the caller has resolved lookup-only
    /// hints. Registered client policy still decides whether the selected method is permitted.
    #[must_use]
    pub fn presented_credentials(
        &self,
        assertion_client_id: Option<String>,
        mtls_client_id: Option<String>,
    ) -> PresentedClientCredentials {
        if matches!(self.basic, BasicAuthorizationCredentials::Malformed) {
            return PresentedClientCredentials {
                method: "client_secret_basic".to_owned(),
                ..PresentedClientCredentials::default()
            };
        }
        if self.client_assertion_type.is_some() || self.client_assertion.is_some() {
            return PresentedClientCredentials {
                client_id: assertion_client_id,
                client_secret: None,
                client_assertion: self.client_assertion.clone(),
                method: "private_key_jwt".to_owned(),
            };
        }
        if let BasicAuthorizationCredentials::Present {
            client_id,
            client_secret,
        } = &self.basic
        {
            return PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: Some(client_secret.clone()),
                client_assertion: None,
                method: "client_secret_basic".to_owned(),
            };
        }
        match self.form_client_id.as_ref() {
            Some(client_id) if self.form_client_secret.is_some() => PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: self.form_client_secret.clone(),
                client_assertion: None,
                method: "client_secret_post".to_owned(),
            },
            Some(client_id) if mtls_client_id.as_deref() == Some(client_id) => {
                PresentedClientCredentials {
                    client_id: Some(client_id.clone()),
                    client_secret: None,
                    client_assertion: None,
                    method: "tls_client_auth".to_owned(),
                }
            }
            Some(client_id) => PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: None,
                client_assertion: None,
                method: "none".to_owned(),
            },
            None if mtls_client_id.is_some() => PresentedClientCredentials {
                client_id: mtls_client_id,
                client_secret: None,
                client_assertion: None,
                method: "tls_client_auth".to_owned(),
            },
            None => PresentedClientCredentials::default(),
        }
    }
}
