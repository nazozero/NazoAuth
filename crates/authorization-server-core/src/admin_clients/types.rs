use nazo_identity::TenantContext;

use crate::{OAuthClient, ValidatedClientRegistration};

/// Caller-supplied client secret used only by privileged management. It is
/// deliberately not serializable and its debug output
/// is redacted. The backing bytes are wiped when the value is dropped.
pub struct SuppliedClientSecret(Vec<u8>);

impl SuppliedClientSecret {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, &'static str> {
        let value = value.as_ref();
        if value.len() < 32
            || value.len() > 512
            || value.iter().any(|byte| {
                *byte == 0 || *byte == b'\r' || *byte == b'\n' || (*byte).is_ascii_control()
            })
        {
            return Err("supplied client secret has invalid size or characters");
        }
        let distinct = value
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if distinct.len() < 16 {
            return Err("supplied client secret has insufficient entropy");
        }
        Ok(Self(value.to_vec()))
    }

    pub(crate) fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }
}

impl std::fmt::Debug for SuppliedClientSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SuppliedClientSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Owns an undisclosed registration secret across asynchronous writes. Moving
/// this field does not release its plaintext; failure or cancellation wipes it.
#[derive(Clone, Default)]
pub struct PendingClientSecret(Option<String>);

impl From<Option<String>> for PendingClientSecret {
    fn from(value: Option<String>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for PendingClientSecret {
    type Target = Option<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PendingClientSecret {
    /// Call only after the accepting persistence owner acknowledges commit.
    pub fn take_after_commit(&mut self) -> Option<String> {
        self.0.take()
    }
}

impl std::fmt::Debug for PendingClientSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for PendingClientSecret {
    fn drop(&mut self) {
        wipe_secret_string(&mut self.0);
    }
}

/// Owned creation input shared by administrative and dynamic registration.
/// The registration moves once; its undisclosed secret retains a separate Drop owner.
pub struct PreparedClientWrite {
    pub client: OAuthClient,
    pub issued_secret: PendingClientSecret,
    pub client_secret_hash: Option<String>,
    pub registration_access_token_blake3: Option<String>,
}

#[derive(Clone)]
pub struct PreparedClientRegistration {
    pub tenant: TenantContext,
    pub registration: ValidatedClientRegistration,
    pub require_mtls_bound_tokens: bool,
    pub issued_secret: PendingClientSecret,
    pub client_secret_hash: Option<String>,
    pub registration_access_token_blake3: Option<String>,
}

impl std::fmt::Debug for PreparedClientRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientRegistration")
            .field("tenant", &self.tenant)
            .field("registration", &self.registration)
            .field("require_mtls_bound_tokens", &self.require_mtls_bound_tokens)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "registration_access_token_blake3",
                &self
                    .registration_access_token_blake3
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl PreparedClientRegistration {
    pub fn into_write(self) -> PreparedClientWrite {
        PreparedClientWrite {
            client: OAuthClient {
                id: uuid::Uuid::now_v7(),
                tenant_id: self.tenant.tenant_id.as_uuid(),
                realm_id: self.tenant.realm_id.as_uuid(),
                organization_id: self.tenant.organization_id.as_uuid(),
                registration: self.registration,
                require_mtls_bound_tokens: self.require_mtls_bound_tokens,
                is_active: true,
            },
            issued_secret: self.issued_secret,
            client_secret_hash: self.client_secret_hash,
            registration_access_token_blake3: self.registration_access_token_blake3,
        }
    }
}

impl std::ops::Deref for PreparedClientRegistration {
    type Target = ValidatedClientRegistration;

    fn deref(&self) -> &Self::Target {
        &self.registration
    }
}

impl std::ops::DerefMut for PreparedClientRegistration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registration
    }
}

#[derive(Clone)]
pub struct CreatedClient {
    pub client: OAuthClient,
    pub issued_secret: Option<String>,
}

impl std::fmt::Debug for CreatedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("client", &self.client)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Drop for CreatedClient {
    fn drop(&mut self) {
        wipe_secret_string(&mut self.issued_secret);
    }
}

fn wipe_secret_string(value: &mut Option<String>) {
    if let Some(secret) = value.take() {
        let mut bytes = secret.into_bytes();
        bytes.fill(0);
    }
}
