use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use crate::ExternalKeySigner;
use arc_swap::ArcSwap;
use base64::{Engine, encoded_len, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Prepublished,
    Active,
    Grace,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyHealthStatus {
    Healthy,
    Unhealthy,
}

// The lifecycle refresh interval is capped at one hour. Two intervals keep a
// transient database outage available without allowing indefinite signing from
// an obsolete generation.
pub(crate) const DATABASE_MAX_STALE: Duration =
    Duration::from_secs(crate::lifecycle::MAX_DATABASE_SNAPSHOT_STALENESS_SECONDS as u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyHealth {
    pub status: KeyHealthStatus,
    pub consecutive_failures: u32,
}

impl KeyHealth {
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            status: KeyHealthStatus::Healthy,
            consecutive_failures: 0,
        }
    }

    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self.status, KeyHealthStatus::Healthy)
    }
}

pub(crate) struct LifecycleHealth {
    healthy: AtomicBool,
    consecutive_failures: AtomicU32,
}

impl LifecycleHealth {
    fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> KeyHealth {
        KeyHealth {
            status: if self.healthy.load(Ordering::Acquire) {
                KeyHealthStatus::Healthy
            } else {
                KeyHealthStatus::Unhealthy
            },
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
        }
    }

    fn mark_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Release);
    }

    fn mark_failure(&self) {
        self.consecutive_failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .ok();
        self.healthy.store(false, Ordering::Release);
    }
}

/// Local private material shared by the active handle and the managed key
/// entry of one generation.
///
/// The DER remains because `database_local_private_key_pem` (mdoc export) is a
/// real consumer; the prepared key serves every request-time signing path and
/// for RSA algorithms now holds the parsed provider key pair, so the private
/// key is never re-parsed from DER per request.
pub(crate) struct LocalSigningMaterial {
    pub(crate) private_pkcs8_der: Vec<u8>,
    pub(crate) prepared: nazo_crypto::signature::PreparedSigningKey,
}

impl LocalSigningMaterial {
    pub(crate) fn new(
        algorithm: nazo_crypto::jwt::Algorithm,
        private_pkcs8_der: Vec<u8>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            prepared: nazo_crypto::signature::PreparedSigningKey::new(
                algorithm,
                &private_pkcs8_der,
            )?,
            private_pkcs8_der,
        })
    }
}

#[derive(Clone)]
pub(crate) enum KeyHandle {
    Local(Arc<LocalSigningMaterial>),
    External { key_ref: String },
}

#[derive(Clone)]
pub(crate) struct ExternalSigningKey {
    pub(crate) key_ref: String,
    pub(crate) signer: Arc<dyn ExternalKeySigner>,
}

#[derive(Clone)]
pub(crate) enum ActiveSigningKey {
    Local(Arc<LocalSigningMaterial>),
    External(ExternalSigningKey),
    /// Test-support behavior for exercising the local signing failure path.
    /// Production material is always a validated `LocalSigningMaterial`; an
    /// empty placeholder key is not representable.
    #[cfg(any(test, feature = "test-support"))]
    FailingForTest,
}

#[derive(Clone)]
pub(crate) struct StoredVerificationKey {
    pub(crate) public_jwk: Value,
    pub(crate) managed: ManagedKey,
    pub(crate) retire_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone)]
pub(crate) struct LoadedKeyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: nazo_crypto::jwt::Algorithm,
    pub(crate) active_signing_key: ActiveSigningKey,
    pub(crate) verification_keys: Vec<StoredVerificationKey>,
    pub(crate) request_object_decryption_key: Vec<u8>,
    pub(crate) request_object_encryption_jwk: Value,
    pub(crate) openid4vc_material: Option<Openid4vcMaterial>,
}

/// Verification material prepared once when a generation is published.
///
/// `algorithm` is the managed key's validated algorithm; `key` is the opaque
/// backend verification key decoded from the public JWK components. Snapshot
/// construction rejects any public JWK that cannot produce this material, so
/// request-time decoding never rebuilds it.
#[derive(Clone, Debug)]
pub(crate) struct PreparedVerification {
    pub(crate) algorithm: nazo_crypto::jwt::Algorithm,
    pub(crate) key: nazo_crypto::jwt::VerificationKey,
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub kid: String,
    pub public_jwk: Value,
    pub(crate) prepared: PreparedVerification,
    pub(crate) signing_purposes: BTreeSet<SigningPurpose>,
    pub(crate) retire_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl VerificationKey {
    #[must_use]
    pub fn can_sign(&self, purpose: SigningPurpose) -> bool {
        self.signing_purposes.contains(&purpose)
    }

    #[must_use]
    pub fn can_verify(&self) -> bool {
        self.retire_at
            .is_none_or(|retire_at| retire_at > Utc::now())
    }
}

#[derive(Clone, Debug)]
pub struct KeySnapshot {
    pub active_kid: String,
    pub active_alg: nazo_crypto::jwt::Algorithm,
    pub verification_keys: Vec<VerificationKey>,
    pub(crate) id_token_signing_algorithms: Vec<nazo_crypto::jwt::Algorithm>,
    pub(crate) response_signing_algorithms: Vec<nazo_crypto::jwt::Algorithm>,
    pub request_object_encryption_jwk: Value,
}

impl KeySnapshot {
    #[must_use]
    pub fn verification_key(&self, kid: &str) -> Option<&VerificationKey> {
        self.verification_keys
            .iter()
            .find(|key| key.kid == kid && key.can_verify())
    }

    #[must_use]
    pub fn signing_verification_key(
        &self,
        purpose: SigningPurpose,
        algorithm: nazo_crypto::jwt::Algorithm,
    ) -> Option<&VerificationKey> {
        let matches =
            |key: &&VerificationKey| key.can_sign(purpose) && key.prepared.algorithm == algorithm;
        self.verification_key(&self.active_kid)
            .filter(matches)
            .or_else(|| {
                self.verification_keys
                    .iter()
                    .filter(|key| key.kid != self.active_kid && key.can_verify())
                    .find(matches)
            })
    }

    #[must_use]
    pub fn response_signing_alg_values_supported(&self) -> Vec<&'static str> {
        self.response_signing_algorithms
            .iter()
            .filter_map(|algorithm| crate::serialization::signing_algorithm_name(*algorithm))
            .collect()
    }

    #[must_use]
    pub fn id_token_signing_alg_values_supported(&self) -> Vec<&'static str> {
        self.id_token_signing_algorithms
            .iter()
            .filter_map(|algorithm| crate::serialization::signing_algorithm_name(*algorithm))
            .collect()
    }

    #[must_use]
    pub fn jwks(&self) -> Value {
        crate::jwks::public_jwks(&self.verification_keys, &self.request_object_encryption_jwk)
    }
}

#[derive(Clone, Debug)]
pub struct KeySettings {
    pub rotation_interval: chrono::Duration,
    pub prepublish_window: chrono::Duration,
    pub verification_grace: chrono::Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    pub kid: String,
    pub status: KeyRecordStatus,
    pub algorithm: String,
    pub backend: String,
    pub locator: String,
    pub retire_at: Option<String>,
}

/// Operator-facing categorization derived from persisted keyset metadata.
///
/// Purpose-scoped signing keys are reported separately from rotation
/// candidates so operators cannot mistake them for the next OIDC active key.
/// Entries without explicit `purposes` are rotation keys and are reported as
/// `Prepublished` until selected through `active_kid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRecordStatus {
    Prepublished,
    PurposeScoped,
    Active,
    Grace,
    Retired,
}

impl KeyRecordStatus {
    /// Stable keyctl text used in the tab-separated list output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepublished => "prepublished",
            Self::PurposeScoped => "purpose-scoped",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExternalKeyRegistration {
    pub kid: String,
    pub algorithm: nazo_crypto::jwt::Algorithm,
    pub key_ref: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug)]
pub struct LocalKeyRegistration {
    pub algorithm: nazo_crypto::jwt::Algorithm,
    pub purposes: BTreeSet<SigningPurpose>,
}

/// Public material used by the OpenID4VC issuer and verifier.
///
/// This type deliberately contains only values that may be exposed to request
/// handlers. IACA private keys are held by [`Openid4vcMaterial`] and are never
/// part of this projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Openid4vcPublicMaterial {
    pub signing_kid: String,
    pub certificate_chain_pem: String,
    pub trust_anchors_pem: String,
    pub revocation_snapshot: Option<nazo_digital_credentials::CertificateRevocationSnapshot>,
}

/// Atomically managed OpenID4VC material for one tenant.
///
/// `iaca_private_materials` is encrypted with the rest of the database-backed
/// keyset. Keep the custom formatter below: debug output is routinely emitted
/// by test failures and operator tooling, and must not disclose private PEM.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Openid4vcMaterial {
    pub public: Openid4vcPublicMaterial,
    pub iaca_private_materials: BTreeMap<String, String>,
}

impl fmt::Debug for Openid4vcMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Openid4vcMaterial")
            .field("public", &self.public)
            .field("iaca_private_materials", &"<redacted>")
            .finish()
    }
}

impl From<Openid4vcPublicMaterial> for Openid4vcMaterial {
    fn from(public: Openid4vcPublicMaterial) -> Self {
        Self {
            public,
            iaca_private_materials: BTreeMap::new(),
        }
    }
}

/// The latest persisted OpenID4VC material and the enclosing keyset revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Openid4vcState {
    pub revision: i64,
    pub material: Option<Openid4vcMaterial>,
}

pub(crate) struct KeyGeneration {
    pub(crate) loaded: LoadedKeyset,
    pub(crate) snapshot: Arc<KeySnapshot>,
    expires_at: Option<Instant>,
}

pub(crate) struct KeyManagerInner {
    pub(crate) generation: ArcSwap<KeyGeneration>,
    pub(crate) settings: KeySettings,
    pub(crate) health: Arc<LifecycleHealth>,
    pub(crate) database: crate::database::DatabaseKeysetBinding,
}

#[derive(Clone)]
pub struct KeyManager {
    pub(crate) inner: Arc<KeyManagerInner>,
}

pub struct HttpSigningLease {
    generation: Arc<KeyGeneration>,
    health: Arc<LifecycleHealth>,
    kid: String,
    algorithm: nazo_crypto::jwt::Algorithm,
    http_algorithm: &'static str,
}

impl HttpSigningLease {
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.http_algorithm
    }

    pub async fn sign(&self, signing_input: &[u8]) -> anyhow::Result<Signature> {
        if self.generation.is_expired() || !self.health.snapshot().is_healthy() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let selected = self
            .generation
            .loaded
            .selected_key(SigningPurpose::HttpMessage, self.algorithm)
            .filter(|selected| selected.kid == self.kid)
            .ok_or_else(|| {
                anyhow::anyhow!("HTTP signing lease no longer matches its generation")
            })?;
        sign_selected(&selected, signing_input)
            .await
            .map_err(anyhow::Error::from)
    }
}

/// A generation-pinned signer for the two OpenID4VC signing purposes.
///
/// The lease keeps its [`KeyGeneration`] alive, so certificate/public material
/// and the private signing key cannot rotate independently while a request is
/// using the lease.
#[derive(Clone)]
pub struct Openid4vcSigningLease {
    generation: Arc<KeyGeneration>,
    health: Arc<LifecycleHealth>,
    kid: String,
}

impl Openid4vcSigningLease {
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn material(&self) -> &Openid4vcPublicMaterial {
        &self
            .generation
            .loaded
            .openid4vc_material
            .as_ref()
            .expect("OpenID4VC signing lease always has managed material")
            .public
    }

    pub async fn encode_jwt<T: Serialize>(
        &self,
        purpose: SigningPurpose,
        header: &nazo_crypto::jwt::Header,
        claims: &T,
    ) -> nazo_crypto::Result<String> {
        encode_jwt_for_generation(
            &self.generation,
            &self.health,
            Some(&self.kid),
            purpose,
            header,
            claims,
        )
        .await
    }
}

impl Signer for Openid4vcSigningLease {
    async fn sign<'a>(&'a self, request: SignRequest<'a>) -> Result<Signature, SignError> {
        if self.generation.is_expired() || !self.health.snapshot().is_healthy() {
            return Err(SignError::KeyUnavailable);
        }
        if !matches!(
            request.purpose,
            SigningPurpose::Credential | SigningPurpose::PresentationRequest
        ) {
            return Err(SignError::KeyUnavailable);
        }
        let algorithm = crate::serialization::signing_algorithm_from_name(request.algorithm)
            .ok_or(SignError::UnsupportedAlgorithm)?;
        if algorithm != nazo_crypto::jwt::Algorithm::ES256 {
            return Err(SignError::UnsupportedAlgorithm);
        }
        let selected = self
            .generation
            .loaded
            .selected_key(request.purpose, algorithm)
            .filter(|selected| selected.kid == self.kid)
            .ok_or(SignError::KeyUnavailable)?;
        sign_selected(&selected, request.signing_input).await
    }
}

#[cfg(any(test, feature = "test-support"))]
pub enum TestSigningBehavior {
    Working,
    Failing,
    ExternalFailure { stderr: String },
}

impl LoadedKeyset {
    pub(crate) fn selected_key(
        &self,
        purpose: SigningPurpose,
        algorithm: nazo_crypto::jwt::Algorithm,
    ) -> Option<SelectedKey<'_>> {
        let algorithm_name = crate::serialization::signing_algorithm_name(algorithm)?;
        let active = self
            .verification_keys
            .iter()
            .find(|key| key.managed.kid == self.active_kid)?;
        if algorithm == self.active_alg
            && active.managed.algorithm == algorithm_name
            && active.managed.can_sign(purpose)
            && active.public_jwk.get("alg").and_then(Value::as_str) == Some(algorithm_name)
        {
            return Some(SelectedKey {
                kid: &self.active_kid,
                algorithm,
                handle: SelectedHandle::Active(&self.active_signing_key),
                public_jwk: &active.public_jwk,
            });
        }
        self.verification_keys.iter().find_map(|key| {
            if key.managed.kid == self.active_kid
                || !key.managed.can_sign(purpose)
                || key.managed.algorithm != algorithm_name
                || key.public_jwk.get("alg").and_then(Value::as_str) != Some(algorithm_name)
            {
                return None;
            }
            Some(SelectedKey {
                kid: &key.managed.kid,
                algorithm,
                handle: match &key.managed.handle {
                    KeyHandle::Local(material) => SelectedHandle::Local(material.as_ref()),
                    KeyHandle::External { key_ref } => {
                        let _ = key_ref;
                        return None;
                    }
                },
                public_jwk: &key.public_jwk,
            })
        })
    }
}

pub(crate) struct SelectedKey<'a> {
    pub(crate) kid: &'a str,
    pub(crate) algorithm: nazo_crypto::jwt::Algorithm,
    pub(crate) handle: SelectedHandle<'a>,
    pub(crate) public_jwk: &'a Value,
}

pub(crate) enum SelectedHandle<'a> {
    Active(&'a ActiveSigningKey),
    Local(&'a LocalSigningMaterial),
}

/// Parse a PEM certificate sequence at the key-management boundary. The
/// OpenID4VC bundle format is deliberately narrow: every block is a complete
/// X.509 certificate and the first block is the leaf certificate.
pub(crate) fn parse_openid4vc_certificate_chain(
    pem_text: &str,
    description: &str,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let blocks = pem::parse_many(pem_text.as_bytes())
        .map_err(|error| anyhow::anyhow!("failed to parse {description}: {error}"))?;
    if blocks.is_empty() {
        anyhow::bail!("OpenID4VC {description} must contain a certificate");
    }
    blocks
        .into_iter()
        .map(|block| {
            if block.tag() != "CERTIFICATE" {
                anyhow::bail!(
                    "OpenID4VC {description} contains PEM block {}, expected CERTIFICATE",
                    block.tag()
                );
            }
            let der = block.contents().to_vec();
            let (rest, _) = x509_parser::parse_x509_certificate(&der).map_err(|error| {
                anyhow::anyhow!("failed to parse OpenID4VC {description} certificate: {error}")
            })?;
            if !rest.is_empty() {
                anyhow::bail!(
                    "OpenID4VC {description} contains trailing bytes after a certificate"
                );
            }
            Ok(der)
        })
        .collect()
}

pub(crate) fn p256_public_key_from_jwk(jwk: &Value, description: &str) -> anyhow::Result<Vec<u8>> {
    let object = jwk
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{description} public JWK must be an object"))?;
    if object.get("kty").and_then(Value::as_str) != Some("EC")
        || object.get("crv").and_then(Value::as_str) != Some("P-256")
        || object.get("alg").and_then(Value::as_str) != Some("ES256")
        || object.get("use").and_then(Value::as_str) != Some("sig")
    {
        anyhow::bail!("{description} public JWK must be an ES256 signing key");
    }
    let x = URL_SAFE_NO_PAD
        .decode(
            object
                .get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{description} public JWK is missing x"))?,
        )
        .map_err(|error| anyhow::anyhow!("{description} public JWK x is invalid: {error}"))?;
    let y = URL_SAFE_NO_PAD
        .decode(
            object
                .get("y")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("{description} public JWK is missing y"))?,
        )
        .map_err(|error| anyhow::anyhow!("{description} public JWK y is invalid: {error}"))?;
    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!("{description} public JWK coordinates must be 32 bytes");
    }
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(nazo_crypto::ec::normalize_p256_public_key(&point)
        .map_err(|error| anyhow::anyhow!("{description} public JWK point is invalid: {error}"))?
        .to_vec())
}

pub(crate) fn p256_public_key_from_certificate(
    der: &[u8],
    description: &str,
) -> anyhow::Result<Vec<u8>> {
    let (rest, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("failed to parse {description}: {error}"))?;
    if !rest.is_empty() {
        anyhow::bail!("{description} contains trailing bytes after a certificate");
    }
    let point = certificate.public_key().subject_public_key.data.as_ref();
    Ok(nazo_crypto::ec::normalize_p256_public_key(point)
        .map_err(|error| anyhow::anyhow!("{description} is not an ES256 certificate: {error}"))?
        .to_vec())
}

pub(crate) fn openid4vc_material_is_revoked(material: &Openid4vcMaterial) -> anyhow::Result<bool> {
    let Some(snapshot) = material.public.revocation_snapshot.as_ref() else {
        return Ok(false);
    };
    let certificates = parse_openid4vc_certificate_chain(
        &material.public.certificate_chain_pem,
        "certificate chain",
    )?;
    let identity = nazo_digital_credentials::certificate_identity(&certificates[0]);
    Ok(snapshot.entries.iter().any(|entry| {
        entry.certificate == identity
            && entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked
    }))
}

impl KeyManager {
    /// Read operator key metadata from the repository-backed keyset.
    pub async fn database_list_keys(&self) -> anyhow::Result<Vec<KeyRecord>> {
        crate::database::list(&self.inner.settings, &self.inner.database).await
    }

    /// Register an external signer in the repository-backed keyset.
    pub async fn database_register_external(
        &self,
        registration: ExternalKeyRegistration,
    ) -> anyhow::Result<()> {
        let loaded = crate::database::register_external(
            &self.inner.settings,
            &self.inner.database,
            registration,
        )
        .await?;
        self.inner
            .generation
            .store(Arc::new(KeyGeneration::database(loaded)?));
        Ok(())
    }

    /// Register a purpose-scoped local key in the repository-backed keyset.
    pub async fn database_register_local(
        &self,
        registration: LocalKeyRegistration,
    ) -> anyhow::Result<String> {
        let (kid, loaded) = crate::database::register_local(
            &self.inner.settings,
            &self.inner.database,
            registration,
        )
        .await?;
        self.inner
            .generation
            .store(Arc::new(KeyGeneration::database(loaded)?));
        Ok(kid)
    }

    /// Return an in-memory local key only for material that must be handed to
    /// the mdoc certificate generator. It never reads a key file.
    pub fn database_local_private_key_pem(&self, kid: &str) -> anyhow::Result<String> {
        crate::database::local_private_key_pem(&self.inner.generation.load().loaded, kid)
    }

    /// Read the latest OpenID4VC material from the tenant's database-backed
    /// keyset. The persisted revocation timestamps are returned unchanged;
    /// request handling uses the generation-pinned projection instead.
    pub async fn database_openid4vc_state(&self) -> anyhow::Result<Openid4vcState> {
        crate::database::openid4vc_state(&self.inner.database, &self.inner.settings).await
    }

    /// Atomically commit OpenID4VC public and private material as one keyset
    /// generation. A stale expected revision is a conflict and is never
    /// retried with the caller's material.
    pub async fn database_commit_openid4vc(
        &self,
        expected_revision: i64,
        material: Openid4vcMaterial,
        new_private_key_pem: Option<String>,
    ) -> anyhow::Result<()> {
        let loaded = crate::database::commit_openid4vc(
            &self.inner.settings,
            &self.inner.database,
            expected_revision,
            material,
            new_private_key_pem,
        )
        .await?;
        self.inner
            .generation
            .store(Arc::new(KeyGeneration::database(loaded)?));
        Ok(())
    }

    /// Return the public OpenID4VC view from the currently published
    /// generation. The returned `Arc` remains pinned to that generation after
    /// a subsequent refresh or rotation.
    #[must_use]
    pub fn openid4vc_public_material(&self) -> Option<Arc<Openid4vcPublicMaterial>> {
        self.inner
            .generation
            .load()
            .loaded
            .openid4vc_material
            .as_ref()
            .map(|material| Arc::new(material.public.clone()))
    }

    /// Install managed material on an in-memory fixture without involving a
    /// repository. This exists only for consumers compiled with the
    /// `test-support` feature; production generations are published by the
    /// database CAS path above.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_openid4vc_material_for_test<M>(&self, material: M)
    where
        M: Into<Openid4vcMaterial>,
    {
        let mut loaded = self.inner.generation.load().loaded.clone();
        loaded.openid4vc_material = Some(material.into());
        self.inner
            .generation
            .store(Arc::new(KeyGeneration::database(loaded).expect(
                "test fixture generation must contain valid key material",
            )));
    }

    /// Pin the currently published OpenID4VC signing key and its matching
    /// certificate/public projection to one lease.
    pub fn prepare_openid4vc_signing(&self) -> anyhow::Result<Openid4vcSigningLease> {
        if !self.is_healthy() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let generation = self.inner.generation.load_full();
        if generation.is_expired() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let material = generation
            .loaded
            .openid4vc_material
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenID4VC signing material is unavailable"))?;
        let credential = generation
            .loaded
            .selected_key(
                SigningPurpose::Credential,
                nazo_crypto::jwt::Algorithm::ES256,
            )
            .ok_or_else(|| anyhow::anyhow!("OpenID4VC credential signing key unavailable"))?;
        let presentation = generation
            .loaded
            .selected_key(
                SigningPurpose::PresentationRequest,
                nazo_crypto::jwt::Algorithm::ES256,
            )
            .ok_or_else(|| {
                anyhow::anyhow!("OpenID4VC presentation-request signing key unavailable")
            })?;
        if credential.kid != presentation.kid || credential.kid != material.public.signing_kid {
            anyhow::bail!(
                "OpenID4VC signing certificate does not match one credential and presentation-request ES256 key"
            );
        }
        if openid4vc_material_is_revoked(material)? {
            anyhow::bail!("OpenID4VC signing certificate is revoked");
        }
        let kid = credential.kid.to_owned();
        Ok(Openid4vcSigningLease {
            generation,
            health: Arc::clone(&self.inner.health),
            kid,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(algorithm: nazo_crypto::jwt::Algorithm) -> Self {
        Self::for_test_behavior(algorithm, TestSigningBehavior::Working)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test_behavior(
        algorithm: nazo_crypto::jwt::Algorithm,
        behavior: TestSigningBehavior,
    ) -> Self {
        let material = crate::serialization::generate_key_material(algorithm)
            .expect("test signing key should generate");
        let kid = format!(
            "test-{}",
            crate::serialization::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk = crate::serialization::public_jwk_from_private_der(
            &kid,
            algorithm,
            &material.private_pkcs8_der,
        )
        .expect("test public JWK should derive");
        let local_material = Arc::new(
            LocalSigningMaterial::new(algorithm, material.private_pkcs8_der)
                .expect("test signing material should be usable"),
        );
        let active_signing_key = match behavior {
            TestSigningBehavior::Working => ActiveSigningKey::Local(Arc::clone(&local_material)),
            TestSigningBehavior::Failing => ActiveSigningKey::FailingForTest,
            TestSigningBehavior::ExternalFailure { stderr: _ } => {
                ActiveSigningKey::External(ExternalSigningKey {
                    key_ref: "kms://test/failure".to_owned(),
                    signer: Arc::new(crate::test_support::FailingExternalKeySigner),
                })
            }
        };
        let loaded = LoadedKeyset {
            active_kid: kid.clone(),
            active_alg: algorithm,
            active_signing_key,
            verification_keys: vec![StoredVerificationKey {
                public_jwk,
                retire_at: None,
                managed: ManagedKey {
                    kid,
                    algorithm: crate::serialization::signing_algorithm_name(algorithm)
                        .unwrap()
                        .to_owned(),
                    purposes: all_signing_purposes(),
                    state: KeyState::Active,
                    handle: KeyHandle::Local(local_material),
                },
            }],
            request_object_decryption_key: test_request_object_decryption_key()
                .expect("test request object decryption key"),
            request_object_encryption_jwk: Value::Null,
            openid4vc_material: None,
        };
        let mut loaded = loaded;
        loaded.request_object_encryption_jwk =
            crate::request_object_encryption::request_object_encryption_jwk(
                &loaded.request_object_decryption_key,
            )
            .expect("test request object encryption JWK");
        let generation = KeyGeneration::database(loaded)
            .expect("test keyset must contain valid signing and verification material");
        Self {
            inner: Arc::new(KeyManagerInner {
                generation: ArcSwap::from_pointee(generation),
                settings: KeySettings {
                    rotation_interval: chrono::Duration::days(90),
                    prepublish_window: chrono::Duration::days(1),
                    verification_grace: chrono::Duration::minutes(10),
                },
                health: Arc::new(LifecycleHealth::new()),
                database: crate::database::DatabaseKeysetBinding {
                    tenant_id: uuid::Uuid::now_v7(),
                    repository: Arc::new(crate::test_support::MemorySigningKeyRepository::default()),
                    wrapping_keys: crate::test_support::wrapping_key_ring(),
                    external_signer: None,
                },
            }),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test_with_auxiliary(algorithm: nazo_crypto::jwt::Algorithm) -> Self {
        let manager = Self::for_test(nazo_crypto::jwt::Algorithm::EdDSA);
        let mut loaded = manager.inner.generation.load().loaded.clone();
        let material = crate::serialization::generate_key_material(algorithm).unwrap();
        let kid = format!(
            "test-aux-{}",
            crate::serialization::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk = crate::serialization::public_jwk_from_private_der(
            &kid,
            algorithm,
            &material.private_pkcs8_der,
        )
        .unwrap();
        loaded.verification_keys.push(StoredVerificationKey {
            public_jwk,
            retire_at: None,
            managed: ManagedKey {
                kid,
                algorithm: crate::serialization::signing_algorithm_name(algorithm)
                    .unwrap()
                    .to_owned(),
                purposes: [
                    SigningPurpose::IdToken,
                    SigningPurpose::Jarm,
                    SigningPurpose::Introspection,
                    SigningPurpose::Credential,
                    SigningPurpose::PresentationRequest,
                ]
                .into_iter()
                .collect(),
                state: KeyState::Active,
                handle: KeyHandle::Local(Arc::new(
                    LocalSigningMaterial::new(algorithm, material.private_pkcs8_der)
                        .expect("test auxiliary key material should be usable"),
                )),
            },
        });
        manager
            .inner
            .generation
            .store(Arc::new(KeyGeneration::database(loaded).expect(
                "test auxiliary generation must contain valid key material",
            )));
        manager
    }

    /// Validate the sealed repository generation, including its public/private
    /// correspondence and request-object key material.
    pub async fn database_validate(&self) -> anyhow::Result<()> {
        crate::database::validate(&self.inner.settings, &self.inner.database).await
    }

    /// Opaque repository generation revision for an operator result.
    pub async fn database_revision(&self) -> anyhow::Result<String> {
        crate::database::revision(&self.inner.database).await
    }

    pub async fn load_or_create_database(
        settings: KeySettings,
        external_signer: Option<Arc<dyn ExternalKeySigner>>,
        tenant_id: uuid::Uuid,
        repository: Arc<dyn crate::SigningKeyRepository>,
        wrapping_keys: crate::SigningKeyWrappingKeyRing,
    ) -> anyhow::Result<Self> {
        let (loaded, database) = crate::database::load_or_create(
            &settings,
            external_signer,
            tenant_id,
            repository,
            wrapping_keys,
        )
        .await?;
        Ok(Self {
            inner: Arc::new(KeyManagerInner {
                generation: ArcSwap::from_pointee(KeyGeneration::database(loaded)?),
                settings,
                health: Arc::new(LifecycleHealth::new()),
                database,
            }),
        })
    }

    #[must_use]
    pub fn health(&self) -> KeyHealth {
        let health = self.inner.health.snapshot();
        if self.inner.generation.load().is_expired() {
            KeyHealth {
                status: KeyHealthStatus::Unhealthy,
                consecutive_failures: health.consecutive_failures,
            }
        } else {
            health
        }
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.health().is_healthy()
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<KeySnapshot> {
        Arc::clone(&self.inner.generation.load().snapshot)
    }

    pub async fn encode_jwt<T: Serialize>(
        &self,
        purpose: SigningPurpose,
        header: &nazo_crypto::jwt::Header,
        claims: &T,
    ) -> nazo_crypto::Result<String> {
        let generation = self.inner.generation.load_full();
        encode_jwt_for_generation(
            &generation,
            &self.inner.health,
            None,
            purpose,
            header,
            claims,
        )
        .await
    }

    pub fn prepare_http_signing(&self) -> anyhow::Result<HttpSigningLease> {
        if !self.is_healthy() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let generation = self.inner.generation.load_full();
        let selected = generation
            .loaded
            .selected_key(SigningPurpose::HttpMessage, generation.loaded.active_alg)
            .ok_or_else(|| anyhow::anyhow!("HTTP message signing key unavailable"))?;
        let http_algorithm = match selected.algorithm {
            nazo_crypto::jwt::Algorithm::EdDSA => "ed25519",
            nazo_crypto::jwt::Algorithm::RS256 => "rsa-v1_5-sha256",
            nazo_crypto::jwt::Algorithm::ES256 => "ecdsa-p256-sha256",
            _ => anyhow::bail!("unsupported HTTP message signing algorithm"),
        };
        Ok(HttpSigningLease {
            algorithm: selected.algorithm,
            kid: selected.kid.to_owned(),
            http_algorithm,
            generation,
            health: Arc::clone(&self.inner.health),
        })
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let result = crate::database::refresh(&self.inner.settings, &self.inner.database)
            .await
            .and_then(KeyGeneration::database);
        match result {
            Ok(generation) => {
                self.inner.generation.store(Arc::new(generation));
                self.inner.health.mark_success();
                Ok(())
            }
            Err(error) => {
                self.inner.health.mark_failure();
                Err(error)
            }
        }
    }
}

pub(crate) async fn encode_jwt_for_generation<T: Serialize>(
    generation: &Arc<KeyGeneration>,
    health: &LifecycleHealth,
    expected_kid: Option<&str>,
    purpose: SigningPurpose,
    header: &nazo_crypto::jwt::Header,
    claims: &T,
) -> nazo_crypto::Result<String> {
    if generation.is_expired() || !health.snapshot().is_healthy() {
        return Err(nazo_crypto::CryptoError::InvalidKey);
    }
    if expected_kid.is_some()
        && !matches!(
            purpose,
            SigningPurpose::Credential | SigningPurpose::PresentationRequest
        )
    {
        return Err(nazo_crypto::CryptoError::UnsupportedAlgorithm);
    }
    if expected_kid.is_some() && header.alg != nazo_crypto::jwt::Algorithm::ES256 {
        return Err(nazo_crypto::CryptoError::UnsupportedAlgorithm);
    }
    let selected = generation
        .loaded
        .selected_key(purpose, header.alg)
        .ok_or(nazo_crypto::CryptoError::UnsupportedAlgorithm)?;
    if expected_kid.is_some_and(|kid| kid != selected.kid)
        || header.kid.as_deref().is_some_and(|kid| kid != selected.kid)
    {
        return Err(nazo_crypto::CryptoError::UnsupportedAlgorithm);
    }
    let mut header = header.clone();
    header.kid = Some(selected.kid.to_owned());
    let header_json =
        serde_json::to_vec(&header).map_err(|_| nazo_crypto::CryptoError::InvalidInput)?;
    let claims_json =
        serde_json::to_vec(claims).map_err(|_| nazo_crypto::CryptoError::InvalidInput)?;
    let mut signing_input = String::with_capacity(
        encoded_len(header_json.len(), false)
            .expect("JWT header is too large to encode")
            .saturating_add(1)
            .saturating_add(
                encoded_len(claims_json.len(), false).expect("JWT claims are too large to encode"),
            ),
    );
    URL_SAFE_NO_PAD.encode_string(&header_json, &mut signing_input);
    signing_input.push('.');
    URL_SAFE_NO_PAD.encode_string(&claims_json, &mut signing_input);
    drop(header_json);
    drop(claims_json);
    let signature = sign_selected(&selected, signing_input.as_bytes())
        .await
        .map_err(|_| nazo_crypto::CryptoError::OperationFailed)?;
    signing_input.reserve(
        encoded_len(signature.as_bytes().len(), false)
            .expect("JWT signature is too large to encode")
            .saturating_add(1),
    );
    signing_input.push('.');
    URL_SAFE_NO_PAD.encode_string(signature.as_bytes(), &mut signing_input);
    Ok(signing_input)
}

impl Signer for KeyManager {
    async fn sign<'a>(&'a self, request: SignRequest<'a>) -> Result<Signature, SignError> {
        if !self.is_healthy() {
            return Err(SignError::KeyUnavailable);
        }
        let algorithm = crate::serialization::signing_algorithm_from_name(request.algorithm)
            .ok_or(SignError::UnsupportedAlgorithm)?;
        let generation = self.inner.generation.load_full();
        let selected = generation
            .loaded
            .selected_key(request.purpose, algorithm)
            .ok_or(SignError::KeyUnavailable)?;
        sign_selected(&selected, request.signing_input).await
    }
}

async fn sign_selected(selected: &SelectedKey<'_>, input: &[u8]) -> Result<Signature, SignError> {
    let local_sign = |material: &LocalSigningMaterial| {
        material
            .prepared
            .sign(input)
            .map(Signature::new)
            .map_err(|_| SignError::SigningFailed)
    };
    match &selected.handle {
        SelectedHandle::Active(ActiveSigningKey::Local(material)) => local_sign(material.as_ref()),
        #[cfg(any(test, feature = "test-support"))]
        SelectedHandle::Active(ActiveSigningKey::FailingForTest) => Err(SignError::SigningFailed),
        SelectedHandle::Active(ActiveSigningKey::External(external)) => {
            crate::external::sign_external(
                external,
                selected.kid,
                selected.algorithm,
                selected.public_jwk,
                input,
            )
            .await
        }
        SelectedHandle::Local(material) => local_sign(material),
    }
}

impl KeyGeneration {
    /// Prepares all per-generation material before publication. A failure
    /// rejects the whole generation; a partially initialized object is never
    /// handed to `ArcSwap`.
    fn database(loaded: LoadedKeyset) -> anyhow::Result<Self> {
        let snapshot = Arc::new(snapshot_from_loaded(&loaded)?);
        Ok(Self {
            loaded,
            snapshot,
            expires_at: Some(Instant::now() + DATABASE_MAX_STALE),
        })
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|deadline| Instant::now() > deadline)
    }
}

/// Build the prepared verification material for a managed key once, at
/// snapshot/generation construction. Runs the same JWK `alg`/`use`/private-field
/// checks and component decoding the request-time path previously repeated for
/// every token; a JWK that cannot produce verification material is rejected.
fn key_ops_allow_verification(key_ops: Option<&Value>) -> bool {
    match key_ops {
        None => true,
        Some(Value::Array(operations)) => {
            operations.len() == 1 && operations[0].as_str() == Some("verify")
        }
        Some(_) => false,
    }
}

fn prepared_verification(
    public_jwk: &Value,
    algorithm: nazo_crypto::jwt::Algorithm,
) -> Option<PreparedVerification> {
    use nazo_crypto::jwt::VerificationKey as JwtVerificationKey;
    let algorithm_name = crate::serialization::signing_algorithm_name(algorithm)?;
    if public_jwk.get("d").is_some()
        || public_jwk
            .get("alg")
            .and_then(Value::as_str)
            .is_some_and(|value| value != algorithm_name)
        || public_jwk
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
        || !key_ops_allow_verification(public_jwk.get("key_ops"))
    {
        return None;
    }
    let key = match algorithm {
        nazo_crypto::jwt::Algorithm::EdDSA
            if public_jwk.get("kty").and_then(Value::as_str) == Some("OKP")
                && public_jwk.get("crv").and_then(Value::as_str) == Some("Ed25519") =>
        {
            let x = public_jwk.get("x")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32 {
                return None;
            }
            JwtVerificationKey::from_ed_components(x).ok()?
        }
        nazo_crypto::jwt::Algorithm::RS256 | nazo_crypto::jwt::Algorithm::PS256
            if public_jwk.get("kty").and_then(Value::as_str) == Some("RSA") =>
        {
            let modulus = public_jwk.get("n")?.as_str()?;
            let exponent = public_jwk.get("e")?.as_str()?;
            if !nazo_auth::rsa_public_key_components_are_safe(
                &URL_SAFE_NO_PAD.decode(modulus).ok()?,
                &URL_SAFE_NO_PAD.decode(exponent).ok()?,
            ) {
                return None;
            }
            JwtVerificationKey::from_rsa_components(modulus, exponent).ok()?
        }
        nazo_crypto::jwt::Algorithm::ES256
            if public_jwk.get("kty").and_then(Value::as_str) == Some("EC")
                && public_jwk.get("crv").and_then(Value::as_str) == Some("P-256") =>
        {
            let x = public_jwk.get("x")?.as_str()?;
            let y = public_jwk.get("y")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32
                || URL_SAFE_NO_PAD.decode(y).ok()?.len() != 32
            {
                return None;
            }
            JwtVerificationKey::from_ec_components(x, y).ok()?
        }
        _ => return None,
    };
    Some(PreparedVerification { algorithm, key })
}

pub(crate) fn snapshot_from_loaded(loaded: &LoadedKeyset) -> anyhow::Result<KeySnapshot> {
    const ORDERED: [nazo_crypto::jwt::Algorithm; 4] = [
        nazo_crypto::jwt::Algorithm::EdDSA,
        nazo_crypto::jwt::Algorithm::RS256,
        nazo_crypto::jwt::Algorithm::ES256,
        nazo_crypto::jwt::Algorithm::PS256,
    ];
    let id_token_signing_algorithms = ORDERED
        .into_iter()
        .filter(|algorithm| {
            loaded
                .selected_key(SigningPurpose::IdToken, *algorithm)
                .is_some()
        })
        .collect();
    let response_signing_algorithms = ORDERED
        .into_iter()
        .filter(|algorithm| {
            loaded
                .selected_key(SigningPurpose::IdToken, *algorithm)
                .is_some()
                || loaded
                    .selected_key(SigningPurpose::Jarm, *algorithm)
                    .is_some()
                || loaded
                    .selected_key(SigningPurpose::Introspection, *algorithm)
                    .is_some()
        })
        .collect();
    let verification_keys = loaded
        .verification_keys
        .iter()
        .filter(|key| key.managed.can_verify())
        .map(|key| {
            let algorithm =
                crate::serialization::signing_algorithm_from_name(&key.managed.algorithm)
                    .ok_or_else(|| {
                        anyhow::anyhow!("managed key {} has unsupported algorithm", key.managed.kid)
                    })?;
            let prepared = prepared_verification(&key.public_jwk, algorithm).ok_or_else(|| {
                anyhow::anyhow!(
                    "managed key {} public JWK cannot produce verification material",
                    key.managed.kid
                )
            })?;
            Ok(VerificationKey {
                kid: key.managed.kid.clone(),
                public_jwk: key.public_jwk.clone(),
                prepared,
                signing_purposes: if key.managed.state == KeyState::Active {
                    key.managed.purposes.clone()
                } else {
                    BTreeSet::new()
                },
                retire_at: key.retire_at,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(KeySnapshot {
        active_kid: loaded.active_kid.clone(),
        active_alg: loaded.active_alg,
        verification_keys,
        id_token_signing_algorithms,
        response_signing_algorithms,
        request_object_encryption_jwk: loaded.request_object_encryption_jwk.clone(),
    })
}

#[cfg(any(test, feature = "test-support"))]
fn test_request_object_decryption_key() -> anyhow::Result<Vec<u8>> {
    crate::serialization::generate_rsa_pkcs8_pem(2048)
}

#[cfg(any(test, feature = "test-support"))]
fn all_signing_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::Introspection,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
        SigningPurpose::SecurityEvent,
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect()
}

#[derive(Clone)]
pub struct ManagedKey {
    pub kid: String,
    pub algorithm: String,
    pub purposes: BTreeSet<SigningPurpose>,
    pub state: KeyState,
    pub(crate) handle: KeyHandle,
}

impl ManagedKey {
    #[must_use]
    pub fn can_sign(&self, purpose: SigningPurpose) -> bool {
        self.state == KeyState::Active && self.purposes.contains(&purpose)
    }

    #[must_use]
    pub fn can_verify(&self) -> bool {
        matches!(
            self.state,
            KeyState::Prepublished | KeyState::Active | KeyState::Grace
        )
    }
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
