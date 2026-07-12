use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use crate::local::SigningBackend;
use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Prepublished,
    Active,
    Grace,
    Retired,
}

#[derive(Clone)]
pub(crate) enum KeyHandle {
    Local(Vec<u8>),
    External { key_ref: String },
}

#[derive(Clone)]
pub(crate) struct ExternalSigningKey {
    pub(crate) command: Arc<Vec<String>>,
    pub(crate) key_ref: String,
    pub(crate) timeout: Duration,
}

#[derive(Clone)]
pub(crate) enum ActiveSigningKey {
    LocalPkcs8Der(Vec<u8>),
    ExternalCommand(ExternalSigningKey),
}

#[derive(Clone)]
pub(crate) struct StoredVerificationKey {
    pub(crate) public_jwk: Value,
    pub(crate) managed: ManagedKey,
}

#[derive(Clone)]
pub(crate) struct LoadedKeyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: jsonwebtoken::Algorithm,
    pub(crate) active_signing_key: ActiveSigningKey,
    pub(crate) verification_keys: Vec<StoredVerificationKey>,
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub kid: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug)]
pub struct KeySnapshot {
    pub active_kid: String,
    pub active_alg: jsonwebtoken::Algorithm,
    pub verification_keys: Vec<VerificationKey>,
    pub(crate) response_signing_algorithms: Vec<jsonwebtoken::Algorithm>,
}

impl KeySnapshot {
    #[must_use]
    pub fn verification_key(&self, kid: &str) -> Option<&VerificationKey> {
        self.verification_keys.iter().find(|key| key.kid == kid)
    }

    #[must_use]
    pub fn response_signing_alg_values_supported(&self) -> Vec<&'static str> {
        self.response_signing_algorithms
            .iter()
            .filter_map(|algorithm| crate::store::signing_algorithm_name(*algorithm))
            .collect()
    }

    #[must_use]
    pub fn jwks(&self) -> Value {
        crate::jwks::public_jwks(&self.verification_keys)
    }
}

#[derive(Clone, Debug)]
pub struct KeySettings {
    pub keys_dir: PathBuf,
    pub external_command: Vec<String>,
    pub external_timeout: Duration,
    pub rotation_interval: chrono::Duration,
    pub prepublish_window: chrono::Duration,
    pub verification_grace: chrono::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessageSignature {
    pub kid: String,
    pub algorithm: &'static str,
    pub signature: Vec<u8>,
}

pub(crate) struct KeyManagerInner {
    pub(crate) snapshot: ArcSwap<KeySnapshot>,
    pub(crate) loaded: ArcSwap<LoadedKeyset>,
    pub(crate) settings: KeySettings,
}

#[derive(Clone)]
pub struct KeyManager {
    pub(crate) inner: Arc<KeyManagerInner>,
}

#[cfg(feature = "test-support")]
pub enum TestSigningBehavior {
    Working,
    Failing,
    ExternalFailure { stderr: String },
}

impl LoadedKeyset {
    pub(crate) fn selected_key(
        &self,
        purpose: SigningPurpose,
        algorithm: jsonwebtoken::Algorithm,
    ) -> Option<SelectedKey<'_>> {
        if algorithm == self.active_alg {
            let public_jwk = &self
                .verification_keys
                .iter()
                .find(|key| key.managed.kid == self.active_kid)?
                .public_jwk;
            return Some(SelectedKey {
                kid: &self.active_kid,
                algorithm,
                handle: SelectedHandle::Active(&self.active_signing_key),
                public_jwk,
            });
        }
        let algorithm_name = crate::store::signing_algorithm_name(algorithm)?;
        self.verification_keys.iter().find_map(|key| {
            if !key.managed.can_sign(purpose)
                || key.public_jwk.get("alg").and_then(Value::as_str) != Some(algorithm_name)
            {
                return None;
            }
            Some(SelectedKey {
                kid: &key.managed.kid,
                algorithm,
                handle: match &key.managed.handle {
                    KeyHandle::Local(private_key) => SelectedHandle::Local(private_key),
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
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) handle: SelectedHandle<'a>,
    pub(crate) public_jwk: &'a Value,
}

pub(crate) enum SelectedHandle<'a> {
    Active(&'a ActiveSigningKey),
    Local(&'a [u8]),
}

impl KeyManager {
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(algorithm: jsonwebtoken::Algorithm) -> Self {
        Self::for_test_behavior(algorithm, TestSigningBehavior::Working)
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test_behavior(
        algorithm: jsonwebtoken::Algorithm,
        behavior: TestSigningBehavior,
    ) -> Self {
        let material = crate::store::generate_key_material(algorithm)
            .expect("test signing key should generate");
        let kid = format!(
            "test-{}",
            crate::store::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk =
            crate::store::public_jwk_from_private_der(&kid, algorithm, &material.private_pkcs8_der)
                .expect("test public JWK should derive");
        let active_signing_key = match behavior {
            TestSigningBehavior::Working => {
                ActiveSigningKey::LocalPkcs8Der(material.private_pkcs8_der.clone())
            }
            TestSigningBehavior::Failing => ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            TestSigningBehavior::ExternalFailure { stderr } => {
                ActiveSigningKey::ExternalCommand(ExternalSigningKey {
                    command: Arc::new(external_failure_command(&stderr)),
                    key_ref: "kms://test/failure".to_owned(),
                    timeout: Duration::from_secs(2),
                })
            }
        };
        let loaded = LoadedKeyset {
            active_kid: kid.clone(),
            active_alg: algorithm,
            active_signing_key,
            verification_keys: vec![StoredVerificationKey {
                public_jwk,
                managed: ManagedKey {
                    kid,
                    algorithm: crate::store::signing_algorithm_name(algorithm)
                        .unwrap()
                        .to_owned(),
                    purposes: all_signing_purposes(),
                    state: KeyState::Active,
                    handle: KeyHandle::Local(material.private_pkcs8_der),
                },
            }],
        };
        let snapshot = snapshot_from_loaded(&loaded);
        Self {
            inner: Arc::new(KeyManagerInner {
                snapshot: ArcSwap::from_pointee(snapshot),
                loaded: ArcSwap::from_pointee(loaded),
                settings: KeySettings {
                    keys_dir: PathBuf::new(),
                    external_command: Vec::new(),
                    external_timeout: Duration::from_secs(2),
                    rotation_interval: chrono::Duration::days(90),
                    prepublish_window: chrono::Duration::days(1),
                    verification_grace: chrono::Duration::minutes(10),
                },
            }),
        }
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test_with_auxiliary(algorithm: jsonwebtoken::Algorithm) -> Self {
        let manager = Self::for_test(jsonwebtoken::Algorithm::EdDSA);
        let mut loaded = (*manager.inner.loaded.load_full()).clone();
        let material = crate::store::generate_key_material(algorithm).unwrap();
        let kid = format!(
            "test-aux-{}",
            crate::store::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk =
            crate::store::public_jwk_from_private_der(&kid, algorithm, &material.private_pkcs8_der)
                .unwrap();
        loaded.verification_keys.push(StoredVerificationKey {
            public_jwk,
            managed: ManagedKey {
                kid,
                algorithm: crate::store::signing_algorithm_name(algorithm)
                    .unwrap()
                    .to_owned(),
                purposes: [SigningPurpose::IdToken, SigningPurpose::Jarm]
                    .into_iter()
                    .collect(),
                state: KeyState::Active,
                handle: KeyHandle::Local(material.private_pkcs8_der),
            },
        });
        let snapshot = snapshot_from_loaded(&loaded);
        manager.inner.loaded.store(Arc::new(loaded));
        manager.inner.snapshot.store(Arc::new(snapshot));
        manager
    }

    pub async fn validate(settings: &KeySettings) -> anyhow::Result<()> {
        let path = settings.keys_dir.join("keyset.json");
        if crate::store::try_load_keyset(settings, &path)
            .await?
            .is_none()
        {
            anyhow::bail!("keyset.json does not exist");
        }
        Ok(())
    }

    pub async fn load_or_create(settings: KeySettings) -> anyhow::Result<Self> {
        let loaded = crate::store::load_or_create_keyset(&settings).await?;
        Ok(Self::from_loaded(settings, loaded))
    }

    pub(crate) fn from_loaded(settings: KeySettings, loaded: LoadedKeyset) -> Self {
        let snapshot = snapshot_from_loaded(&loaded);
        Self {
            inner: Arc::new(KeyManagerInner {
                snapshot: ArcSwap::from_pointee(snapshot),
                loaded: ArcSwap::from_pointee(loaded),
                settings,
            }),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<KeySnapshot> {
        self.inner.snapshot.load_full()
    }

    pub async fn encode_jwt<T: Serialize>(
        &self,
        purpose: SigningPurpose,
        header: &jsonwebtoken::Header,
        claims: &T,
    ) -> jsonwebtoken::errors::Result<String> {
        let loaded = self.inner.loaded.load_full();
        let selected = loaded
            .selected_key(purpose, header.alg)
            .ok_or(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
        if header.kid.as_deref().is_some_and(|kid| kid != selected.kid) {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
        }
        let mut header = header.clone();
        header.kid = Some(selected.kid.to_owned());
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = sign_selected(&selected, signing_input.as_bytes())
            .await
            .map_err(sign_error_to_jwt)?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_bytes())
        ))
    }

    pub async fn sign_http_message(
        &self,
        signing_input: &[u8],
    ) -> anyhow::Result<HttpMessageSignature> {
        let loaded = self.inner.loaded.load_full();
        let selected = loaded
            .selected_key(SigningPurpose::HttpMessage, loaded.active_alg)
            .ok_or_else(|| anyhow::anyhow!("HTTP message signing key unavailable"))?;
        let algorithm = match selected.algorithm {
            jsonwebtoken::Algorithm::EdDSA => "ed25519",
            jsonwebtoken::Algorithm::RS256 => "rsa-v1_5-sha256",
            jsonwebtoken::Algorithm::ES256 => "ecdsa-p256-sha256",
            _ => anyhow::bail!("unsupported HTTP message signing algorithm"),
        };
        let signature = sign_selected(&selected, signing_input).await?;
        Ok(HttpMessageSignature {
            kid: selected.kid.to_owned(),
            algorithm,
            signature: signature.into_bytes(),
        })
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let loaded = crate::store::load_or_create_keyset(&self.inner.settings).await?;
        let snapshot = snapshot_from_loaded(&loaded);
        self.inner.loaded.store(Arc::new(loaded));
        self.inner.snapshot.store(Arc::new(snapshot));
        Ok(())
    }
}

#[cfg(all(feature = "test-support", windows))]
fn external_failure_command(stderr: &str) -> Vec<String> {
    vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        format!(
            "$null=[Console]::In.ReadToEnd(); [Console]::Error.Write('{}'); exit 7",
            stderr.replace('\'', "''")
        ),
    ]
}

#[cfg(all(feature = "test-support", unix))]
fn external_failure_command(stderr: &str) -> Vec<String> {
    vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "cat >/dev/null; printf '%s' '{}' >&2; exit 7",
            stderr.replace('\'', "'\"'\"'")
        ),
    ]
}

impl Signer for KeyManager {
    async fn sign<'a>(&'a self, request: SignRequest<'a>) -> Result<Signature, SignError> {
        let algorithm = crate::store::signing_algorithm_from_name(request.algorithm)
            .ok_or(SignError::UnsupportedAlgorithm)?;
        let loaded = self.inner.loaded.load_full();
        let selected = loaded
            .selected_key(request.purpose, algorithm)
            .ok_or(SignError::KeyUnavailable)?;
        sign_selected(&selected, request.signing_input).await
    }
}

async fn sign_selected(selected: &SelectedKey<'_>, input: &[u8]) -> Result<Signature, SignError> {
    match &selected.handle {
        SelectedHandle::Active(ActiveSigningKey::LocalPkcs8Der(private_key)) => {
            crate::local::LocalBackend {
                algorithm: selected.algorithm,
                private_key,
            }
            .sign(input)
            .await
        }
        SelectedHandle::Active(ActiveSigningKey::ExternalCommand(external)) => {
            crate::external::ExternalBackend {
                external,
                kid: selected.kid,
                algorithm: selected.algorithm,
                public_jwk: selected.public_jwk,
            }
            .sign(input)
            .await
        }
        SelectedHandle::Local(private_key) => {
            crate::local::LocalBackend {
                algorithm: selected.algorithm,
                private_key,
            }
            .sign(input)
            .await
        }
    }
}

fn sign_error_to_jwt(error: SignError) -> jsonwebtoken::errors::Error {
    crate::external::jwt_provider_error(error.to_string())
}

pub(crate) fn snapshot_from_loaded(loaded: &LoadedKeyset) -> KeySnapshot {
    const ORDERED: [jsonwebtoken::Algorithm; 4] = [
        jsonwebtoken::Algorithm::EdDSA,
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::Algorithm::PS256,
    ];
    let response_signing_algorithms = ORDERED
        .into_iter()
        .filter(|algorithm| {
            loaded
                .selected_key(SigningPurpose::IdToken, *algorithm)
                .is_some()
                || loaded
                    .selected_key(SigningPurpose::Jarm, *algorithm)
                    .is_some()
        })
        .collect();
    KeySnapshot {
        active_kid: loaded.active_kid.clone(),
        active_alg: loaded.active_alg,
        verification_keys: loaded
            .verification_keys
            .iter()
            .map(|key| VerificationKey {
                kid: key.managed.kid.clone(),
                public_jwk: key.public_jwk.clone(),
            })
            .collect(),
        response_signing_algorithms,
    }
}

#[cfg(feature = "test-support")]
fn all_signing_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
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
mod tests {
    use std::collections::BTreeSet;

    use nazo_auth::SigningPurpose;

    use super::{KeyHandle, KeyState, ManagedKey};

    fn managed_key(state: KeyState, purposes: &[SigningPurpose]) -> ManagedKey {
        ManagedKey {
            kid: "purpose-key".to_owned(),
            algorithm: "EdDSA".to_owned(),
            purposes: purposes.iter().copied().collect::<BTreeSet<_>>(),
            state,
            handle: KeyHandle::Local(Vec::new()),
        }
    }

    #[test]
    fn id_token_key_rejects_http_message_signing() {
        let key = managed_key(KeyState::Active, &[SigningPurpose::IdToken]);
        assert!(key.can_sign(SigningPurpose::IdToken));
        assert!(!key.can_sign(SigningPurpose::HttpMessage));
    }

    #[test]
    fn grace_key_verifies_but_does_not_sign() {
        let key = managed_key(KeyState::Grace, &[SigningPurpose::AccessToken]);
        assert!(key.can_verify());
        assert!(!key.can_sign(SigningPurpose::AccessToken));
    }

    #[test]
    fn retired_key_neither_verifies_nor_signs() {
        let key = managed_key(KeyState::Retired, &[SigningPurpose::AccessToken]);
        assert!(!key.can_verify());
        assert!(!key.can_sign(SigningPurpose::AccessToken));
    }
}
