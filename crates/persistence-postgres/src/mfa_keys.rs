//! Versioned at-rest TOTP encryption keys owned by the PostgreSQL adapter.

#[derive(Clone)]
pub struct MfaTotpKeyRing {
    current: MfaTotpKey,
    previous: Option<MfaTotpKey>,
}

#[derive(Clone)]
pub struct MfaTotpKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaTotpKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl std::fmt::Display for MfaTotpKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "MFA TOTP encryption key id must not be empty",
            Self::IdTooLong => "MFA TOTP encryption key id must be at most 128 bytes",
            Self::DuplicateId => "MFA TOTP current and previous key ids must differ",
        })
    }
}

impl std::error::Error for MfaTotpKeyError {}

impl MfaTotpKey {
    pub fn new(id: impl Into<String>, key: [u8; 32]) -> Result<Self, MfaTotpKeyError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(MfaTotpKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(MfaTotpKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl MfaTotpKeyRing {
    pub fn new(current: MfaTotpKey, previous: Option<MfaTotpKey>) -> Result<Self, MfaTotpKeyError> {
        if previous
            .as_ref()
            .is_some_and(|candidate| candidate.id() == current.id())
        {
            return Err(MfaTotpKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current(&self) -> &MfaTotpKey {
        &self.current
    }

    #[must_use]
    pub fn previous(&self) -> Option<&MfaTotpKey> {
        self.previous.as_ref()
    }
}
