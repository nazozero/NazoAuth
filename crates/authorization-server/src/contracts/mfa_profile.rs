use std::{future::Future, pin::Pin};

use super::local_registration::AuthenticationRateLimitError;

pub type MfaProfileFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, MfaProfileError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaRequestContext {
    pub session_id: String,
    pub source_ip: String,
    pub user_agent_hash: Option<String>,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaCodeCommand {
    pub context: MfaRequestContext,
    pub code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaChallengeCommand {
    pub context: MfaRequestContext,
    pub code: String,
    pub remember_device: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaSessionRotation {
    pub session_id: String,
    pub csrf_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaTotpEnrollment {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaTotpConfirmation {
    pub rotation: MfaSessionRotation,
    pub backup_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaChallengeSuccess {
    pub rotation: MfaSessionRotation,
    pub method: String,
    pub remembered_device_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaStepUpSuccess {
    pub rotation: MfaSessionRotation,
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaBackupCodesRegenerated {
    pub rotation: MfaSessionRotation,
    pub backup_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaProfileErrorKind {
    SessionMissing,
    ChallengeMissing,
    SessionUnavailable,
    RateLimitUnavailable,
    RateLimited,
    AlreadyEnabled,
    EnrollmentMissing,
    InvalidCode,
    MfaDisabled,
    CredentialUnavailable,
    HashUnavailable,
    SessionWriteFailed,
    RememberDeviceFailed,
    BackupCodesFailed,
    DisableFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaProfileError {
    pub kind: MfaProfileErrorKind,
    pub retry_after_seconds: Option<u64>,
    pub rotation: Option<MfaSessionRotation>,
    pub clear_session_cookies: bool,
}

impl MfaProfileError {
    #[must_use]
    pub const fn new(kind: MfaProfileErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
            rotation: None,
            clear_session_cookies: false,
        }
    }

    #[must_use]
    pub const fn rate_limit(error: AuthenticationRateLimitError) -> Self {
        match error {
            AuthenticationRateLimitError::Unavailable => {
                Self::new(MfaProfileErrorKind::RateLimitUnavailable)
            }
            AuthenticationRateLimitError::Limited {
                retry_after_seconds,
            } => Self {
                kind: MfaProfileErrorKind::RateLimited,
                retry_after_seconds: Some(retry_after_seconds),
                rotation: None,
                clear_session_cookies: false,
            },
        }
    }
}

pub trait MfaProfileOperations: Send + Sync {
    fn begin_totp(&self, context: MfaRequestContext) -> MfaProfileFuture<'_, MfaTotpEnrollment>;
    fn confirm_totp(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaTotpConfirmation>;
    fn verify_challenge(
        &self,
        command: MfaChallengeCommand,
    ) -> MfaProfileFuture<'_, MfaChallengeSuccess>;
    fn step_up(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaStepUpSuccess>;
    fn regenerate_backup_codes(
        &self,
        command: MfaCodeCommand,
    ) -> MfaProfileFuture<'_, MfaBackupCodesRegenerated>;
    fn disable(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, bool>;
}
