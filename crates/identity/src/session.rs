#[must_use]
pub fn valid_authentication_metadata(
    auth_time: i64,
    amr: &[String],
    oidc_sid: Option<&str>,
    now: i64,
) -> bool {
    auth_time > 0
        && auth_time <= now.saturating_add(30)
        && !amr.is_empty()
        && oidc_sid.is_some_and(|sid| !sid.trim().is_empty())
}

pub fn add_amr(amr: &mut Vec<String>, value: &str) {
    if !amr.iter().any(|method| method == value) {
        amr.push(value.to_owned());
    }
}
use crate::UserId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    user_id: UserId,
    auth_time: i64,
    amr: Vec<String>,
    pending_mfa: bool,
    oidc_sid: Option<String>,
}

impl SessionRecord {
    #[must_use]
    pub fn new(
        user_id: UserId,
        auth_time: i64,
        amr: Vec<String>,
        pending_mfa: bool,
        oidc_sid: Option<String>,
    ) -> Self {
        Self {
            user_id,
            auth_time,
            amr,
            pending_mfa,
            oidc_sid,
        }
    }

    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.auth_time
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    #[must_use]
    pub const fn pending_mfa(&self) -> bool {
        self.pending_mfa
    }

    #[must_use]
    pub fn oidc_sid(&self) -> Option<&str> {
        self.oidc_sid.as_deref()
    }

    pub fn set_auth_time(&mut self, auth_time: i64) {
        self.auth_time = auth_time;
    }

    pub fn set_pending_mfa(&mut self, pending_mfa: bool) {
        self.pending_mfa = pending_mfa;
    }

    pub fn add_amr(&mut self, value: &str) {
        add_amr(&mut self.amr, value);
    }
}
