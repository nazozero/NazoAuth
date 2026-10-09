//! The only accepted PKCE method is S256. Retain the challenge, not a second
//! independently mutable method. Legacy stored pairs are validated on decode.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StoredPkce")]
pub struct S256Pkce {
    #[serde(skip_serializing_if = "Option::is_none")]
    s256_code_challenge: Option<String>,
}

#[derive(Deserialize)]
struct StoredPkce {
    #[serde(default)]
    s256_code_challenge: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}
impl TryFrom<StoredPkce> for S256Pkce {
    type Error = &'static str;
    fn try_from(value: StoredPkce) -> Result<Self, Self::Error> {
        match (
            value.s256_code_challenge,
            value.code_challenge,
            value.code_challenge_method.as_deref(),
        ) {
            (challenge, None, None) => Ok(Self::from(challenge)),
            (None, Some(challenge), Some("S256")) => Ok(Self::from(Some(challenge))),
            _ => Err("stored PKCE must have one S256 challenge authority"),
        }
    }
}
impl From<Option<String>> for S256Pkce {
    fn from(s256_code_challenge: Option<String>) -> Self {
        Self {
            s256_code_challenge,
        }
    }
}
impl S256Pkce {
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.s256_code_challenge.as_deref()
    }
}
