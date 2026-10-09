//! One claim-request authority per response target.
//!
//! Older encoded authorizations carried both bare names and full requests. Only
//! decoding needs both: a full request wins for the same name, so a legacy bare
//! name cannot remove its essential/value constraints. New encodings carry only
//! the full requests. These values do not prescribe a storage backend.
use crate::OidcClaimRequest;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(from = "LegacyUserinfoSelection")]
pub struct UserinfoClaimRequests {
    userinfo_claim_requests: Vec<OidcClaimRequest>,
}
#[derive(Default, Deserialize)]
struct LegacyUserinfoSelection {
    #[serde(default)]
    userinfo_claims: Vec<String>,
    #[serde(default)]
    userinfo_claim_requests: Vec<OidcClaimRequest>,
}
impl From<LegacyUserinfoSelection> for UserinfoClaimRequests {
    fn from(legacy: LegacyUserinfoSelection) -> Self {
        Self {
            userinfo_claim_requests: merge_legacy_names(
                legacy.userinfo_claims,
                legacy.userinfo_claim_requests,
            ),
        }
    }
}
impl From<Vec<OidcClaimRequest>> for UserinfoClaimRequests {
    fn from(userinfo_claim_requests: Vec<OidcClaimRequest>) -> Self {
        Self {
            userinfo_claim_requests,
        }
    }
}
impl Deref for UserinfoClaimRequests {
    type Target = Vec<OidcClaimRequest>;
    fn deref(&self) -> &Self::Target {
        &self.userinfo_claim_requests
    }
}
impl DerefMut for UserinfoClaimRequests {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.userinfo_claim_requests
    }
}
impl UserinfoClaimRequests {
    /// Presentation-only projection; never another stored or writable authority.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.iter().map(|request| request.name.as_str()).collect()
    }
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(from = "LegacyIdTokenSelection")]
pub struct IdTokenClaimRequests {
    id_token_claim_requests: Vec<OidcClaimRequest>,
}
#[derive(Default, Deserialize)]
struct LegacyIdTokenSelection {
    #[serde(default)]
    id_token_claims: Vec<String>,
    #[serde(default)]
    id_token_claim_requests: Vec<OidcClaimRequest>,
}
impl From<LegacyIdTokenSelection> for IdTokenClaimRequests {
    fn from(legacy: LegacyIdTokenSelection) -> Self {
        Self {
            id_token_claim_requests: merge_legacy_names(
                legacy.id_token_claims,
                legacy.id_token_claim_requests,
            ),
        }
    }
}
impl From<Vec<OidcClaimRequest>> for IdTokenClaimRequests {
    fn from(id_token_claim_requests: Vec<OidcClaimRequest>) -> Self {
        Self {
            id_token_claim_requests,
        }
    }
}
impl Deref for IdTokenClaimRequests {
    type Target = Vec<OidcClaimRequest>;
    fn deref(&self) -> &Self::Target {
        &self.id_token_claim_requests
    }
}
impl DerefMut for IdTokenClaimRequests {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.id_token_claim_requests
    }
}
impl IdTokenClaimRequests {
    /// Presentation-only projection; never another stored or writable authority.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.iter().map(|request| request.name.as_str()).collect()
    }
}
fn merge_legacy_names(
    names: Vec<String>,
    mut requests: Vec<OidcClaimRequest>,
) -> Vec<OidcClaimRequest> {
    for name in names {
        if !requests.iter().any(|request| request.name == name) {
            requests.push(OidcClaimRequest::named(name));
        }
    }
    requests
}
