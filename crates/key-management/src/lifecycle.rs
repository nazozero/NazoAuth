use nazo_auth::SigningPurpose;

/// A database-backed generation may sign only until this stale-snapshot bound.
pub(crate) const MAX_DATABASE_SNAPSHOT_STALENESS_SECONDS: i64 = 2 * 60 * 60;
pub(crate) const MAX_DATABASE_SNAPSHOT_STALENESS: chrono::Duration =
    chrono::Duration::seconds(MAX_DATABASE_SNAPSHOT_STALENESS_SECONDS);
/// Managed local revocation facts are refreshed on the same cadence as the
/// previous file-backed source. This observation deadline is intentionally
/// shorter than the two-hour signing-generation stale bound.
pub(crate) const OPENID4VC_REVOCATION_MAX_STALE_SECONDS: i64 = 60;

pub(crate) fn all_signing_purposes() -> std::collections::BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::Introspection,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
        SigningPurpose::SecurityEvent,
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
