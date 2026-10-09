/// Absolute acceptance interval for a cryptographically verified client
/// attestation PoP. The replay owner checks this interval with its own clock in
/// the same atomic operation that consumes the JTI. A node-local TTL cannot
/// establish replay acceptance across nodes with different clocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAttestationProofWindow {
    not_before: i64,
    expires_at: i64,
}

impl ClientAttestationProofWindow {
    const FUTURE_TOLERANCE_SECONDS: i64 = 60;
    const MAX_AGE_SECONDS: i64 = 300;

    /// `iat` has already been verified as an integer signed by the client
    /// instance key. The last accepted age is inclusive; expiry is exclusive.
    #[must_use]
    pub fn from_verified_issued_at(iat: i64) -> Option<Self> {
        Some(Self {
            not_before: iat.checked_sub(Self::FUTURE_TOLERANCE_SECONDS)?,
            expires_at: iat.checked_add(Self::MAX_AGE_SECONDS)?.checked_add(1)?,
        })
    }

    #[must_use]
    pub fn accepts(self, now: i64) -> bool {
        now >= self.not_before && now < self.expires_at
    }

    #[must_use]
    pub fn not_before(self) -> i64 {
        self.not_before
    }

    #[must_use]
    pub fn expires_at(self) -> i64 {
        self.expires_at
    }
}

#[cfg(test)]
#[path = "../tests/unit/client_attestation.rs"]
mod tests;
