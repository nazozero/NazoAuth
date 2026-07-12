use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Checks a `client-secret-v1` verifier without exposing adapter-owned digests.
#[must_use]
pub fn verify_client_secret_hash(candidate: &str, stored_hash: &str, pepper: &str) -> bool {
    let mut parts = stored_hash.split(':');
    let (Some(version), Some(salt), Some(stored_mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if version != "client-secret-v1" {
        return false;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(candidate.as_bytes());
    let actual = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    bool::from(actual.as_bytes().ct_eq(stored_mac.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_secret_verifier_accepts_only_the_matching_candidate() {
        let stored = "client-secret-v1:c2FsdA:6lJn3EOo_fxJByZR75cMn9RtlGGznqcVi4V4OkrfNCw";
        assert!(verify_client_secret_hash("correct", stored, "pepper"));
        assert!(!verify_client_secret_hash("wrong", stored, "pepper"));
        assert!(!verify_client_secret_hash(
            "candidate",
            "not-a-hash",
            "pepper"
        ));
    }
}
