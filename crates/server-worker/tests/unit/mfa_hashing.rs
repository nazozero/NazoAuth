use super::*;
use futures_executor::block_on;

#[test]
fn mfa_hashing_keeps_native_work_parameters_and_matches_only_the_proved_code() {
    block_on(async {
        let first = nazo_oauth_server::crypto::random_urlsafe_token();
        let second = nazo_oauth_server::crypto::random_urlsafe_token();
        let hashes = Passwords
            .hash_secrets(vec![first.clone(), second.clone()])
            .await
            .unwrap();
        assert_eq!(hashes.len(), 2);
        for hash in &hashes {
            nazo_crypto::password::validate_argon2id_phc(hash.as_str(), 19_456, 2, 1).unwrap();
            assert!(!hash.as_str().contains(&first));
            assert!(!hash.as_str().contains(&second));
        }
        assert_eq!(
            Passwords
                .find_matching_secret(second, hashes.clone())
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            Passwords
                .find_matching_secret(nazo_oauth_server::crypto::random_urlsafe_token(), hashes)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            Passwords
                .find_matching_secret(first, vec![EncodedSecretHash::new("malformed").unwrap()])
                .await
                .unwrap(),
            None
        );
    });
}
