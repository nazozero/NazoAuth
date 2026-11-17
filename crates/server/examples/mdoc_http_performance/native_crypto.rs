//! Construct the public crypto adapter with the native deployment policy.
pub(crate) fn create(
    keys: nazo_key_management::KeyManager,
) -> nazo_oauth_server::domain::openid4vc::Openid4vcCredentialCrypto {
    nazo_oauth_server::domain::openid4vc::Openid4vcCredentialCrypto::new_with_policies(
        keys,
        nazo_digital_credentials::VcIssuerTrustPolicy::san_bound(),
        nazo_oauth_server::policy::Openid4vcRevocationPolicy::Required,
    )
    .expect("shared native credential material must be valid")
}
