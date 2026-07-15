pub(super) fn apply_ciba_ping_tls_policy(
    builder: reqwest::ClientBuilder,
) -> reqwest::ClientBuilder {
    builder
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .tls_version_max(reqwest::tls::Version::TLS_1_3)
}
