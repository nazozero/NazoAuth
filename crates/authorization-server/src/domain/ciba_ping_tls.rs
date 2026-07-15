use anyhow::Context as _;

pub(super) fn apply_ciba_ping_tls_policy(
    mut builder: reqwest::ClientBuilder,
) -> anyhow::Result<reqwest::ClientBuilder> {
    builder = builder
        .use_rustls_tls()
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .tls_version_max(reqwest::tls::Version::TLS_1_3);
    if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        let bundle = std::fs::read(&path).with_context(|| {
            format!(
                "failed to read CIBA ping TLS trust bundle {}",
                std::path::Path::new(&path).display()
            )
        })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&bundle)
            .context("failed to parse CIBA ping TLS trust bundle")?;
        if certificates.is_empty() {
            anyhow::bail!("CIBA ping TLS trust bundle contains no certificates");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(builder)
}
