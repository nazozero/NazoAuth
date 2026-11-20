use crate::capabilities::MdocCrlProvider;

struct Publication;

impl MdocCrlProvider for Publication {
    fn signed_crl<'a>(
        &'a self,
        issuer_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Option<bytes::Bytes>>> + Send + 'a>,
    > {
        Box::pin(async move {
            match issuer_id {
                "current" => Ok(Some(bytes::Bytes::from_static(b"public CRL fixture"))),
                "missing" => Ok(None),
                _ => anyhow::bail!("authority changed"),
            }
        })
    }
}

#[test]
fn crl_publication_preserves_failure_statuses_and_forbids_cache_reuse() {
    let publication = Publication;
    for (configured, id, status) in [
        (true, "current", http::StatusCode::OK),
        (true, "missing", http::StatusCode::NOT_FOUND),
        (true, "stale", http::StatusCode::SERVICE_UNAVAILABLE),
        (false, "current", http::StatusCode::NOT_FOUND),
    ] {
        let provider = configured.then_some(&publication as &dyn MdocCrlProvider);
        let response = futures_executor::block_on(super::mdoc_crl(provider, id));
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        if status == http::StatusCode::OK {
            assert_eq!(
                response.headers()[http::header::CONTENT_TYPE],
                "application/pkix-crl"
            );
        }
    }
}
