//! Capture authenticated TLS connection facts; request trust policy is neutral.
use actix_web::dev::Extensions;
use nazoauth::{ConnectionFacts, capabilities::CertificateChainVerifier};
use rustls::pki_types::CertificateDer;
use std::{any::Any, sync::Arc};

pub(crate) struct RustlsCertificateVerifier(
    pub(crate) Arc<dyn rustls::server::danger::ClientCertVerifier>,
);

impl CertificateChainVerifier for RustlsCertificateVerifier {
    fn verify(&self, chain: &[CertificateDer<'static>]) -> bool {
        let Some((leaf, intermediates)) = chain.split_first() else {
            return false;
        };
        self.0
            .verify_client_cert(leaf, intermediates, rustls::pki_types::UnixTime::now())
            .is_ok()
    }
}

pub(crate) fn capture_direct_tls_client_certificate(
    io: &dyn Any,
    extensions: &mut Extensions,
    deployment_verifier: Option<&dyn rustls::server::danger::ClientCertVerifier>,
) {
    let Some(stream) = io
        .downcast_ref::<actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>>()
    else {
        return;
    };
    let connection = stream.get_ref().1;
    let server_name = connection
        .server_name()
        .and_then(|name| nazo_identity::canonical_tenant_host(name).ok())
        .map(Arc::from);
    // Own the peer chain once per TLS connection using the upstream API.
    // Every request on this connection shares the resulting certificate facts.
    let client_certificate = connection
        .peer_certificates()
        .map(|chain| Arc::new(chain.to_vec()))
        .and_then(nazo_oauth_server::security::mtls::certificate_chain_identity)
        .map(|mut identity| {
            let (leaf, intermediates) = identity
                .certificate_chain_der
                .split_first()
                .expect("parsed certificate has a leaf");
            identity.deployment_trusted_chain = deployment_verifier.is_some_and(|verifier| {
                verifier
                    .verify_client_cert(leaf, intermediates, rustls::pki_types::UnixTime::now())
                    .is_ok()
            });
            Arc::new(identity)
        });
    extensions.insert(ConnectionFacts {
        peer_addr: None,
        server_name,
        client_certificate,
    });
}
