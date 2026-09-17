use crate::http::mtls::{self, ServerMtlsThumbprintExtractor};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web::Data};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use diesel::{
    sql_query,
    sql_types::{Text, Uuid as SqlUuid},
};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use nazo_http_actix::IpCidr;
use nazo_http_actix::mtls::MtlsThumbprintExtractor;
use nazo_identity::DEFAULT_ORGANIZATION_ID;
use nazo_identity::DEFAULT_REALM_ID;
use nazo_identity::DEFAULT_TENANT_ID;
use nazo_oauth_server::token::client_auth::{
    ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
    authenticate_client_with_dependencies,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

struct Material {
    ca: CertifiedIssuer<'static, KeyPair>,
    leaf: rcgen::Certificate,
    key: KeyPair,
}

fn material() -> Material {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "T00 tenant CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "T00 client");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &ca).unwrap();
    Material { ca, leaf, key }
}

#[actix_web::test]
async fn framework_boundary_transport_direct_tls_captures_real_peer_certificate() {
    use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
    let material = material();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(material.ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .unwrap();
    let server_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = params.signed_by(&server_key, &material.ca).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    let server = HttpServer::new(|| {
        App::new()
            .app_data(Data::new(mtls::MtlsCertificateSource::new(
                mtls::MtlsCertificateSourceMode::DirectTls,
            )))
            .route(
                "/identity",
                actix_web::web::get().to(|request: HttpRequest| async move {
                    let resolver = ServerMtlsThumbprintExtractor::new(Vec::new());
                    HttpResponse::Ok().body(
                        resolver
                            .resolve(&request)
                            .unwrap_or_else(|| "absent".to_owned()),
                    )
                }),
            )
    })
    .workers(1)
    .on_connect(move |io, extensions| {
        mtls::capture_direct_tls_client_certificate(io, extensions, Some(verifier.as_ref()))
    })
    .bind_rustls_0_23(("127.0.0.1", 0), tls)
    .unwrap();
    let url = format!("https://localhost:{}/identity", server.addrs()[0].port());
    let server = server.run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    let root = reqwest::Certificate::from_pem(material.ca.pem().as_bytes()).unwrap();
    let anonymous = reqwest::Client::builder()
        .no_proxy()
        .tls_backend_rustls()
        .tls_certs_only([root.clone()])
        .build()
        .unwrap();
    let response = anonymous
        .get(&url)
        .header(
            "client-cert",
            format!(":{}:", STANDARD.encode(material.leaf.der())),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"absent");
    let identity = reqwest::Identity::from_pem(
        format!(
            "{}{}{}",
            material.leaf.pem(),
            material.ca.pem(),
            material.key.serialize_pem()
        )
        .as_bytes(),
    )
    .unwrap();
    let authenticated = reqwest::Client::builder()
        .no_proxy()
        .tls_backend_rustls()
        .tls_certs_only([root])
        .identity(identity)
        .build()
        .unwrap();
    let response = authenticated
        .get(&url)
        .header("client-cert", ":AA==:")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        URL_SAFE_NO_PAD
            .encode(Sha256::digest(material.leaf.der()))
            .as_bytes()
    );
    drop(authenticated);
    drop(anonymous);
    handle.stop(true).await;
}

#[actix_web::test]
async fn framework_boundary_transport_rfc9440_same_resolver_observes_tenant_ca_revocation() {
    let state = super::live_transport_state().await;
    let material = material();
    let trusted = vec![IpCidr::parse("192.0.2.0/24").unwrap()];
    let resolver = ServerMtlsThumbprintExtractor::new(trusted.clone());
    let certificate_header = format!(":{}:", STANDARD.encode(material.leaf.der()));
    let make_request = |peer: &str| {
        actix_web::test::TestRequest::post()
            .uri("/token")
            .app_data(Data::new(mtls::MtlsCertificateSource::new(
                mtls::MtlsCertificateSourceMode::Rfc9440,
            )))
            .peer_addr(peer.parse().unwrap())
            .insert_header(("client-cert", certificate_header.as_str()))
            .to_http_request()
    };
    let request = make_request("192.0.2.1:443");
    let untrusted = make_request("198.51.100.1:443");
    let expected_thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(material.leaf.der()));
    assert_eq!(
        resolver.resolve(&request).as_deref(),
        Some(expected_thumbprint.as_str())
    );
    assert!(resolver.resolve(&untrusted).is_none());
    assert!(
        mtls::request_mtls_client_certificate(&request, &[]).is_none(),
        "cached certificate cannot bypass a changed peer policy"
    );
    let certificate = mtls::request_mtls_client_certificate(&request, &trusted).unwrap();
    assert!(!certificate.deployment_trusted_chain);
    assert_eq!(
        certificate.certificate_chain_der,
        vec![material.leaf.der().to_vec()]
    );
    let facts = ClientAuthRequestFacts::new("/token", Some(certificate.clone()));
    let name = format!("t00-ca-{}", uuid::Uuid::now_v7());
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    sql_query(r#"INSERT INTO oauth_clients (
        tenant_id, realm_id, organization_id, client_id, client_name, client_type,
        redirect_uris, scopes, allowed_audiences, grant_types, token_endpoint_auth_method,
        tls_client_auth_subject_dn, require_dpop_bound_tokens, require_mtls_bound_tokens,
        tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,
        allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,
        require_par_request_object, is_active, security_policy, post_logout_redirect_uris,
        backchannel_logout_session_required)
        VALUES ($1,$2,$3,$4,'T00 CA','confidential','[]','["openid"]','["resource://default"]',
        '["client_credentials"]','tls_client_auth',$5,false,true,'[]','[]','[]','[]',
        false,false,false,true,
        '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}',
        '[]',true)"#)
        .bind::<SqlUuid,_>(DEFAULT_TENANT_ID).bind::<SqlUuid,_>(DEFAULT_REALM_ID)
        .bind::<SqlUuid,_>(DEFAULT_ORGANIZATION_ID).bind::<Text,_>(&name)
        .bind::<Text,_>(certificate.subject_dn.as_deref().unwrap())
        .execute(&mut connection).await.unwrap();
    drop(connection);
    let mut client = nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .by_client_id(DEFAULT_TENANT_ID, &name)
        .await
        .unwrap()
        .unwrap();
    let valkey = state.valkey_connection();
    let service = nazo_oauth_server::services::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&valkey)),
        state.keyset.clone(),
    );
    let config = ClientAuthConfig::new(
        &state.settings.endpoint.issuer,
        &state.settings.protocol.client_secret_pepper,
        crate::test_support::test_remote_client_documents(),
        crate::http::authorization::test_support::test_security_audit(),
    );
    let credentials = nazo_auth::PresentedClientCredentials {
        client_id: Some(name),
        client_secret: None,
        client_assertion: None,
        method: "tls_client_auth".to_owned(),
    };
    let context = nazo_auth::ClientAuthenticationContext::ConfidentialOnly;
    assert!(matches!(
        authenticate_client_with_dependencies(
            &service,
            config,
            &facts,
            &mut client,
            &credentials,
            context,
            None
        )
        .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
    let tenant = nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap();
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    connection.batch_execute("BEGIN").await.unwrap();
    let anchor = nazo_postgres::insert_operator_managed_trust_anchor_on_connection(
        &mut connection,
        nazo_postgres::OperatorManagedTrustAnchor {
            tenant_id: tenant,
            client_id: client.id,
            certificate_pem: &material.ca.pem(),
            certificate_sha256: &Sha256::digest(material.ca.der())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            subject_dn: "CN=T00 tenant CA",
            not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
            not_after: chrono::Utc::now() + chrono::Duration::hours(1),
        },
    )
    .await
    .unwrap();
    connection.batch_execute("COMMIT").await.unwrap();
    drop(connection);
    assert!(
        authenticate_client_with_dependencies(
            &service,
            config,
            &facts,
            &mut client,
            &credentials,
            context,
            None
        )
        .await
        .is_ok()
    );
    let absent_facts = crate::http::token::client_auth_request_facts(&untrusted, &trusted);
    assert!(matches!(
        authenticate_client_with_dependencies(
            &service,
            config,
            &absent_facts,
            &mut client,
            &credentials,
            context,
            None
        )
        .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    connection.batch_execute("BEGIN").await.unwrap();
    assert!(
        nazo_postgres::revoke_operator_managed_trust_anchor_on_connection(
            &mut connection,
            tenant,
            anchor
        )
        .await
        .unwrap()
    );
    connection.batch_execute("COMMIT").await.unwrap();
    drop(connection);
    assert_eq!(
        resolver.resolve(&request).as_deref(),
        Some(expected_thumbprint.as_str())
    );
    assert!(
        service
            .mtls_trust_anchor_bundle(client.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        matches!(
            authenticate_client_with_dependencies(
                &service,
                config,
                &facts,
                &mut client,
                &credentials,
                context,
                None
            )
            .await,
            Err(TokenManagementClientAuthError::InvalidClient)
        ),
        "same captured certificate and same service must observe revocation"
    );
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_events WHERE request_id = $1")
        .bind::<SqlUuid, _>(anchor)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE id = $1")
        .bind::<SqlUuid, _>(anchor)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .unwrap();
}
