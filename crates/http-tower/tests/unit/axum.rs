use super::*;
use nazoauth::integration::ClientCertificateFacts;

#[test]
fn existing_connection_facts_and_shared_storage_are_preserved() {
    let certificate = Arc::new(ClientCertificateFacts {
        thumbprint: Some("verified-certificate".into()),
        deployment_trusted_chain: true,
        ..ClientCertificateFacts::default()
    });
    let server_name: Arc<str> = Arc::from("issuer.example");
    for peer_addr in [None, Some("192.0.2.10:8000".parse().unwrap())] {
        let expected = ConnectionFacts {
            peer_addr,
            authenticated_client_ip: Some("192.0.2.20".parse().unwrap()),
            server_name: Some(Arc::clone(&server_name)),
            client_certificate: Some(Arc::clone(&certificate)),
        };
        let mut request = Request::new(());
        request.extensions_mut().insert(expected.clone());
        request
            .extensions_mut()
            .insert(ConnectInfo("127.0.0.1:4000".parse::<SocketAddr>().unwrap()));

        connection_facts(&mut request);

        let actual = request.extensions().get::<ConnectionFacts>().unwrap();
        assert_eq!(actual, &expected);
        assert!(Arc::ptr_eq(
            actual.client_certificate.as_ref().unwrap(),
            &certificate,
        ));
        assert!(Arc::ptr_eq(
            actual.server_name.as_ref().unwrap(),
            &server_name,
        ));
    }
}

#[test]
fn axum_connection_info_supplies_only_the_socket_peer() {
    let peer_addr = "192.0.2.30:1234".parse::<SocketAddr>().unwrap();
    let mut request = Request::builder()
        .header("host", "untrusted.example")
        .header("forwarded", "for=192.0.2.99;proto=https")
        .header("x-forwarded-for", "192.0.2.99")
        .header("client-cert", ":Zm9yZ2Vk:")
        .body(())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer_addr));

    connection_facts(&mut request);

    assert_eq!(
        request.extensions().get::<ConnectionFacts>(),
        Some(&ConnectionFacts {
            peer_addr: Some(peer_addr),
            ..ConnectionFacts::default()
        }),
    );
    assert_eq!(
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .unwrap()
            .0,
        peer_addr,
    );
}

#[test]
fn headers_and_untyped_addresses_do_not_supply_connection_facts() {
    let mut request = Request::builder()
        .header("forwarded", "for=192.0.2.99;proto=https")
        .header("x-forwarded-for", "192.0.2.99")
        .header("client-cert", ":Zm9yZ2Vk:")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert("192.0.2.99:1234".parse::<SocketAddr>().unwrap());

    connection_facts(&mut request);

    assert!(request.extensions().get::<ConnectionFacts>().is_none());
}
