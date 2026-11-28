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

        connection_facts(
            &mut request,
            Some(&ConnectionFacts {
                peer_addr: Some("127.0.0.1:4000".parse().unwrap()),
                ..ConnectionFacts::default()
            }),
        );

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
fn connection_target_supplies_trusted_facts_without_reading_headers() {
    let expected = ConnectionFacts {
        peer_addr: Some("192.0.2.30:1234".parse().unwrap()),
        server_name: Some(Arc::from("issuer.example")),
        ..ConnectionFacts::default()
    };
    let mut request = Request::builder()
        .header("host", "untrusted.example")
        .header("forwarded", "for=192.0.2.99;proto=https")
        .header("x-forwarded-for", "192.0.2.99")
        .header("client-cert", ":Zm9yZ2Vk:")
        .body(())
        .unwrap();

    connection_facts(&mut request, Some(&expected));

    let actual = request.extensions().get::<ConnectionFacts>().unwrap();
    assert_eq!(actual, &expected);
    assert!(Arc::ptr_eq(
        actual.server_name.as_ref().unwrap(),
        expected.server_name.as_ref().unwrap(),
    ));
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
        .insert("192.0.2.99:1234".parse::<std::net::SocketAddr>().unwrap());

    connection_facts(&mut request, None);

    assert!(request.extensions().get::<ConnectionFacts>().is_none());
}
