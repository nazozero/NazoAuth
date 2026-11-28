#[actix_web::test]
async fn public_builder_revalidates_mutable_configuration() {
    let state = super::infrastructure(false).await;
    let original = state.settings.application_configuration();
    original.validate().unwrap();
    for invalid in ["credential", "lifetime", "issuer"] {
        let mut configuration = original.clone();
        let expected = match invalid {
            "credential" => {
                configuration.modules.enable_openid4vci_issuer = true;
                "data encryption root"
            }
            "lifetime" => {
                configuration.protocol.access_token_ttl_seconds = 3_601;
                "ACCESS_TOKEN_TTL_SECONDS"
            }
            "issuer" => {
                configuration.endpoint.issuer = "not-a-url".into();
                "issuer"
            }
            _ => unreachable!(),
        };
        let capabilities = crate::test_support::facade::capabilities(&state, Default::default())
            .expect("configured host capabilities");
        let result = nazoauth::NazoAuthBuilder::new(configuration, capabilities, "invalid-config")
            .build()
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid product configuration was accepted"),
        };
        assert!(error.to_string().contains(expected), "{error}");
    }
}
