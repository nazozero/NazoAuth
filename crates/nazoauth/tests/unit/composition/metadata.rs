use nazo_auth::{CibaMetadataProfile, MetadataAuthorizationServerProfile};

use super::metadata_config;
use crate::config::{Configuration, IpCidr};
use nazo_oauth_server::contracts::metadata::MetadataEndpointConfig;
use nazo_oauth_server::policy::{AuthorizationServerProfile, CibaSecurityProfile};

fn settings() -> Configuration {
    Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://127.0.0.1:8000",
        "client-secret-pepper-for-tests-000000000001",
    )
    .expect("default settings")
}

#[test]
fn metadata_config_maps_only_the_focused_settings_boundary() {
    let mut settings = settings();
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.issuer.example".to_owned();
    settings.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];
    settings.endpoint.mtls_certificate_source = crate::config::MtlsCertificateSourceMode::Rfc9440;
    settings.protocol.pairwise_subject_secret = Some("a".repeat(32));
    settings.protocol.protected_resource_identifier = "https://resource.example".to_owned();
    settings.protocol.require_pushed_authorization_requests = true;

    assert_eq!(
        metadata_config(&settings).endpoint_config(),
        MetadataEndpointConfig {
            deployment_profile: nazo_auth::DeploymentProfile::Full,
            backchannel_logout_supported: true,
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
            mtls_enabled: true,
            authorization_server_profile: MetadataAuthorizationServerProfile::Composable,
            ciba_profile: CibaMetadataProfile::FapiCiba,
            pairwise_subject_enabled: true,
            protected_resource_identifier: "https://resource.example".to_owned(),
            additional_scopes_supported: vec![],
            credential_scopes: vec![],
            require_pushed_authorization_requests: true,
        }
    );
}

#[test]
fn metadata_config_uses_composable_discovery_for_every_legacy_profile() {
    let cases = [
        AuthorizationServerProfile::Oauth2Baseline,
        AuthorizationServerProfile::Fapi2Security,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
        AuthorizationServerProfile::Fapi2MessageSigningJarm,
        AuthorizationServerProfile::Fapi2MessageSigningIntrospection,
    ];

    for profile in cases {
        let mut settings = settings();
        settings.protocol.authorization_server_profile = profile;
        settings.protocol.require_pushed_authorization_requests = false;
        let config = metadata_config(&settings);
        assert_eq!(
            config.authorization_server_profile,
            MetadataAuthorizationServerProfile::Composable
        );
        assert!(!config.require_pushed_authorization_requests);
    }
}

#[test]
fn metadata_config_selects_machine_profile_for_hosts_without_user_authorization() {
    let mut settings = settings();
    settings.protocol.deployment_profile = nazo_auth::DeploymentProfile::MachineToMachine;
    assert_eq!(
        metadata_config(&settings).deployment_profile,
        nazo_auth::DeploymentProfile::MachineToMachine
    );
}

#[test]
fn metadata_config_maps_both_ciba_profiles() {
    for (profile, expected) in [
        (
            CibaSecurityProfile::FapiCibaId1,
            CibaMetadataProfile::FapiCiba,
        ),
        (
            CibaSecurityProfile::Fapi2Ciba,
            CibaMetadataProfile::Fapi2Ciba,
        ),
    ] {
        let mut settings = settings();
        settings.protocol.ciba_security_profile = profile;
        assert_eq!(metadata_config(&settings).ciba_security_profile, expected);
    }
}

#[test]
fn metadata_credential_scopes_come_from_the_issuer_configurations() {
    let mut settings = settings();
    settings.protocol.additional_scopes_supported = vec!["orders:read".to_owned()];
    settings.openid4vc.credential_configurations = serde_json::from_str(
        r#"{"pid":{"format":"dc+sd-jwt","scope":"urn:example:pid","vct":"https://issuer.example/pid","credential_signing_alg_values_supported":["ES256"]}}"#,
    ).unwrap();
    let metadata = metadata_config(&settings).endpoint_config();
    assert_eq!(metadata.additional_scopes_supported, ["orders:read"]);
    assert_eq!(metadata.credential_scopes, ["urn:example:pid"]);
}
