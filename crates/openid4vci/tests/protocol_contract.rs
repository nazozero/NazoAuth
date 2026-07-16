use std::collections::BTreeMap;

use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{
    BatchCredentialIssuance, CredentialConfiguration, CredentialIssuerMetadata, CredentialRequest,
};

#[test]
fn credential_request_requires_exactly_one_identifier_form() {
    let request: CredentialRequest =
        serde_json::from_str(r#"{"credential_configuration_id":"pid","proofs":{"jwt":["proof"]}}"#)
            .unwrap();
    assert!(request.validate_identifier().is_ok());

    let both: CredentialRequest = serde_json::from_str(
        r#"{"credential_configuration_id":"pid","credential_identifier":"pid-1"}"#,
    )
    .unwrap();
    assert!(both.validate_identifier().is_err());
}

#[test]
fn metadata_rejects_single_item_batch_claim() {
    let metadata = CredentialIssuerMetadata {
        credential_issuer: "https://issuer.example".to_owned(),
        authorization_servers: vec!["https://issuer.example".to_owned()],
        credential_endpoint: "https://issuer.example/credential".to_owned(),
        nonce_endpoint: Some("https://issuer.example/nonce".to_owned()),
        deferred_credential_endpoint: None,
        notification_endpoint: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        batch_credential_issuance: Some(BatchCredentialIssuance { batch_size: 1 }),
        display: Vec::new(),
        credential_configurations_supported: BTreeMap::from([(
            "pid".to_owned(),
            CredentialConfiguration {
                format: CredentialFormat::SdJwtVc,
                scope: Some("pid".to_owned()),
                cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
                credential_signing_alg_values_supported: vec!["ES256".to_owned()],
                proof_types_supported: BTreeMap::new(),
                vct: Some("urn:example:pid".to_owned()),
                doctype: None,
                credential_metadata: None,
            },
        )]),
        signed_metadata: None,
    };
    assert!(metadata.validate().is_err());
}

#[test]
fn metadata_rejects_algorithms_the_issuer_cannot_execute() {
    let configuration: CredentialConfiguration = serde_json::from_value(serde_json::json!({
        "format":"dc+sd-jwt",
        "credential_signing_alg_values_supported":["RS256"],
        "vct":"urn:example:pid"
    }))
    .unwrap();
    assert!(configuration.validate().is_err());

    let proof: CredentialConfiguration = serde_json::from_value(serde_json::json!({
        "format":"dc+sd-jwt",
        "cryptographic_binding_methods_supported":["jwk"],
        "credential_signing_alg_values_supported":["ES256"],
        "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["RS256"]}},
        "vct":"urn:example:pid"
    }))
    .unwrap();
    assert!(proof.validate().is_err());
}
