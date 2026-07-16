use nazo_digital_credentials::{CredentialFormat, DcqlError, DcqlQuery, decode_compact_jwt};

#[test]
fn credential_formats_use_final_spec_identifiers() {
    assert_eq!(CredentialFormat::SdJwtVc.as_str(), "dc+sd-jwt");
    assert_eq!(CredentialFormat::MsoMdoc.as_str(), "mso_mdoc");
}

#[test]
fn unsigned_jwt_is_rejected() {
    assert!(decode_compact_jwt("e30.e30.").is_err());
}

#[test]
fn dcql_requires_at_least_one_credential_query() {
    let query: DcqlQuery = serde_json::from_str(r#"{"credentials":[]}"#).unwrap();
    assert_eq!(query.validate(), Err(DcqlError::MissingCredentials));
}
