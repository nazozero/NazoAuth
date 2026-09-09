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

#[test]
fn dcql_multiple_defaults_to_false_and_accepts_only_booleans() {
    let mut value = serde_json::json!({"credentials":[{"id":"pid","format":"dc+sd-jwt"}]});
    let default: DcqlQuery = serde_json::from_value(value.clone()).unwrap();
    assert!(!default.credentials[0].multiple);
    for multiple in [false, true] {
        value["credentials"][0]["multiple"] = multiple.into();
        let query: DcqlQuery = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(query.credentials[0].multiple, multiple);
        assert_eq!(query.validate(), Ok(()));
        assert_eq!(
            serde_json::to_value(&query).unwrap()["credentials"][0]["multiple"],
            if multiple {
                serde_json::json!(true)
            } else {
                serde_json::Value::Null
            }
        );
    }
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::json!("true"),
    ] {
        value["credentials"][0]["multiple"] = invalid;
        assert!(serde_json::from_value::<DcqlQuery>(value.clone()).is_err());
    }
}

#[test]
fn dcql_claim_paths_and_sets_are_closed_over_declared_claims() {
    for (json, expected) in [
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"path":[]}]}]}"#,
            DcqlError::EmptyClaimPath,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"id":"","path":["name"]}]}]}"#,
            DcqlError::InvalidClaimId,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"id":"name","path":["name"]},{"id":"name","path":["family_name"]}]}]}"#,
            DcqlError::InvalidClaimId,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"id":"name","path":["name"]}],"claim_sets":[["unknown"]]}]}"#,
            DcqlError::InvalidClaimSet,
        ),
    ] {
        let query: DcqlQuery = serde_json::from_str(json).expect("DCQL shape must deserialize");
        assert_eq!(query.validate(), Err(expected));
    }

    let query: DcqlQuery = serde_json::from_str(
        r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"id":"name","path":["person","name"]}],"claim_sets":[["name"]]}]}"#,
    )
    .expect("valid DCQL must deserialize");
    assert_eq!(query.validate(), Ok(()));
}
