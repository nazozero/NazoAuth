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
    let mut value =
        serde_json::json!({"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]});
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
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{},"claims":[{"path":[]}]}]}"#,
            DcqlError::EmptyClaimPath,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{},"claims":[{"id":"","path":["name"]}]}]}"#,
            DcqlError::InvalidClaimId,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{},"claims":[{"id":"name","path":["name"]},{"id":"name","path":["family_name"]}]}]}"#,
            DcqlError::InvalidClaimId,
        ),
        (
            r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{},"claims":[{"id":"name","path":["name"]}],"claim_sets":[["unknown"]]}]}"#,
            DcqlError::InvalidClaimSet,
        ),
    ] {
        let query: DcqlQuery = serde_json::from_str(json).expect("DCQL shape must deserialize");
        assert_eq!(query.validate(), Err(expected));
    }

    let query: DcqlQuery = serde_json::from_str(
        r#"{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{},"claims":[{"id":"name","path":["person","name"]}],"claim_sets":[["name"]]}]}"#,
    )
    .expect("valid DCQL must deserialize");
    assert_eq!(query.validate(), Ok(()));
}

#[test]
fn dcql_ignores_extensions_at_every_object_level_without_weakening_known_fields() {
    let mut wire = serde_json::json!({
        "future_query": {"version": 2},
        "credentials": [{
            "id": "pid", "format": "dc+sd-jwt", "meta": {},
            "future_credential": true,
            "claims": [{"id": "name", "path": ["given_name"], "future_claim": 7}],
            "claim_sets": [["name"]],
            "trusted_authorities": [{"type": "aki", "values": ["AQID"], "future_authority": []}]
        }],
        "credential_sets": [{"options": [["pid"]], "future_set": null}]
    });
    let query: DcqlQuery =
        serde_json::from_value(wire.clone()).expect("extension properties ignored");
    assert_eq!(query.validate(), Ok(()));
    assert_eq!(
        query.credentials[0].claims.as_ref().unwrap()[0]
            .id
            .as_deref(),
        Some("name")
    );
    assert!(query.credential_sets.as_ref().unwrap()[0].required);
    wire["credentials"][0]["multiple"] = serde_json::json!(1);
    assert!(serde_json::from_value::<DcqlQuery>(wire.clone()).is_err());
    wire["credentials"][0]["multiple"] = serde_json::json!(false);
    wire["credentials"][0]["claim_sets"] = serde_json::json!([["undefined"]]);
    let invalid: DcqlQuery = serde_json::from_value(wire).unwrap();
    assert_eq!(invalid.validate(), Err(DcqlError::InvalidClaimSet));
}

#[test]
fn dcql_rejects_empty_sets_and_malformed_known_metadata_while_ignoring_extensions() {
    let base = serde_json::json!({"credentials":[{
        "id":"pid", "format":"dc+sd-jwt", "meta":{}
    }]});
    let mut empty_sets = base.clone();
    empty_sets["credential_sets"] = serde_json::json!([]);
    assert_eq!(
        serde_json::from_value::<DcqlQuery>(empty_sets)
            .unwrap()
            .validate(),
        Err(DcqlError::InvalidCredentialSet)
    );
    for meta in [
        serde_json::Value::Null,
        serde_json::json!(17),
        serde_json::json!([]),
        serde_json::json!({"vct_values":"required-type"}),
        serde_json::json!({"vct_values":[]}),
        serde_json::json!({"vct_values":[17]}),
        serde_json::json!({"vct_values":[""]}),
    ] {
        let mut wire = base.clone();
        wire["credentials"][0]["meta"] = meta;
        assert_eq!(
            serde_json::from_value::<DcqlQuery>(wire)
                .unwrap()
                .validate(),
            Err(DcqlError::InvalidMetadata)
        );
    }
    let mut missing = base.clone();
    missing["credentials"][0]
        .as_object_mut()
        .unwrap()
        .remove("meta");
    assert_eq!(
        serde_json::from_value::<DcqlQuery>(missing)
            .unwrap()
            .validate(),
        Err(DcqlError::InvalidMetadata)
    );
    for value in [
        serde_json::json!(["required-doctype"]),
        serde_json::json!(null),
        serde_json::json!(""),
    ] {
        let mut wire = base.clone();
        wire["credentials"][0]["format"] = serde_json::json!("mso_mdoc");
        wire["credentials"][0]["meta"] = serde_json::json!({"doctype_value":value});
        assert_eq!(
            serde_json::from_value::<DcqlQuery>(wire)
                .unwrap()
                .validate(),
            Err(DcqlError::InvalidMetadata)
        );
    }
    for (format, meta) in [
        (
            "dc+sd-jwt",
            serde_json::json!({"vct_values":["ExampleCredential"],"future_constraint":17}),
        ),
        (
            "mso_mdoc",
            serde_json::json!({"doctype_value":"org.iso.18013.5.1.mDL","future_constraint":[]}),
        ),
        ("dc+sd-jwt", serde_json::json!({"future_constraint":17})),
    ] {
        let mut wire = base.clone();
        wire["credentials"][0]["format"] = format.into();
        wire["credentials"][0]["meta"] = meta;
        assert_eq!(
            serde_json::from_value::<DcqlQuery>(wire)
                .unwrap()
                .validate(),
            Ok(())
        );
    }
}
