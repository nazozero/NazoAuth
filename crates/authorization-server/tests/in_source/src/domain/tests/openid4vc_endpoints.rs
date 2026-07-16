use nazo_digital_credentials::CredentialFormat;
use nazo_identity::{SubjectClaims, UserId};
use serde_json::json;
use uuid::Uuid;

use super::credential_subject_claims;

fn subject_claims() -> SubjectClaims {
    SubjectClaims {
        subject: UserId::new(Uuid::now_v7()).expect("valid user id"),
        preferred_username: "oidf-user".to_owned(),
        name: Some("Alice Example".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: Some("1990-01-02".to_owned()),
        zoneinfo: None,
        locale: None,
        email: "alice@example.test".to_owned(),
        email_verified: true,
        address: None,
        phone_number: None,
        phone_number_verified: false,
        updated_at: 1_784_192_400,
    }
}

#[test]
fn sd_jwt_vc_dataset_keeps_flat_subject_claims() {
    let value = credential_subject_claims(CredentialFormat::SdJwtVc, subject_claims())
        .expect("sd-jwt vc claims");

    assert_eq!(value["given_name"], "Alice");
    assert_eq!(value["family_name"], "Example");
    assert_eq!(value["birthdate"], "1990-01-02");
    assert!(value.get("org.iso.18013.5.1").is_none());
}

#[test]
fn mdoc_dataset_uses_iso_namespace_and_mdoc_birth_date_name() {
    let subject = subject_claims();
    let document_number = format!("NAZO-{}", subject.subject.as_uuid().simple());
    let value = credential_subject_claims(CredentialFormat::MsoMdoc, subject).expect("mdoc claims");

    assert_eq!(
        value,
        json!({
            "org.iso.18013.5.1": {
                "birth_date": "1990-01-02",
                "document_number": document_number,
                "driving_privileges": [
                    {
                        "expiry_date": "2036-07-16",
                        "issue_date": "2026-07-16",
                        "vehicle_category_code": "B"
                    }
                ],
                "email": "alice@example.test",
                "expiry_date": "2036-07-16",
                "family_name": "Example",
                "given_name": "Alice",
                "issue_date": "2026-07-16",
                "issuing_authority": "NazoAuth OpenID4VC OIDF Test Issuer",
                "issuing_country": "UT",
                "portrait": "openid4vc-oidf-placeholder-portrait",
                "resident_address": null,
                "un_distinguishing_sign": "UT"
            }
        })
    );
}

#[test]
fn mdoc_dataset_contains_iso_18013_5_mandatory_mdl_elements() {
    let value = credential_subject_claims(CredentialFormat::MsoMdoc, subject_claims())
        .expect("mdoc claims");
    let namespace = value["org.iso.18013.5.1"]
        .as_object()
        .expect("mdoc namespace");

    for element in [
        "family_name",
        "given_name",
        "birth_date",
        "issue_date",
        "expiry_date",
        "issuing_country",
        "issuing_authority",
        "document_number",
        "portrait",
        "driving_privileges",
        "un_distinguishing_sign",
    ] {
        assert!(
            namespace.contains_key(element),
            "missing mandatory mDL element {element}"
        );
    }
}
