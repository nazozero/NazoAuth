use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nazo_operator_protocol::{TenantResourceIdentity, TenantResourceKind};
use sha2::Sha256;

use super::*;

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn change_set_decoder_requires_the_exact_signed_identity_set() {
    let payload = serde_json::to_vec(&serde_json::json!({
        "username": "alice",
        "email": "alice@example.com",
        "password": "correct horse battery staple",
        "email_verified": true
    }))
    .unwrap();
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-alice".to_owned(),
        digest: digest(&payload),
    };
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [{
            "kind": "user",
            "resource_id": "user-alice",
            "payload_base64url": URL_SAFE_NO_PAD.encode(&payload)
        }]
    }))
    .unwrap();
    let authorized = [identity.clone()];

    assert!(decode_change_set_payloads(&manifest, &[identity.clone(), identity.clone()]).is_err());
    let decoded = decode_change_set_payloads(&manifest, &authorized).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].identity, identity);

    let mut drifted = authorized;
    drifted[0].digest = "0".repeat(64);
    assert!(decode_change_set_payloads(&manifest, &drifted).is_err());
}

#[test]
fn change_set_identity_is_unique_by_kind_and_resource_id() {
    let user_payload = serde_json::to_vec(&serde_json::json!({
        "username": "shared",
        "email": "shared@example.com",
        "password": "correct horse battery staple",
        "email_verified": true
    }))
    .unwrap();
    let dataset_payload = serde_json::to_vec(&serde_json::json!({
        "user_resource_id": "shared",
        "configuration_id": "employee-card",
        "claims": {}
    }))
    .unwrap();
    let user = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "shared".to_owned(),
        digest: digest(&user_payload),
    };
    let dataset = TenantResourceIdentity {
        kind: TenantResourceKind::Openid4vcDataset,
        resource_id: "shared".to_owned(),
        digest: digest(&dataset_payload),
    };
    let authorized = [user, dataset];
    let resource = |kind: &str, payload: &[u8]| {
        serde_json::json!({
            "kind": kind,
            "resource_id": "shared",
            "payload_base64url": URL_SAFE_NO_PAD.encode(payload)
        })
    };

    let cross_kind = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [
            resource("user", &user_payload),
            resource("openid4vc-dataset", &dataset_payload)
        ]
    }))
    .unwrap();
    assert_eq!(
        decode_change_set_payloads(&cross_kind, &authorized)
            .unwrap()
            .len(),
        2
    );

    let duplicate = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [
            resource("user", &user_payload),
            resource("user", &user_payload)
        ]
    }))
    .unwrap();
    assert!(decode_change_set_payloads(&duplicate, &authorized).is_err());
}

#[test]
fn current_action_names_are_closed() {
    assert_eq!(operation_name(TenantResourceAction::Apply), "apply");
    assert_eq!(operation_name(TenantResourceAction::Enumerate), "enumerate");
    assert_eq!(operation_name(TenantResourceAction::Revoke), "revoke");
}

#[test]
fn user_profile_decodes_owned_fields_and_preserves_closed_bounds() {
    let decode = |profile| {
        let payload = serde_json::to_vec(&serde_json::json!({
            "username": "alice", "email": "alice@example.com",
            "password": "correct horse battery staple", "email_verified": true,
            "profile": profile,
        }))
        .unwrap();
        decode_payload(TenantResourceKind::User, &payload)
    };
    let TenantResourcePayload::User(user) = decode(serde_json::json!({
        "display_name": "张三", "given_name": null,
        "phone_number": "+8613800000000", "phone_number_verified": true,
    }))
    .unwrap() else {
        panic!("expected user payload")
    };
    assert_eq!(user.profile.display_name.as_deref(), Some("张三"));
    assert_eq!(user.profile.given_name, None);
    assert!(user.profile.phone_number_verified);
    for profile in [
        serde_json::json!({"is_admin": true}),
        serde_json::json!({"display_name": "x".repeat(81)}),
        serde_json::json!({"display_name": ""}),
        serde_json::json!({"display_name": "name\n"}),
        serde_json::json!({"display_name": 42}),
        serde_json::json!({"phone_number_verified": null}),
        serde_json::json!([]),
    ] {
        let description = profile.to_string();
        assert!(
            decode(profile).is_err(),
            "accepted invalid profile: {description}"
        );
    }
    let TenantResourcePayload::User(user) = decode(serde_json::Value::Null).unwrap() else {
        panic!("expected user payload")
    };
    assert!(user.profile.display_name.is_none());
    assert!(!user.profile.phone_number_verified);
}
