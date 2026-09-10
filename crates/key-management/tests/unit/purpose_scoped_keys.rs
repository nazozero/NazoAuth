use std::{collections::BTreeSet, time::Duration};

use crate::{KeyRecordStatus, KeySettings, LocalKeyRegistration, test_support::key_manager};
use nazo_auth::{SignError, SignRequest, Signer, SigningPurpose};

fn settings(rotation_interval: chrono::Duration) -> KeySettings {
    KeySettings {
        external_command: Vec::new(),
        external_timeout: Duration::from_secs(2),
        rotation_interval,
        prepublish_window: chrono::Duration::zero(),
        verification_grace: chrono::Duration::minutes(10),
    }
}

fn openid4vc_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect()
}

#[tokio::test]
async fn purpose_scoped_key_signs_only_declared_openid4vc_purposes() {
    let manager = key_manager(settings(chrono::Duration::seconds(-1)))
        .await
        .unwrap();
    let scoped_kid = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: openid4vc_purposes(),
        })
        .await
        .unwrap();
    let retried_kid = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: openid4vc_purposes(),
        })
        .await
        .expect("an exact purpose-scoped registration retry must be idempotent");
    assert_eq!(retried_kid, scoped_kid);

    for purpose in [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ] {
        assert!(
            manager
                .sign(SignRequest {
                    purpose,
                    algorithm: "ES256",
                    signing_input: b"header.payload",
                })
                .await
                .is_ok()
        );
    }
    for purpose in [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
    ] {
        assert_eq!(
            manager
                .sign(SignRequest {
                    purpose,
                    algorithm: "ES256",
                    signing_input: b"header.payload",
                })
                .await,
            Err(SignError::KeyUnavailable)
        );
    }

    manager.refresh().await.unwrap();
    let snapshot = manager.snapshot();
    assert_ne!(snapshot.active_kid, scoped_kid);
    let scoped = snapshot.verification_key(&scoped_kid).unwrap();
    assert!(scoped.can_sign(SigningPurpose::Credential));
    assert!(!scoped.can_sign(SigningPurpose::IdToken));
    assert_eq!(
        manager
            .database_list_keys()
            .await
            .unwrap()
            .into_iter()
            .find(|key| key.kid == scoped_kid)
            .unwrap()
            .status,
        KeyRecordStatus::PurposeScoped
    );
}

#[tokio::test]
async fn overlapping_purpose_scoped_keys_are_rejected() {
    let manager = key_manager(settings(chrono::Duration::days(90)))
        .await
        .unwrap();
    manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [SigningPurpose::Credential].into_iter().collect(),
        })
        .await
        .unwrap();

    let error = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: openid4vc_purposes(),
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("already covers"));
}

#[tokio::test]
async fn purpose_scoped_registration_rejects_oidc_signing_purposes() {
    let manager = key_manager(settings(chrono::Duration::days(90)))
        .await
        .unwrap();
    let error = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [SigningPurpose::IdToken].into_iter().collect(),
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("restricted"));
}
