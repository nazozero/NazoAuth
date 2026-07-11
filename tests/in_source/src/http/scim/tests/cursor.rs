use super::*;
use crate::config::ConfigSource;
use crate::http::scim::auth::ScimCredential;
use crate::settings::Settings;
use chrono::{Duration, Utc};
use uuid::Uuid;

fn cursor_settings() -> Settings {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.client_secret_pepper = "cursor-test-pepper-32-bytes-minimum-value".to_owned();
    settings
}

fn database_credential() -> ScimCredential {
    ScimCredential {
        token_id: Some(Uuid::from_u128(0x11111111111111111111111111111111)),
        tenant_id: Uuid::from_u128(0x22222222222222222222222222222222),
        scopes: vec!["scim:read".to_owned()],
        source: "database",
    }
}

#[test]
fn scim_cursor_round_trip_is_opaque_url_safe_and_randomized() {
    let settings = cursor_settings();
    let credential = database_credential();
    let filter = Some("userName eq \"alice@example.test\"");
    let now = Utc::now();
    let last_created_at = now - Duration::seconds(30);
    let last_id = Uuid::from_u128(0x33333333333333333333333333333333);
    let context = ScimCursorContext {
        credential: &credential,
        filter,
        count: 25,
        last_created_at,
        last_id,
    };

    let first = encode_scim_cursor(&settings, &context, now).expect("cursor should encode");
    let second = encode_scim_cursor(&settings, &context, now).expect("cursor should encode");

    assert_ne!(first, second);
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert!(!first.contains('='));
    assert!(!first.contains("alice@example.test"));
    assert!(!first.contains(&credential.tenant_id.to_string()));
    assert!(!first.contains(&credential.token_id.expect("token id").to_string()));
    assert!(!first.contains(&last_id.to_string()));
    assert_eq!(
        decode_scim_cursor(&settings, &first, &credential, filter, 25, now,),
        Ok(ScimCursorPosition {
            last_created_at,
            last_id,
        })
    );
}

fn encoded_cursor(
    settings: &Settings,
    credential: &ScimCredential,
    now: chrono::DateTime<Utc>,
) -> String {
    encode_scim_cursor(
        settings,
        &ScimCursorContext {
            credential,
            filter: Some("userName eq \"alice@example.test\""),
            count: 25,
            last_created_at: now - Duration::seconds(30),
            last_id: Uuid::from_u128(0x33333333333333333333333333333333),
        },
        now,
    )
    .expect("cursor should encode")
}

#[test]
fn scim_cursor_rejects_count_filter_actor_and_tenant_changes() {
    let settings = cursor_settings();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&settings, &credential, now);

    assert_eq!(
        decode_scim_cursor(
            &settings,
            &encoded,
            &credential,
            Some("userName eq \"alice@example.test\""),
            26,
            now,
        ),
        Err(ScimCursorError::InvalidCount)
    );
    assert_eq!(
        decode_scim_cursor(&settings, &encoded, &credential, None, 25, now),
        Err(ScimCursorError::Invalid)
    );

    let mut other_actor = credential.clone();
    other_actor.token_id = Some(Uuid::from_u128(0x44444444444444444444444444444444));
    assert_eq!(
        decode_scim_cursor(
            &settings,
            &encoded,
            &other_actor,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );

    let mut other_tenant = credential.clone();
    other_tenant.tenant_id = Uuid::from_u128(0x55555555555555555555555555555555);
    assert_eq!(
        decode_scim_cursor(
            &settings,
            &encoded,
            &other_tenant,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );
}

#[test]
fn scim_cursor_rejects_expired_and_future_issued_payloads() {
    let settings = cursor_settings();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&settings, &credential, now);

    assert_eq!(
        decode_scim_cursor(
            &settings,
            &encoded,
            &credential,
            Some("userName eq \"alice@example.test\""),
            25,
            now + Duration::seconds(SCIM_CURSOR_TIMEOUT_SECONDS),
        ),
        Err(ScimCursorError::Expired)
    );

    let future = encoded_cursor(&settings, &credential, now + Duration::seconds(61));
    assert_eq!(
        decode_scim_cursor(
            &settings,
            &future,
            &credential,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );
}

#[test]
fn scim_cursor_rejects_tampering_padding_truncation_and_oversize_input() {
    let settings = cursor_settings();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&settings, &credential, now);
    let mut tampered = encoded.clone().into_bytes();
    let last = tampered.last_mut().expect("cursor should not be empty");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("cursor should remain ASCII");

    for invalid in [
        tampered,
        format!("{encoded}="),
        encoded[..8].to_owned(),
        "A".repeat(SCIM_CURSOR_MAX_ENCODED_LEN + 1),
    ] {
        assert_eq!(
            decode_scim_cursor(
                &settings,
                &invalid,
                &credential,
                Some("userName eq \"alice@example.test\""),
                25,
                now,
            ),
            Err(ScimCursorError::Invalid)
        );
    }
}
