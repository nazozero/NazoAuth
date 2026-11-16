use super::*;

#[tokio::test]
async fn access_and_notification_fail_closed_for_invalid_bearer() {
    let issuer = operations(true).await;
    let context = request_context();
    let access_error = issuer
        .access(&context)
        .await
        .expect_err("invalid bearer must not reach credential state");
    assert_error(
        access_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );

    let notify_error = issuer
        .notify(
            context,
            NotificationRequest {
                notification_id: "unit-notification".to_owned(),
                event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                event_description: Some("unit".to_owned()),
            },
        )
        .await
        .expect_err("notification requires a valid access token");
    assert_error(
        notify_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );
}
