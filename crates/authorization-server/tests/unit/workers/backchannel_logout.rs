use super::*;
#[test]
fn retries_are_bounded_and_never_scheduled_after_expiry() {
    let now = Utc::now();
    assert_eq!(
        next_retry_at(0, now, now + Duration::seconds(60)),
        Some(now + Duration::seconds(5))
    );
    assert_eq!(
        next_retry_at(1, now, now + Duration::seconds(60)),
        Some(now + Duration::seconds(15))
    );
    assert_eq!(
        next_retry_at(2, now, now + Duration::seconds(60)),
        Some(now + Duration::seconds(45))
    );
    assert_eq!(next_retry_at(3, now, now + Duration::seconds(60)), None);
    assert_eq!(next_retry_at(2, now, now + Duration::seconds(45)), None);
}

#[test]
fn persisted_delivery_errors_are_unicode_safe_and_bounded() {
    let error = "失".repeat(ERROR_MAX_CHARS + 10);
    let truncated = truncate_error(&error);
    assert_eq!(truncated.chars().count(), ERROR_MAX_CHARS);
    assert!(truncated.is_char_boundary(truncated.len()));
}

#[test]
fn backchannel_response_classification_retries_only_recoverable_statuses() {
    assert_eq!(
        classify_backchannel_status(200),
        BackchannelResponseAction::Delivered
    );
    assert_eq!(
        classify_backchannel_status(204),
        BackchannelResponseAction::Delivered
    );
    for status in [408, 425, 429, 500, 503, 599] {
        assert_eq!(
            classify_backchannel_status(status),
            BackchannelResponseAction::Retry,
            "status {status}"
        );
    }
    for status in [201, 202, 206, 300, 400, 401, 404, 422] {
        assert_eq!(
            classify_backchannel_status(status),
            BackchannelResponseAction::TerminalFailure,
            "status {status}"
        );
    }
}

#[test]
fn delivery_failure_state_distinguishes_terminal_and_retryable_outcomes() {
    let now = Utc::now();
    let expires_at = now + Duration::seconds(60);
    let (next_attempt_at, terminal) =
        delivery_failure_state(Ok(http::StatusCode::BAD_REQUEST), 1, now, expires_at);
    assert_eq!(next_attempt_at, None);
    assert!(terminal.to_string().contains("terminal status 400"));

    let (next_attempt_at, retryable) = delivery_failure_state(
        Err(anyhow::anyhow!("network unavailable")),
        2,
        now,
        expires_at,
    );
    assert_eq!(next_attempt_at, Some(now + Duration::seconds(15)));
    assert_eq!(retryable.to_string(), "network unavailable");

    let (next_attempt_at, retryable) = delivery_failure_state(
        Ok(http::StatusCode::SERVICE_UNAVAILABLE),
        1,
        now,
        expires_at,
    );
    assert_eq!(next_attempt_at, Some(now + Duration::seconds(5)));
    assert!(retryable.to_string().contains("retryable status 503"));
}
