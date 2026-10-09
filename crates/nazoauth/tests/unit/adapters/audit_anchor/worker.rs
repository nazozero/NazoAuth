use super::*;

#[test]
fn recent_committed_observation_avoids_another_write() {
    let now = Utc::now();
    let interval = Duration::from_secs(5);
    assert!(!observation_due(Some(now), now, interval));
    assert!(!observation_due(
        Some(now - ChronoDuration::milliseconds(4999)),
        now,
        interval,
    ));
}

#[test]
fn missing_expired_or_future_observation_requires_a_write() {
    let now = Utc::now();
    let interval = Duration::from_secs(5);
    for observed_at in [
        None,
        Some(now - ChronoDuration::seconds(5)),
        Some(now - ChronoDuration::seconds(6)),
        Some(now + ChronoDuration::seconds(1)),
    ] {
        assert!(observation_due(observed_at, now, interval));
    }
}

#[test]
fn zero_observation_interval_never_suppresses_a_heartbeat() {
    let now = Utc::now();
    assert!(observation_due(Some(now), now, Duration::ZERO));
}
