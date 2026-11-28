use nazo_auth::{RequestRateLimitBucket, RequestRateLimitPort};

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_window_counts_concurrent_requests_without_sliding_or_aliases() {
    let state = crate::test_support::test_state();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            RequestRateLimitPort::increment(
                &state,
                RequestRateLimitBucket::Authentication,
                "subject",
                60,
            )
            .await
            .unwrap()
        }));
    }
    let mut counts = Vec::new();
    for task in tasks {
        counts.push(task.await.unwrap());
    }
    counts.sort_unstable();
    assert_eq!(counts, (1..=32).collect::<Vec<_>>());
    assert_eq!(
        RequestRateLimitPort::increment(
            &state,
            RequestRateLimitBucket::Authentication,
            "subject",
            3_600,
        )
        .await
        .unwrap(),
        33
    );
    let key = state.key("rate-auth", &[b"subject"]);
    assert!(state.volatile.ttl_ms(&key) <= 60_000);
    assert_eq!(
        RequestRateLimitPort::increment(&state, RequestRateLimitBucket::Token, "subject", 60,)
            .await
            .unwrap(),
        1
    );

    state.record_failure("b:c", "a", 60).await.unwrap();
    assert_eq!(state.failure_count("b:c", "a").await.unwrap(), 1);
    assert_eq!(state.failure_count("c", "a:b").await.unwrap(), 0);
    state.clear_failure("b:c", "a").await.unwrap();
    assert_eq!(state.failure_count("b:c", "a").await.unwrap(), 0);
}
