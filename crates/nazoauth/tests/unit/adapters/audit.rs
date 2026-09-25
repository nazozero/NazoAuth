use super::*;
use nazo_oauth_server::ports::audit::audit_fields;
use serde_json::json;

#[tokio::test]
async fn interleaved_requests_capture_their_own_tenant_before_audit_queueing() {
    let tenant_a = nazo_identity::TenantId::new(Uuid::from_u128(101)).unwrap();
    let tenant_b = nazo_identity::TenantId::new(Uuid::from_u128(102)).unwrap();
    let capture = |tenant| {
        REQUEST_TENANT.scope(tenant, async {
            tokio::task::yield_now().await;
            prepare_event(
                "login_success",
                audit_fields(&[("user_id", json!("same-id"))]),
            )
            .unwrap()
        })
    };
    let (event_a, event_b) = tokio::join!(capture(tenant_a), capture(tenant_b));
    assert_eq!(event_a.payload["tenant_id"], json!(tenant_a));
    assert_eq!(event_b.payload["tenant_id"], json!(tenant_b));
    assert!(REQUEST_TENANT.try_with(|tenant| *tenant).is_err());
    assert!(
        prepare_event("login_success", serde_json::Map::new())
            .unwrap()
            .payload
            .get("tenant_id")
            .is_none(),
        "an unscoped deployment event must not inherit the preceding request tenant"
    );
}

#[tokio::test]
async fn audit_payload_cannot_override_the_resolved_request_tenant() {
    let tenant_a = nazo_identity::TenantId::new(Uuid::from_u128(101)).unwrap();
    let tenant_b = nazo_identity::TenantId::new(Uuid::from_u128(102)).unwrap();
    REQUEST_TENANT
        .scope(tenant_a, async {
            assert!(matches!(
                prepare_event(
                    "login_success",
                    audit_fields(&[("tenant_id", json!(tenant_b))])
                ),
                Err("tenant_context_mismatch")
            ));
            let event = prepare_event(
                "login_success",
                audit_fields(&[("tenant_id", json!(tenant_a))]),
            )
            .unwrap();
            assert_eq!(event.payload["tenant_id"], json!(tenant_a));
        })
        .await;
}

#[test]
fn audit_fields_can_remove_sensitive_material() {
    let mut fields = audit_fields(&[
        ("client_id", json!("client-1")),
        ("access_token", json!("secret-token")),
    ]);
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }

    assert_eq!(fields.get("client_id"), Some(&json!("client-1")));
    assert!(fields.get("access_token").is_none());
}

#[test]
fn audit_event_names_are_allowlisted_and_siem_ready() {
    for (name, category, _) in AUDIT_EVENT_DEFINITIONS {
        assert!(audit_event_name_valid(name));
        assert_eq!(audit_event_category(name), Some(*category));
        assert!(audit_event_name_valid(category));
    }
    assert!(audit_event_category("unknown_event").is_none());
    assert!(!audit_event_name_valid("LoginSuccess"));
    assert!(!audit_event_name_valid("login-success"));
    assert!(!audit_event_name_valid(""));
}

#[test]
fn audit_event_definitions_include_dynamic_client_lifecycle() {
    for name in [
        "dynamic_client_registered",
        "dynamic_client_configuration_read",
        "dynamic_client_configuration_updated",
        "dynamic_client_deleted",
    ] {
        assert_eq!(audit_event_category(name), Some("client_lifecycle"));
    }
}

#[test]
fn audit_event_definitions_include_administrative_user_lifecycle() {
    for name in ["admin_user_created", "admin_user_updated"] {
        assert_eq!(audit_event_category(name), Some("administration"));
    }
}

#[test]
fn audit_event_definitions_include_external_identity_lifecycle() {
    assert_eq!(
        audit_event_category("external_identity_linked"),
        Some("identity_lifecycle")
    );
    assert_eq!(
        audit_event_category("external_identity_unlinked"),
        Some("identity_lifecycle")
    );
    assert_eq!(
        audit_event_category("external_identity_relink_denied"),
        Some("identity_lifecycle")
    );
}

#[test]
fn audit_event_definitions_include_ciba_authorization_lifecycle() {
    for name in [
        "ciba_authorization_started",
        "ciba_authorization_intent",
        "ciba_authorization_approved",
        "ciba_authorization_denied",
        "ciba_decision_intent",
    ] {
        assert_eq!(audit_event_category(name), Some("authorization"));
    }
}

#[test]
fn audit_event_definitions_include_device_authorization_lifecycle() {
    for name in [
        "device_authorization_started",
        "device_authorization_approved",
        "device_authorization_denied",
        "device_decision_intent",
    ] {
        assert_eq!(audit_event_category(name), Some("authorization"));
        assert!(prepare_event(name, serde_json::Map::new()).is_ok());
    }
}

#[test]
fn audit_event_definitions_include_authorization_decision_intent() {
    assert_eq!(
        audit_event_category("authorization_decision_intent"),
        Some("authorization")
    );
    assert!(prepare_event("authorization_decision_intent", serde_json::Map::new()).is_ok());
}

#[test]
fn audit_event_definitions_include_token_issuance_intent() {
    assert_eq!(
        audit_event_category("token_issuance_intent"),
        Some("token_lifecycle")
    );
    assert!(prepare_event("token_issuance_intent", serde_json::Map::new()).is_ok());
}

#[test]
fn audit_event_definitions_include_mfa_step_up() {
    assert_eq!(
        audit_event_category("mfa_step_up_success"),
        Some("authentication")
    );
}

#[test]
fn audit_event_definitions_include_trust_and_credential_control_planes() {
    for name in [
        "mtls_trust_anchor_requested",
        "mtls_trust_anchor_approved",
        "mtls_trust_anchor_rejected",
        "mtls_trust_anchor_revoked",
        "mtls_trust_bundle_exported",
    ] {
        assert_eq!(audit_event_category(name), Some("trust_lifecycle"));
    }
    for name in [
        "openid4vci_credential_dataset_updated",
        "openid4vci_credential_dataset_deleted",
    ] {
        assert_eq!(audit_event_category(name), Some("credential_lifecycle"));
    }
}

#[test]
fn audit_schema_version_is_stable_for_collectors() {
    assert_eq!(AUDIT_SCHEMA_VERSION, "nazo.audit.v1");
}

#[test]
fn prepare_event_normalizes_security_payload_and_rejects_unknown_or_oversized_events() {
    let queued = prepare_event(
        "login_success",
        audit_fields(&[
            ("user_id", json!("user-1")),
            ("access_token", json!("must-not-persist")),
        ]),
    )
    .expect("allowlisted audit event should be prepared");
    assert_eq!(queued.event_type, "login_success");
    assert_eq!(queued.event_category, "authentication");
    assert_eq!(
        queued.payload["schema_version"],
        json!(AUDIT_SCHEMA_VERSION)
    );
    assert_eq!(queued.payload["event_category"], json!("authentication"));
    assert!(queued.payload.get("access_token").is_none());

    assert!(matches!(
        prepare_event("unknown_event", serde_json::Map::new()),
        Err("unknown_event_type")
    ));
    let oversized = audit_fields(&[(
        "large",
        json!("x".repeat(nazo_postgres::MAX_SECURITY_AUDIT_PAYLOAD_BYTES + 1)),
    )]);
    assert!(matches!(
        prepare_event("login_success", oversized),
        Err("payload_too_large")
    ));
}

#[test]
fn prepare_event_redacts_every_known_credential_from_intent_and_outcome_payloads() {
    let mut fields = audit_fields(&[("request_id_hash", json!("request-hash"))]);
    for key in SENSITIVE_FIELD_NAMES {
        fields.insert((*key).to_owned(), json!(format!("{key}-raw-secret")));
    }

    for event in [
        "authorization_decision_intent",
        "ciba_decision_intent",
        "device_decision_intent",
        "token_issuance_intent",
        "token_issued",
    ] {
        let queued = prepare_event(event, fields.clone())
            .expect("high-impact audit event should be allowlisted");
        let serialized = serde_json::to_string(&queued.payload).expect("payload should serialize");
        for key in SENSITIVE_FIELD_NAMES {
            assert!(
                queued.payload.get(*key).is_none(),
                "{event} must omit sensitive field {key}"
            );
            assert!(
                !serialized.contains(&format!("{key}-raw-secret")),
                "{event} must not serialize sensitive value {key}"
            );
        }
        assert_eq!(queued.payload["request_id_hash"], json!("request-hash"));
    }
}

fn assert_source_order(source: &str, earlier: &str, later: &str) {
    let earlier_offset = source
        .find(earlier)
        .unwrap_or_else(|| panic!("missing source marker {earlier}"));
    let later_offset = source
        .find(later)
        .unwrap_or_else(|| panic!("missing source marker {later}"));
    assert!(
        earlier_offset < later_offset,
        "source marker {earlier} must precede {later}"
    );
}

fn source_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary {end}"))
        .0
}

#[test]
fn high_impact_state_changes_are_guarded_by_required_audit_intent() {
    // This is a source-level architecture guard for the fail-closed ordering
    // around mutations. Runtime audit serialization is exercised above; this
    // guard prevents a future refactor from moving the required intent behind
    // a state change without pretending to be a protocol E2E test.
    let authorization =
        include_str!("../../../../authorization-server/src/domain/authorization_decision.rs");
    assert_source_order(authorization, ".ensure_storage()", "preview_user_decision(");
    assert_source_order(authorization, "preview_user_decision(", "record_required(");
    assert_source_order(authorization, "record_required(", "consume_user_decision(");
    assert!(authorization.contains("AuthorizationDecisionError::AuditUnavailable"));

    let device = include_str!("../../../../authorization-server/src/token/device.rs");
    assert_source_order(device, ".ensure_storage()", "record_required(");
    assert_source_order(device, "record_required(", "let result = match decision {");
    assert!(device.contains("设备授权审计无法持久化."));

    let ciba = include_str!("../../../../authorization-server/src/token/ciba/decision.rs");
    let ciba_intent = source_body(
        ciba,
        "async fn prepare_ciba_decision_intent(",
        "async fn set_ciba_request_decision(",
    );
    assert_source_order(ciba_intent, ".ensure_storage()", ".record_required(");
    let ciba_browser = source_body(
        ciba,
        "pub async fn decide(",
        "async fn load_ciba_request_payload(",
    );
    assert!(
        ciba_browser.contains("set_ciba_request_decision("),
        "browser CIBA decisions must use the ordinary user mutation path"
    );
    assert!(ciba.contains("CIBA decision audit could not be persisted."));

    let issuance = include_str!("../../../../authorization-server/src/token/issue_grant.rs");
    // Token issuance commits its success audit in the same PG transaction as
    // the durable token fact.  Issuance must run an audit-readiness gate of
    // the appropriate strength before that commit: commit-owned Fresh
    // issuance may rely on the transaction itself (transactional readiness);
    // every path carrying earlier durable side effects keeps the full
    // storage preflight.  The retired intent/saga markers must not return.
    assert_source_order(
        issuance,
        "context.security_audit.ensure_transactional_ready().await",
        "commit_token_issuance(",
    );
    assert_source_order(
        issuance,
        "context.security_audit.ensure_storage().await",
        "commit_token_issuance(",
    );
    assert!(
        issuance.contains("matches!(mode, TokenIssuanceMode::Fresh)"),
        "transactional readiness must be gated on commit-owned Fresh issuance"
    );
    let pre_commit = source_body(issuance, "let commit_owned", "commit_token_issuance(");
    assert!(
        pre_commit.contains("issue.native_sso.is_none()"),
        "Native SSO persists a device secret before the commit and must \
         keep the full storage preflight"
    );
    assert!(!issuance.contains("token_issuance_intent"));
    assert!(!issuance.contains("record_token_issuance_signed("));
}

#[tokio::test]
async fn explicitly_bound_audit_does_not_use_the_request_tenant() {
    let bound = nazo_identity::TenantId::new(Uuid::from_u128(701)).unwrap();
    let request = nazo_identity::TenantId::new(Uuid::from_u128(702)).unwrap();
    let audit = TenantSecurityAudit::new(bound);
    REQUEST_TENANT
        .scope(request, async {
            let queued = prepare_event_for_tenant(
                "login_success",
                serde_json::Map::new(),
                Some(audit.tenant_id),
            )
            .unwrap();
            assert_eq!(queued.payload["tenant_id"], json!(bound));
            let error = audit
                .record_required(
                    "login_success",
                    audit_fields(&[("tenant_id", json!(request))]),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("tenant_context_mismatch"));
        })
        .await;
}

#[test]
fn explicitly_bound_audit_captures_tenant_without_request_scope() {
    let tenant = nazo_identity::TenantId::new(Uuid::from_u128(703)).unwrap();
    let audit = TenantSecurityAudit::new(tenant);
    let queued = prepare_event_for_tenant(
        "login_success",
        serde_json::Map::new(),
        Some(audit.tenant_id),
    )
    .unwrap();
    assert_eq!(queued.payload["tenant_id"], json!(tenant));
}

mod queue_persistence {
    use super::*;
    use futures_util::future::BoxFuture;
    use nazo_identity::ports::RepositoryError;
    use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditLedger};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    struct FakeLedger {
        appended: Mutex<Vec<Uuid>>,
        batches: Mutex<Vec<Vec<Uuid>>>,
        fail_next: AtomicU64,
        fail_next_batch: AtomicU64,
    }

    impl FakeLedger {
        fn new() -> Self {
            Self {
                appended: Mutex::new(Vec::new()),
                batches: Mutex::new(Vec::new()),
                fail_next: AtomicU64::new(0),
                fail_next_batch: AtomicU64::new(0),
            }
        }
    }

    impl SecurityAuditLedger for FakeLedger {
        fn check_available(
            &self,
            _require_least_privilege: bool,
        ) -> BoxFuture<'_, Result<(), RepositoryError>> {
            Box::pin(async { Ok(()) })
        }

        fn anchor_health(
            &self,
        ) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
            Box::pin(async {
                Ok(SecurityAuditAnchorHealth {
                    head_sequence: 0,
                    head_hash: vec![0; 32],
                    pending_exists: false,
                    pending_estimate: 0,
                    pending_orphan_exists: false,
                    oldest_pending_occurred_at: None,
                    last_exported_sequence: None,
                    last_exported_hash: None,
                    last_exported_occurred_at: None,
                    last_exported_at: None,
                    deployment_id: None,
                    observed_at: None,
                    batch: None,
                })
            })
        }

        fn append(&self, event: SecurityAuditEvent) -> BoxFuture<'_, Result<(), RepositoryError>> {
            Box::pin(async move {
                if self.fail_next.load(AtomicOrdering::Relaxed) > 0 {
                    self.fail_next.fetch_sub(1, AtomicOrdering::Relaxed);
                    return Err(RepositoryError::Unavailable);
                }
                self.appended.lock().unwrap().push(event.event_id);
                Ok(())
            })
        }

        fn append_batch<'a>(
            &'a self,
            events: &'a [SecurityAuditEvent],
        ) -> BoxFuture<'a, Result<(), RepositoryError>> {
            Box::pin(async move {
                if self.fail_next_batch.load(AtomicOrdering::Relaxed) > 0 {
                    self.fail_next_batch.fetch_sub(1, AtomicOrdering::Relaxed);
                    return Err(RepositoryError::Unavailable);
                }
                let ids: Vec<Uuid> = events.iter().map(|event| event.event_id).collect();
                self.appended.lock().unwrap().extend_from_slice(&ids);
                self.batches.lock().unwrap().push(ids);
                Ok(())
            })
        }
    }

    // The queue counters are process-global atomics, so tests that assert on
    // their deltas must not overlap.
    static COUNTER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn telemetry_event() -> QueuedAuditEvent {
        prepare_event("login_success", serde_json::Map::new()).unwrap()
    }

    fn counters() -> (u64, u64, u64, u64, u64, u64) {
        (
            AUDIT_QUEUE_ENQUEUED.load(Ordering::Relaxed),
            AUDIT_QUEUE_PERSISTED.load(Ordering::Relaxed),
            AUDIT_QUEUE_DROPPED.load(Ordering::Relaxed),
            AUDIT_PERSIST_BATCHES.load(Ordering::Relaxed),
            AUDIT_PERSIST_BATCH_EVENTS.load(Ordering::Relaxed),
            AUDIT_PERSIST_MAX_BATCH.load(Ordering::Relaxed),
        )
    }

    #[tokio::test]
    async fn worker_persists_a_single_event_immediately_without_batching() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let (sender, receiver) = mpsc::channel(8);
        let ledger = Arc::new(FakeLedger::new());
        let worker = tokio::spawn(run_audit_persist_worker(receiver, ledger.clone()));
        let (e0, p0, _, b0, be0, _) = counters();
        let event = telemetry_event();
        let id = event.event_id;
        sender.send(event).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ledger.appended.lock().unwrap().contains(&id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a single queued event must persist without waiting to batch");
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker must finish after the sender closes")
            .unwrap();
        let (e1, p1, _, b1, be1, m1) = counters();
        assert_eq!(p1 - p0, 1);
        assert_eq!(b1 - b0, 1);
        assert_eq!(be1 - be0, 1);
        assert!(m1 >= 1);
        let _ = (e0, e1);
    }

    #[tokio::test]
    async fn worker_retries_failed_append_then_preserves_order() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let (sender, receiver) = mpsc::channel(8);
        let ledger = Arc::new(FakeLedger::new());
        ledger.fail_next.store(1, AtomicOrdering::Relaxed);
        let worker = tokio::spawn(run_audit_persist_worker(receiver, ledger.clone()));
        let first = telemetry_event();
        let second = telemetry_event();
        let (id_first, id_second) = (first.event_id, second.event_id);
        sender.send(first).await.unwrap();
        sender.send(second).await.unwrap();
        drop(sender);
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .expect("worker must drain and exit after retries")
            .unwrap();
        let appended = ledger.appended.lock().unwrap();
        assert_eq!(
            appended.as_slice(),
            &[id_first, id_second],
            "the retried event must not be skipped or reordered"
        );
    }

    #[tokio::test]
    async fn queue_counters_reconcile_enqueue_persist_drop_and_pending() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let (sender, receiver) = mpsc::channel(4);
        let ledger = Arc::new(FakeLedger::new());
        let worker = tokio::spawn(run_audit_persist_worker(receiver, ledger.clone()));
        let (e0, p0, d0, _, _, _) = counters();
        for _ in 0..4 {
            enqueue_into_sink(&sender, "login_success", telemetry_event());
        }
        // Channel is full: the next two sends must drop, not block.
        enqueue_into_sink(&sender, "login_success", telemetry_event());
        enqueue_into_sink(&sender, "login_success", telemetry_event());
        drop(sender);
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        let (e1, p1, d1, _, _, _) = counters();
        // Counters are process-global; only deltas belong to this test.
        assert_eq!(e1 - e0, 4, "four successful try_send calls");
        assert_eq!(d1 - d0, 2, "two queue_full rejections");
        assert_eq!(p1 - p0, 4, "each enqueued event persisted");
    }

    #[tokio::test]
    async fn required_append_uses_the_direct_ledger_path_not_the_queue() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let fake = Arc::new(FakeLedger::new());
        let ledger: Arc<dyn SecurityAuditLedger> = fake.clone();
        let (e0, _, d0, _, _, _) = counters();
        let queued = prepare_event("token_issued", serde_json::Map::new()).unwrap();
        append_required_via(&ledger, "token_issued", queued)
            .await
            .expect("required append should succeed");
        let (e1, _, d1, _, _, _) = counters();
        assert_eq!(e1 - e0, 0, "required evidence must not enter the queue");
        assert_eq!(d1 - d0, 0);
        assert!(
            fake.batches.lock().unwrap().is_empty(),
            "required append must not go through append_batch"
        );
    }

    #[tokio::test]
    async fn burst_events_persist_in_bounded_batches() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let (sender, receiver) = mpsc::channel(256);
        let ledger = Arc::new(FakeLedger::new());
        let worker = tokio::spawn(run_audit_persist_worker(receiver, ledger.clone()));
        let (e0, p0, _, b0, be0, _) = counters();
        let mut ids = Vec::new();
        for _ in 0..130 {
            let event = telemetry_event();
            ids.push(event.event_id);
            sender.send(event).await.unwrap();
        }
        drop(sender);
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .expect("burst must drain after sender close")
            .unwrap();
        let batches = ledger.batches.lock().unwrap();
        assert!(
            batches
                .iter()
                .all(|batch| batch.len() <= AUDIT_PERSIST_BATCH_MAX),
            "no batch may exceed {AUDIT_PERSIST_BATCH_MAX}: {:?}",
            batches.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert!(
            batches.iter().any(|batch| batch.len() > 1),
            "a backlog must form at least one multi-event batch"
        );
        let persisted: Vec<Uuid> = batches.iter().flatten().copied().collect();
        assert_eq!(persisted.len(), 130);
        // Every queued event landed exactly once; queue order is preserved
        // within and across batches.
        let mut sorted = persisted.clone();
        sorted.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(sorted, expected);
        let (e1, p1, _, b1, be1, m1) = counters();
        let _ = (e0, e1);
        assert_eq!(p1 - p0, 130);
        assert_eq!(be1 - be0, 130);
        assert_eq!(b1 - b0, batches.len() as u64);
        assert!(m1 <= AUDIT_PERSIST_BATCH_MAX as u64);
    }

    #[tokio::test]
    async fn failed_batch_is_retried_whole_and_blocks_later_batches() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        let (sender, receiver) = mpsc::channel(16);
        let ledger = Arc::new(FakeLedger::new());
        // Fail the first two batch attempts: the first batch must be retried
        // intact and nothing behind it may overtake.
        ledger.fail_next_batch.store(2, AtomicOrdering::Relaxed);
        let worker = tokio::spawn(run_audit_persist_worker(receiver, ledger.clone()));
        let (e0, p0, _, _, _, _) = counters();
        let mut ids = Vec::new();
        for _ in 0..80 {
            let event = telemetry_event();
            ids.push(event.event_id);
            sender.send(event).await.unwrap();
        }
        drop(sender);
        tokio::time::timeout(Duration::from_secs(15), worker)
            .await
            .expect("worker must retry the failed batch then finish")
            .unwrap();
        let batches = ledger.batches.lock().unwrap();
        assert!(batches.len() >= 2, "80 events must span multiple batches");
        // In-order persistence: batch contents concat in enqueue order.
        let persisted: Vec<Uuid> = batches.iter().flatten().copied().collect();
        assert_eq!(persisted, ids);
        let (_, p1, _, _, _, _) = counters();
        assert_eq!(p1 - p0, 80, "persisted only counts successful batches");
        let _ = e0;
    }
}

#[test]
fn audit_event_definitions_pin_required_and_telemetry_classes() {
    for (name, _, class) in AUDIT_EVENT_DEFINITIONS {
        // Intents, decisions, mutations, replay detections, and lifecycle
        // changes are required evidence; starts and routine auth telemetry
        // are the only events allowed on the droppable path.
        let telemetry = matches!(
            *name,
            "authorization_approved"
                | "authorization_denied"
                | "authorization_prompt_none_approved"
                | "ciba_authorization_approved"
                | "ciba_authorization_denied"
                | "ciba_authorization_started"
                | "device_authorization_approved"
                | "device_authorization_denied"
                | "device_authorization_started"
                | "dynamic_client_configuration_read"
                | "federation_login_success"
                | "login_failure"
                | "login_success"
                | "mfa_challenge_failure"
                | "mfa_challenge_success"
                | "mfa_step_up_success"
                | "passkey_login_failure"
                | "passkey_login_success"
                | "scim_token_used"
        );
        assert_eq!(
            matches!(class, AuditEventClass::Telemetry),
            telemetry,
            "unexpected class for {name}"
        );
    }
    assert!(audit_event_is_required("token_issued"));
    assert!(!audit_event_is_required("login_success"));
    // Unknown names default to required: fail closed on taxonomy gaps.
    assert!(audit_event_is_required("unlisted_future_event"));
}

mod transactional_readiness {
    use super::*;
    use chrono::Utc;
    use futures_util::future::BoxFuture;
    use nazo_identity::ports::RepositoryError;
    use nazo_oauth_server::ports::audit::SecurityAudit;
    use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditLedger};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use crate::adapters::audit_anchor::{AuditAnchorPreflightConfig, config::AuditAnchorMode};

    /// Counts ledger calls so tests prove which repository probes a
    /// readiness mode performs instead of inferring them.
    struct CountingLedger {
        check_available_calls: AtomicU64,
        anchor_health_calls: AtomicU64,
        health: Mutex<SecurityAuditAnchorHealth>,
    }

    impl CountingLedger {
        fn new(health: SecurityAuditAnchorHealth) -> Self {
            Self {
                check_available_calls: AtomicU64::new(0),
                anchor_health_calls: AtomicU64::new(0),
                health: Mutex::new(health),
            }
        }

        fn calls(&self) -> (u64, u64) {
            (
                self.check_available_calls.load(AtomicOrdering::SeqCst),
                self.anchor_health_calls.load(AtomicOrdering::SeqCst),
            )
        }
    }

    impl SecurityAuditLedger for CountingLedger {
        fn check_available(
            &self,
            _require_least_privilege: bool,
        ) -> BoxFuture<'_, Result<(), RepositoryError>> {
            Box::pin(async move {
                self.check_available_calls
                    .fetch_add(1, AtomicOrdering::SeqCst);
                Ok(())
            })
        }

        fn anchor_health(
            &self,
        ) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
            Box::pin(async move {
                self.anchor_health_calls
                    .fetch_add(1, AtomicOrdering::SeqCst);
                Ok(self.health.lock().unwrap().clone())
            })
        }

        fn append(&self, _event: SecurityAuditEvent) -> BoxFuture<'_, Result<(), RepositoryError>> {
            Box::pin(async { Ok(()) })
        }

        fn append_batch<'a>(
            &'a self,
            _events: &'a [SecurityAuditEvent],
        ) -> BoxFuture<'a, Result<(), RepositoryError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn preflight(mode: AuditAnchorMode) -> AuditAnchorPreflight {
        AuditAnchorPreflight::new(AuditAnchorPreflightConfig {
            mode,
            deployment_id: "test-deployment".to_owned(),
            freshness: Duration::from_secs(30),
            max_lag: Duration::from_secs(30),
        })
        .expect("test anchor preflight config is valid")
    }

    fn healthy_anchor() -> SecurityAuditAnchorHealth {
        SecurityAuditAnchorHealth {
            head_sequence: 7,
            head_hash: vec![0xAA; 32],
            pending_exists: false,
            pending_estimate: 0,
            pending_orphan_exists: false,
            oldest_pending_occurred_at: None,
            last_exported_sequence: Some(7),
            last_exported_hash: Some(vec![0xAA; 32]),
            last_exported_occurred_at: Some(Utc::now()),
            last_exported_at: Some(Utc::now()),
            deployment_id: Some("test-deployment".to_owned()),
            observed_at: Some(Utc::now()),
            batch: None,
        }
    }

    fn required_repo(
        ledger: Arc<CountingLedger>,
        mode: AuditAnchorMode,
    ) -> RequiredAuditRepository {
        RequiredAuditRepository {
            repository: ledger,
            require_least_privilege: true,
            preflight: preflight(mode),
        }
    }

    #[tokio::test]
    async fn transactional_ready_skips_the_static_writer_probe_in_disabled_mode() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Disabled);
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect("disabled mode must be ready without touching the database");
        assert_eq!(ledger.calls(), (0, 0));
        // The generic gate is unchanged: it still performs the static probe.
        ensure_audit_storage_via(&required)
            .await
            .expect("generic ensure_storage still checks writer capability");
        assert_eq!(ledger.calls(), (1, 0));
    }

    #[tokio::test]
    async fn transactional_ready_skips_the_static_writer_probe_in_optional_mode() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Optional);
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect("optional mode must be ready without touching the database");
        assert_eq!(ledger.calls(), (0, 0));
        ensure_audit_storage_via(&required)
            .await
            .expect("generic ensure_storage still checks writer capability");
        assert_eq!(ledger.calls(), (1, 0));
    }

    #[tokio::test]
    async fn transactional_ready_keeps_the_dynamic_anchor_gate_in_required_mode() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect("fresh anchor health must pass");
        // Exactly the dynamic health probe; the static writer probe is elided.
        assert_eq!(ledger.calls(), (0, 1));
        // The same health status would also satisfy the generic path's anchor
        // gate after its static probe; both probes fire there.
        ensure_audit_storage_via(&required)
            .await
            .expect("generic path also passes with fresh health");
        assert_eq!(ledger.calls(), (1, 2));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_stale_anchor_health() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        ledger.health.lock().unwrap().observed_at =
            Some(Utc::now() - chrono::Duration::seconds(3600));
        let error = ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("stale anchor observation must reject issuance");
        assert!(
            error.to_string().contains("stale"),
            "unexpected error: {error}"
        );
        assert_eq!(ledger.calls(), (0, 1));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_anchor_identity_mismatch() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        ledger.health.lock().unwrap().deployment_id = Some("other-deployment".to_owned());
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("foreign deployment identity must reject issuance");
        assert_eq!(ledger.calls(), (0, 1));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_blocked_anchor_batch() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        ledger.health.lock().unwrap().batch = Some(nazo_persistence::SecurityAuditBatchLease {
            first_sequence: 1,
            last_sequence: 3,
            event_count: 3,
            generation: 1,
            attempts: 1,
            available_at: None,
            locked_until: None,
            last_error: None,
            blocked_reason: Some("receiver rejected event".to_owned()),
        });
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("a permanently blocked export batch must reject issuance");
        assert_eq!(ledger.calls(), (0, 1));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_anchor_checkpoint_mismatch() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        // Exported checkpoint disagrees with the ledger head.
        ledger.health.lock().unwrap().last_exported_hash = Some(vec![0xBB; 32]);
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("checkpoint/head mismatch must reject issuance");
        assert_eq!(ledger.calls(), (0, 1));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_excessive_pending_lag() {
        let ledger = Arc::new(CountingLedger::new(healthy_anchor()));
        let required = required_repo(ledger.clone(), AuditAnchorMode::Required);
        {
            let mut health = ledger.health.lock().unwrap();
            health.pending_exists = true;
            // Pending exists and checkpoint equals head: allowed shape, but
            // the oldest pending event exceeds the lag budget.
            health.oldest_pending_occurred_at = Some(Utc::now() - chrono::Duration::seconds(3600));
        }
        ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("pending lag beyond max_lag must reject issuance");
        assert_eq!(ledger.calls(), (0, 1));
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_on_anchor_health_unavailable() {
        struct FailingLedger;
        impl SecurityAuditLedger for FailingLedger {
            fn check_available(
                &self,
                _require_least_privilege: bool,
            ) -> BoxFuture<'_, Result<(), RepositoryError>> {
                Box::pin(async { Ok(()) })
            }
            fn anchor_health(
                &self,
            ) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
                Box::pin(async { Err(RepositoryError::Unavailable) })
            }
            fn append(
                &self,
                _event: SecurityAuditEvent,
            ) -> BoxFuture<'_, Result<(), RepositoryError>> {
                Box::pin(async { Ok(()) })
            }
            fn append_batch<'a>(
                &'a self,
                _events: &'a [SecurityAuditEvent],
            ) -> BoxFuture<'a, Result<(), RepositoryError>> {
                Box::pin(async { Ok(()) })
            }
        }
        let required = RequiredAuditRepository {
            repository: Arc::new(FailingLedger),
            require_least_privilege: true,
            preflight: preflight(AuditAnchorMode::Required),
        };
        let error = ensure_transactional_audit_ready_via(&required)
            .await
            .expect_err("anchor health read failure must reject issuance");
        assert!(
            error.to_string().contains("health unavailable"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn transactional_ready_fails_closed_without_a_durable_repository() {
        // The production entry point consults the process-global sink; when
        // bootstrap never installed it the call must fail rather than let a
        // commit probe reach a missing ledger.
        if REQUIRED_AUDIT_REPOSITORY.get().is_some() {
            // Another test already installed it in this process; the unwrap
            // branch is covered by startup ordering instead.
            return;
        }
        let error = ensure_transactional_audit_ready()
            .await
            .expect_err("missing durable repository must reject issuance");
        assert!(
            error.to_string().contains("not configured"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn port_default_transactional_ready_delegates_to_ensure_storage() {
        struct StrictAudit {
            calls: AtomicU64,
        }
        impl SecurityAudit for StrictAudit {
            fn ensure_storage(&self) -> AuditFuture<'_> {
                Box::pin(async move {
                    self.calls.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                })
            }
            fn record(&self, _event: &str, _fields: serde_json::Map<String, serde_json::Value>) {}
            fn record_required<'a>(
                &'a self,
                _event: &'a str,
                _fields: serde_json::Map<String, serde_json::Value>,
            ) -> AuditFuture<'a> {
                Box::pin(async { Ok(()) })
            }
        }
        let audit = StrictAudit {
            calls: AtomicU64::new(0),
        };
        // An adapter that does not override the new capability keeps the old
        // strict behavior through the default delegation.
        audit
            .ensure_transactional_ready()
            .await
            .expect("default delegates to ensure_storage");
        assert_eq!(audit.calls.load(AtomicOrdering::SeqCst), 1);
    }
}
