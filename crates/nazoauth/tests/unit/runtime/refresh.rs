use super::*;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId,
};
use nazo_persistence::TenantDirectoryStore;
use uuid::Uuid;

use nazo_oauth_server::ports::transient_state::{
    TenantDirectoryCachePort, TransientStateError, TransientStateFuture,
};

impl TenantRuntime {
    fn for_test(binding: TenantDirectoryBinding) -> Arc<Self> {
        super::super::test_support::runtime(binding)
    }
}

fn binding(id: u128, host: &str, issuer: &str) -> TenantDirectoryBinding {
    TenantDirectoryBinding {
        tenant: TenantContext {
            tenant_id: TenantId::new(Uuid::from_u128(id)).expect("tenant id is non-nil"),
            realm_id: RealmId::new(Uuid::from_u128(id + 0x100)).expect("realm id is non-nil"),
            organization_id: OrganizationId::new(Uuid::from_u128(id + 0x200))
                .expect("organization id is non-nil"),
        },
        runtime_revision: 1,
        issuer: issuer.to_owned(),
        external_host: host.to_owned(),
    }
}

fn snapshot(revision: u64, tenants: Vec<TenantDirectoryBinding>) -> TenantDirectorySnapshot {
    TenantDirectorySnapshot { revision, tenants }
}

#[derive(Clone)]
enum CacheReply {
    Snapshot(TenantDirectorySnapshot),
    Miss,
    Error(TransientStateError),
}

struct RecordingCache {
    replies: Mutex<VecDeque<CacheReply>>,
    loads: AtomicUsize,
    stores: Mutex<Vec<TenantDirectorySnapshot>>,
    store_error: Mutex<Option<TransientStateError>>,
}

impl RecordingCache {
    fn new(replies: impl IntoIterator<Item = CacheReply>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            loads: AtomicUsize::new(0),
            stores: Mutex::new(Vec::new()),
            store_error: Mutex::new(None),
        }
    }

    fn load_count(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }

    fn stored(&self) -> Vec<TenantDirectorySnapshot> {
        self.stores.lock().expect("cache stores lock").clone()
    }
}

impl TenantDirectoryCachePort for RecordingCache {
    fn load(&self) -> TransientStateFuture<'_, Option<Arc<TenantDirectorySnapshot>>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .replies
            .lock()
            .expect("cache replies lock")
            .pop_front()
            .unwrap_or(CacheReply::Miss);
        Box::pin(async move {
            match reply {
                CacheReply::Snapshot(snapshot) => Ok(Some(Arc::new(snapshot))),
                CacheReply::Miss => Ok(None),
                CacheReply::Error(error) => Err(error),
            }
        })
    }

    fn publish_authoritative<'a>(
        &'a self,
        snapshot: &'a TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        self.stores
            .lock()
            .expect("cache stores lock")
            .push(snapshot.clone());
        let error = *self.store_error.lock().expect("cache store error lock");
        Box::pin(async move { error.map_or(Ok(true), Err) })
    }
}

struct RecordingDirectory {
    revision: Mutex<u64>,
    snapshots:
        Mutex<VecDeque<Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>>>,
    revision_reads: AtomicUsize,
    snapshot_reads: AtomicUsize,
}

impl RecordingDirectory {
    fn new(revision: u64, snapshots: impl IntoIterator<Item = TenantDirectorySnapshot>) -> Self {
        Self {
            revision: Mutex::new(revision),
            snapshots: Mutex::new(snapshots.into_iter().map(Ok).collect()),
            revision_reads: AtomicUsize::new(0),
            snapshot_reads: AtomicUsize::new(0),
        }
    }

    fn revision_read_count(&self) -> usize {
        self.revision_reads.load(Ordering::SeqCst)
    }

    fn snapshot_read_count(&self) -> usize {
        self.snapshot_reads.load(Ordering::SeqCst)
    }

    fn set_revision(&self, revision: u64) {
        *self.revision.lock().expect("directory revision lock") = revision;
    }

    fn push_snapshot(&self, snapshot: TenantDirectorySnapshot) {
        self.snapshots
            .lock()
            .expect("directory snapshots lock")
            .push_back(Ok(snapshot));
    }
}

impl TenantDirectoryStore for RecordingDirectory {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>>
    {
        self.revision_reads.fetch_add(1, Ordering::SeqCst);
        let revision = *self.revision.lock().expect("directory revision lock");
        Box::pin(async move { Ok(revision) })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>,
    > {
        self.snapshot_reads.fetch_add(1, Ordering::SeqCst);
        let result = self
            .snapshots
            .lock()
            .expect("directory snapshots lock")
            .pop_front()
            .unwrap_or_else(|| {
                Err(nazo_identity::ports::RepositoryError::Unexpected(
                    "unscripted directory read".to_owned(),
                ))
            });
        Box::pin(async move { result })
    }

    fn find_active_binding(
        &self,
        _: nazo_identity::TenantId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<TenantDirectoryBinding>, nazo_identity::ports::RepositoryError>,
    > {
        panic!("runtime refresh must use the coherent complete directory")
    }
}

struct RecordingBuilder {
    builds: AtomicUsize,
    failing_host: Mutex<Option<String>>,
}

impl RecordingBuilder {
    fn new() -> Self {
        Self {
            builds: AtomicUsize::new(0),
            failing_host: Mutex::new(None),
        }
    }

    fn build_count(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }

    fn fail_for(&self, host: &str) {
        *self.failing_host.lock().expect("builder failure lock") = Some(host.to_owned());
    }
}

impl TenantRuntimeBuildPort for RecordingBuilder {
    fn build(&self, binding: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        let binding = binding.clone();
        let should_fail = self
            .failing_host
            .lock()
            .expect("builder failure lock")
            .as_deref()
            == Some(binding.external_host.as_str());
        Box::pin(async move {
            if should_fail {
                anyhow::bail!("scripted build failure for {}", binding.external_host);
            }
            Ok(TenantRuntime::for_test(binding))
        })
    }
}

struct Fixture {
    registry: TenantRuntimeRegistry,
    cache: Arc<RecordingCache>,
    directory: Arc<RecordingDirectory>,
    builder: Arc<RecordingBuilder>,
    refresher: TenantRuntimeRefresher,
}

impl Fixture {
    async fn new(
        initial: TenantDirectorySnapshot,
        cache_replies: impl IntoIterator<Item = CacheReply>,
        directory_revision: u64,
        directory_snapshots: impl IntoIterator<Item = TenantDirectorySnapshot>,
    ) -> Self {
        let registry = TenantRuntimeRegistry::empty();
        let cache = Arc::new(RecordingCache::new(cache_replies));
        let directory = Arc::new(RecordingDirectory::new(
            directory_revision,
            directory_snapshots,
        ));
        let builder = Arc::new(RecordingBuilder::new());
        let refresher = TenantRuntimeRefresher::new(
            registry.clone(),
            directory.clone(),
            cache.clone(),
            builder.clone(),
        );
        let expected_revision = initial.revision;
        assert_eq!(
            refresher
                .install_initial(initial)
                .await
                .expect("initial tenant snapshot installs"),
            TenantDirectoryRefreshOutcome::Applied {
                revision: expected_revision
            }
        );
        Self {
            registry,
            cache,
            directory,
            builder,
            refresher,
        }
    }
}

#[test]
fn request_snapshot_hits_never_touch_cache_or_database() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let fixture = Fixture::new(snapshot(1, vec![tenant_a]), [], 1, []).await;
        let cache_stores_before = fixture.cache.stored().len();

        let first = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A is locally routable");
        let second = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A remains locally routable");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("unknown.example")
                .cloned()
                .is_none()
        );

        assert_eq!(fixture.cache.load_count(), 0);
        assert_eq!(fixture.cache.stored().len(), cache_stores_before);
        assert_eq!(fixture.directory.revision_read_count(), 0);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
    });
}

#[test]
fn old_and_equal_cached_revisions_are_rejected_without_database_or_builds() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a.clone()]),
            [
                CacheReply::Snapshot(snapshot(0, vec![tenant_b.clone()])),
                CacheReply::Snapshot(snapshot(1, vec![changed_a, tenant_b])),
            ],
            1,
            [],
        )
        .await;
        let original = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A was installed");

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("old cache snapshot is handled"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("equal cache snapshot is handled"),
            TenantDirectoryRefreshOutcome::Unchanged
        );

        assert_eq!(fixture.registry.revision(), 1);
        assert!(Arc::ptr_eq(
            &original,
            &fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("last-good tenant A remains")
        ));
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_none()
        );
        assert_eq!(fixture.builder.build_count(), 1);
        assert_eq!(fixture.cache.load_count(), 2);
        assert_eq!(fixture.directory.revision_read_count(), 0);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
    });
}

#[test]
fn newer_cached_hint_is_confirmed_by_database_before_publication() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a]),
            [CacheReply::Snapshot(snapshot(
                2,
                vec![changed_a.clone(), tenant_b.clone()],
            ))],
            2,
            [snapshot(2, vec![changed_a.clone(), tenant_b])],
        )
        .await;

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("new cache snapshot applies"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );

        assert_eq!(fixture.registry.revision(), 2);
        assert_eq!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("updated tenant A is routable")
                .binding,
            changed_a
        );
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_some()
        );
        assert_eq!(fixture.cache.load_count(), 1);
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
    });
}

#[test]
fn tenant_runtime_revision_rebuilds_only_the_changed_tenant() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let mut reloaded_a = tenant_a.clone();
        reloaded_a.runtime_revision = 2;
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a, tenant_b]),
            [CacheReply::Snapshot(snapshot(
                2,
                vec![
                    reloaded_a.clone(),
                    binding(2, "tenant-b.example", "https://tenant-b.example"),
                ],
            ))],
            2,
            [snapshot(
                2,
                vec![
                    reloaded_a.clone(),
                    binding(2, "tenant-b.example", "https://tenant-b.example"),
                ],
            )],
        )
        .await;
        let previous_a = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .unwrap();
        let previous_b = fixture
            .registry
            .load()
            .by_host
            .get("tenant-b.example")
            .cloned()
            .unwrap();

        assert_eq!(
            fixture.refresher.refresh_cache_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );

        let current_a = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .unwrap();
        let current_b = fixture
            .registry
            .load()
            .by_host
            .get("tenant-b.example")
            .cloned()
            .unwrap();
        assert!(!Arc::ptr_eq(&previous_a, &current_a));
        assert!(Arc::ptr_eq(&previous_b, &current_b));
        assert_eq!(current_a.binding, reloaded_a);
        assert_eq!(fixture.builder.build_count(), 3);
    });
}

#[test]
fn database_payload_is_used_instead_of_same_revision_cache_payload() {
    futures_executor::block_on(async {
        let initial_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let cached_a = binding(1, "tenant-a.example", "https://tenant-a.example/cache");
        let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example/database");
        let authoritative = snapshot(2, vec![authoritative_a.clone()]);
        let fixture = Fixture::new(
            snapshot(1, vec![initial_a]),
            [CacheReply::Snapshot(snapshot(2, vec![cached_a.clone()]))],
            2,
            [authoritative.clone()],
        )
        .await;

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("cache revision two applies first"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );
        let cache_runtime = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("cached tenant A is routable");
        assert_eq!(cache_runtime.binding, authoritative_a);

        assert_eq!(
            fixture
                .refresher
                .reconcile_database_once()
                .await
                .expect("confirmed revision stays unchanged"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        let authoritative_runtime = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("authoritative tenant A is routable");
        assert_eq!(authoritative_runtime.binding, authoritative_a);
        assert!(Arc::ptr_eq(&cache_runtime, &authoritative_runtime));
        assert_eq!(fixture.directory.revision_read_count(), 2);
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
        assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
    });
}

#[test]
fn cache_ahead_of_database_never_routes_and_rejects_repeated_revision() {
    futures_executor::block_on(async {
        let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let cached_a = binding(1, "tenant-a.example", "https://tenant-a.example/cache");
        let cached_revision = snapshot(3, vec![cached_a.clone()]);
        let authoritative = snapshot(1, vec![authoritative_a.clone()]);
        let fixture = Fixture::new(
            authoritative.clone(),
            [
                CacheReply::Snapshot(cached_revision.clone()),
                CacheReply::Snapshot(cached_revision),
            ],
            1,
            [authoritative.clone()],
        )
        .await;

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("cache-ahead revision is rejected"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("cached tenant A is routable")
                .binding,
            authoritative_a
        );

        assert_eq!(
            fixture
                .refresher
                .reconcile_database_once()
                .await
                .expect("database remains authoritative"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.registry.revision(), 1);
        assert_eq!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("authoritative tenant A is restored")
                .binding,
            authoritative_a
        );
        assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
        let builds_after_rollback = fixture.builder.build_count();

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("rejected cache revision is ignored"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.registry.revision(), 1);
        assert_eq!(fixture.builder.build_count(), builds_after_rollback);
        assert_eq!(fixture.cache.load_count(), 2);
        assert_eq!(fixture.directory.revision_read_count(), 2);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
    });
}

async fn assert_cache_failure_falls_back_to_database(cache_reply: CacheReply) {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let authoritative = snapshot(2, vec![tenant_a.clone(), tenant_b]);
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a]),
        [cache_reply],
        2,
        [authoritative.clone()],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("database fallback applies"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    assert_eq!(fixture.registry.revision(), 2);
    assert!(
        fixture
            .registry
            .load()
            .by_host
            .get("tenant-b.example")
            .cloned()
            .is_some()
    );
    assert_eq!(fixture.cache.load_count(), 1);
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
    assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
}

#[test]
fn cache_miss_falls_back_to_database_and_repairs_cache() {
    futures_executor::block_on(async {
        assert_cache_failure_falls_back_to_database(CacheReply::Miss).await;
    });
}

#[test]
fn corrupt_cache_falls_back_to_database_and_repairs_cache() {
    futures_executor::block_on(async {
        assert_cache_failure_falls_back_to_database(CacheReply::Error(
            TransientStateError::CorruptData,
        ))
        .await;
    });
}

#[test]
fn invalid_cache_snapshot_repairs_from_database_and_quarantines_revision() {
    futures_executor::block_on(async {
        let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let invalid_a = binding(1, "Tenant-A.example", "https://tenant-a.example");
        let invalid_revision = snapshot(2, vec![invalid_a]);
        let authoritative = snapshot(1, vec![authoritative_a.clone()]);
        let fixture = Fixture::new(
            authoritative.clone(),
            [
                CacheReply::Snapshot(invalid_revision.clone()),
                CacheReply::Snapshot(invalid_revision),
            ],
            1,
            [authoritative.clone()],
        )
        .await;

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("invalid cache snapshot falls back to database"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.registry.revision(), 1);
        assert_eq!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("authoritative tenant A remains routable")
                .binding,
            authoritative_a
        );
        assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
        let builds_after_repair = fixture.builder.build_count();

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("quarantined cache revision is ignored"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.registry.revision(), 1);
        assert_eq!(fixture.builder.build_count(), builds_after_repair);
        assert_eq!(fixture.cache.load_count(), 2);
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
    });
}

#[test]
fn database_reconciliation_reads_snapshot_only_for_newer_revision() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let fixture = Fixture::new(snapshot(1, vec![tenant_a.clone()]), [], 1, []).await;

        assert_eq!(
            fixture
                .refresher
                .reconcile_database_once()
                .await
                .expect("equal database revision is handled"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);

        fixture.directory.set_revision(2);
        fixture
            .directory
            .push_snapshot(snapshot(2, vec![tenant_a, tenant_b]));
        assert_eq!(
            fixture
                .refresher
                .reconcile_database_once()
                .await
                .expect("new database revision applies"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );
        assert_eq!(fixture.directory.revision_read_count(), 2);
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
        assert_eq!(fixture.registry.revision(), 2);
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_some()
        );
        assert_eq!(
            fixture
                .cache
                .stored()
                .last()
                .expect("new authoritative snapshot is cached")
                .revision,
            2
        );
    });
}

#[test]
fn candidate_build_failure_retains_last_good_snapshot() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a.clone()]),
            [CacheReply::Snapshot(snapshot(
                2,
                vec![tenant_a.clone(), tenant_b.clone()],
            ))],
            2,
            [snapshot(2, vec![tenant_a, tenant_b])],
        )
        .await;
        let original = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A was installed");
        fixture.builder.fail_for("tenant-b.example");

        let error = fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect_err("scripted candidate build must fail");
        assert!(error.to_string().contains("scripted build failure"));

        assert_eq!(fixture.registry.revision(), 1);
        assert!(Arc::ptr_eq(
            &original,
            &fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .expect("last-good tenant A remains")
        ));
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_none()
        );
        assert_eq!(fixture.builder.build_count(), 2);
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
    });
}

#[test]
fn revoked_routes_leave_before_unrelated_candidate_builds_and_retry_same_revision() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let next = snapshot(2, vec![tenant_b]);
        let fixture = Fixture::new(snapshot(1, vec![tenant_a]), [], 1, []).await;
        fixture.builder.fail_for("tenant-b.example");
        for _ in 0..2 {
            assert!(fixture.refresher.apply_snapshot(&next).await.is_err());
            assert!(fixture.registry.load().by_host.is_empty());
            assert_eq!(fixture.registry.revision(), 1);
        }
        *fixture.builder.failing_host.lock().unwrap() = None;
        fixture.refresher.apply_snapshot(&next).await.unwrap();
        assert_eq!(fixture.registry.revision(), 2);
        assert!(
            fixture
                .registry
                .load()
                .by_host
                .contains_key("tenant-b.example")
        );
        assert!(
            !fixture
                .registry
                .load()
                .by_host
                .contains_key("tenant-a.example")
        );
    });
}

#[test]
fn failed_identity_replacement_retires_old_route_but_runtime_only_change_retains_it() {
    futures_executor::block_on(async {
        for identity_changes in [false, true] {
            let tenant = binding(1, "tenant-a.example", "https://tenant-a.example");
            let mut next = tenant.clone();
            next.runtime_revision += 1;
            if identity_changes {
                next.issuer = "https://tenant-a.example/replacement".to_owned();
            }
            let fixture = Fixture::new(snapshot(1, vec![tenant]), [], 1, []).await;
            fixture.builder.fail_for("tenant-a.example");
            assert!(
                fixture
                    .refresher
                    .apply_snapshot(&snapshot(2, vec![next]))
                    .await
                    .is_err()
            );
            assert_eq!(
                fixture
                    .registry
                    .load()
                    .by_host
                    .contains_key("tenant-a.example"),
                !identity_changes
            );
        }
    });
}

#[test]
fn in_flight_request_arc_keeps_old_runtime_after_atomic_update() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a.clone()]),
            [CacheReply::Snapshot(snapshot(2, vec![changed_a.clone()]))],
            2,
            [snapshot(2, vec![changed_a.clone()])],
        )
        .await;
        let in_flight = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A was installed");

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("updated tenant A applies"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );
        let next_request = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("updated tenant A is routable");

        assert!(!Arc::ptr_eq(&in_flight, &next_request));
        assert_eq!(in_flight.binding, tenant_a);
        assert_eq!(next_request.binding, changed_a);
    });
}

#[test]
fn disable_removes_tenant_only_from_new_requests() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a.clone(), tenant_b.clone()]),
            [CacheReply::Snapshot(snapshot(2, vec![tenant_b.clone()]))],
            2,
            [snapshot(2, vec![tenant_b])],
        )
        .await;
        let in_flight_a = fixture
            .registry
            .load()
            .by_host
            .get("tenant-a.example")
            .cloned()
            .expect("tenant A was installed");
        let original_b = fixture
            .registry
            .load()
            .by_host
            .get("tenant-b.example")
            .cloned()
            .expect("tenant B was installed");

        assert_eq!(
            fixture
                .refresher
                .refresh_cache_once()
                .await
                .expect("disabled tenant is removed"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );

        assert!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .is_none()
        );
        assert_eq!(in_flight_a.binding, tenant_a);
        assert!(Arc::ptr_eq(
            &original_b,
            &fixture
                .registry
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .expect("unchanged tenant B keeps its runtime")
        ));
    });
}

#[test]
fn two_instances_converge_on_new_cache_revision_and_reject_stale_replay() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let revision_two = snapshot(2, vec![tenant_a.clone(), tenant_b]);
        let shared_cache = Arc::new(RecordingCache::new([
            CacheReply::Snapshot(revision_two.clone()),
            CacheReply::Snapshot(revision_two.clone()),
            CacheReply::Snapshot(snapshot(1, vec![tenant_a.clone()])),
            CacheReply::Snapshot(snapshot(1, vec![tenant_a.clone()])),
        ]));
        let shared_directory = Arc::new(RecordingDirectory::new(
            2,
            [revision_two.clone(), revision_two],
        ));

        let registry_one = TenantRuntimeRegistry::empty();
        let builder_one = Arc::new(RecordingBuilder::new());
        let refresher_one = TenantRuntimeRefresher::new(
            registry_one.clone(),
            shared_directory.clone(),
            shared_cache.clone(),
            builder_one,
        );
        refresher_one
            .install_initial(snapshot(1, vec![tenant_a.clone()]))
            .await
            .expect("instance one installs revision one");

        let registry_two = TenantRuntimeRegistry::empty();
        let builder_two = Arc::new(RecordingBuilder::new());
        let refresher_two = TenantRuntimeRefresher::new(
            registry_two.clone(),
            shared_directory.clone(),
            shared_cache.clone(),
            builder_two,
        );
        refresher_two
            .install_initial(snapshot(1, vec![tenant_a]))
            .await
            .expect("instance two installs revision one");

        assert_eq!(
            refresher_one
                .refresh_cache_once()
                .await
                .expect("instance one reads revision two"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );
        assert_eq!(
            refresher_two
                .refresh_cache_once()
                .await
                .expect("instance two reads revision two"),
            TenantDirectoryRefreshOutcome::Applied { revision: 2 }
        );
        assert_eq!(registry_one.revision(), 2);
        assert_eq!(registry_two.revision(), 2);
        assert!(
            registry_one
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_some()
        );
        assert!(
            registry_two
                .load()
                .by_host
                .get("tenant-b.example")
                .cloned()
                .is_some()
        );

        assert_eq!(
            refresher_one
                .refresh_cache_once()
                .await
                .expect("instance one rejects stale replay"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(
            refresher_two
                .refresh_cache_once()
                .await
                .expect("instance two rejects stale replay"),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(shared_directory.revision_read_count(), 2);
        assert_eq!(shared_directory.snapshot_read_count(), 2);
    });
}

#[test]
fn repeated_cache_failure_repairs_confirmed_snapshot_without_full_database_reads() {
    futures_executor::block_on(async {
        let authoritative = snapshot(
            1,
            vec![binding(1, "tenant-a.example", "https://tenant-a.example")],
        );
        let fixture = Fixture::new(
            authoritative.clone(),
            [
                CacheReply::Miss,
                CacheReply::Error(TransientStateError::CorruptData),
                CacheReply::Error(TransientStateError::Unavailable),
            ],
            1,
            [],
        )
        .await;
        *fixture.cache.store_error.lock().unwrap() = Some(TransientStateError::Unavailable);
        for _ in 0..3 {
            assert_eq!(
                fixture.refresher.refresh_cache_once().await.unwrap(),
                TenantDirectoryRefreshOutcome::Unchanged
            );
        }
        assert_eq!(fixture.directory.revision_read_count(), 3);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
        assert_eq!(fixture.builder.build_count(), 1);
        assert_eq!(fixture.cache.stored(), vec![authoritative; 4]);
    });
}

#[test]
fn cache_failure_does_not_republish_unconfirmed_cache_payload() {
    futures_executor::block_on(async {
        let authoritative = snapshot(
            2,
            vec![binding(
                1,
                "tenant-a.example",
                "https://tenant-a.example/authoritative",
            )],
        );
        let fixture = Fixture::new(
            snapshot(
                1,
                vec![binding(1, "tenant-a.example", "https://tenant-a.example")],
            ),
            [
                CacheReply::Snapshot(snapshot(
                    2,
                    vec![binding(
                        1,
                        "tenant-a.example",
                        "https://tenant-a.example/cache",
                    )],
                )),
                CacheReply::Miss,
            ],
            2,
            [authoritative.clone()],
        )
        .await;
        fixture.refresher.refresh_cache_once().await.unwrap();
        fixture.refresher.refresh_cache_once().await.unwrap();
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
        assert_eq!(
            &fixture.cache.stored()[1..],
            &[authoritative.clone(), authoritative.clone()]
        );
        assert_eq!(
            fixture
                .registry
                .load()
                .by_host
                .get("tenant-a.example")
                .cloned()
                .unwrap()
                .binding,
            authoritative.tenants[0]
        );
    });
}

#[test]
fn database_snapshot_may_advance_past_precheck_without_a_second_full_read() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let newer = snapshot(3, vec![tenant_a.clone(), tenant_b]);
        let fixture = Fixture::new(snapshot(1, vec![tenant_a]), [], 2, [newer.clone()]).await;
        assert_eq!(
            fixture.refresher.reconcile_database_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Applied { revision: 3 }
        );
        assert_eq!(fixture.registry.revision(), 3);
        assert_eq!(fixture.registry.load().by_host.len(), 2);
        assert_eq!(fixture.directory.revision_read_count(), 1);
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
        assert_eq!(fixture.cache.stored().last(), Some(&newer));
        fixture.directory.set_revision(3);
        assert_eq!(
            fixture.refresher.reconcile_database_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
    });
}

#[test]
fn database_snapshot_older_than_precheck_keeps_last_good_and_cache() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let fixture = Fixture::new(
            snapshot(1, vec![tenant_a.clone()]),
            [],
            3,
            [snapshot(2, vec![tenant_a])],
        )
        .await;
        let stores = fixture.cache.stored().len();
        assert!(fixture.refresher.reconcile_database_once().await.is_err());
        assert_eq!(fixture.registry.revision(), 1);
        assert_eq!(fixture.builder.build_count(), 1);
        assert_eq!(fixture.cache.stored().len(), stores);
        assert_eq!(
            fixture
                .refresher
                .state
                .lock()
                .await
                .last_database_snapshot
                .as_ref()
                .unwrap()
                .revision,
            1
        );
    });
}

#[test]
fn newer_database_snapshot_uses_its_own_revision_to_reject_cache_ahead() {
    futures_executor::block_on(async {
        let initial = binding(1, "tenant-a.example", "https://tenant-a.example");
        let cached = binding(1, "tenant-a.example", "https://tenant-a.example/cache");
        let confirmed = snapshot(3, vec![initial.clone()]);
        let ahead = snapshot(4, vec![cached]);
        let fixture = Fixture::new(
            snapshot(1, vec![initial]),
            [
                CacheReply::Snapshot(ahead.clone()),
                CacheReply::Snapshot(ahead),
            ],
            2,
            [confirmed.clone()],
        )
        .await;
        assert_eq!(
            fixture.refresher.refresh_cache_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Applied { revision: 3 }
        );
        fixture.directory.set_revision(3);
        assert_eq!(
            fixture.refresher.reconcile_database_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.registry.revision(), 3);
        assert_eq!(
            fixture.refresher.state.lock().await.rejected_cache_revision,
            Some(4)
        );
        assert_eq!(fixture.cache.stored().last(), Some(&confirmed));
        assert_eq!(
            fixture.refresher.refresh_cache_once().await.unwrap(),
            TenantDirectoryRefreshOutcome::Unchanged
        );
        assert_eq!(fixture.directory.snapshot_read_count(), 1);
        fixture.directory.set_revision(4);
        fixture
            .directory
            .push_snapshot(snapshot(4, confirmed.tenants));
        fixture.refresher.reconcile_database_once().await.unwrap();
        assert_eq!(
            fixture.refresher.state.lock().await.rejected_cache_revision,
            None
        );
    });
}

#[test]
fn security_cloud_increasing_forged_cache_revisions_cannot_swap_or_remove_tenants() {
    futures_executor::block_on(async {
        let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
        let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
        let authoritative = snapshot(1, vec![tenant_a.clone(), tenant_b.clone()]);
        let fixture = Fixture::new(
            authoritative.clone(),
            [
                CacheReply::Snapshot(snapshot(100, vec![])),
                CacheReply::Snapshot(snapshot(
                    101,
                    vec![binding(1, "tenant-b.example", "https://tenant-b.example")],
                )),
                CacheReply::Snapshot(snapshot(
                    102,
                    vec![binding(2, "tenant-a.example", "https://tenant-a.example")],
                )),
            ],
            1,
            [],
        )
        .await;
        for _ in 0..3 {
            assert_eq!(
                fixture.refresher.refresh_cache_once().await.unwrap(),
                TenantDirectoryRefreshOutcome::Unchanged
            );
            assert_eq!(fixture.registry.revision(), 1);
            let current = fixture.registry.load();
            assert_eq!(current.by_host["tenant-a.example"].binding, tenant_a);
            assert_eq!(current.by_host["tenant-b.example"].binding, tenant_b);
        }
        assert_eq!(fixture.builder.build_count(), 2);
        assert_eq!(fixture.directory.snapshot_read_count(), 0);
        assert_eq!(fixture.cache.stored(), vec![authoritative; 4]);
    });
}

#[derive(Default)]
struct RecordingLifecycle {
    starts: AtomicUsize,
    stops: AtomicUsize,
    fail_start: bool,
    pending_stop: bool,
}

impl TenantLifecycle for RecordingLifecycle {
    fn start(&self) -> anyhow::Result<()> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(!self.fail_start, "injected lifecycle start failure");
        Ok(())
    }

    fn stop(&self) -> BoxFuture<'_, ()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.pending_stop {
                std::future::pending::<()>().await;
            }
        })
    }
}

fn runtime_with_tasks(id: u128, host: &str, tasks: Arc<RecordingLifecycle>) -> Arc<TenantRuntime> {
    super::super::test_support::runtime_with_lifecycle(
        binding(id, host, &format!("https://{host}")),
        tasks,
    )
}

#[test]
fn publication_signals_only_displaced_lifecycles_and_shutdown_closes_all_routes() {
    futures_executor::block_on(async {
        let fixture = Fixture::new(snapshot(1, vec![]), [], 1, []).await;
        let kept = Arc::new(RecordingLifecycle::default());
        let replaced = Arc::new(RecordingLifecycle::default());
        let removed = Arc::new(RecordingLifecycle::default());
        let first = runtime_with_tasks(1, "a.example", kept.clone());
        let second = runtime_with_tasks(2, "b.example", replaced.clone());
        let third = runtime_with_tasks(3, "c.example", removed.clone());
        fixture
            .refresher
            .publish_candidate(
                2,
                HashMap::from([
                    ("a.example".to_owned(), first.clone()),
                    ("b.example".to_owned(), second.clone()),
                    ("c.example".to_owned(), third.clone()),
                ]),
                vec![first.clone(), second.clone(), third],
            )
            .await
            .unwrap();
        let new_tasks = Arc::new(RecordingLifecycle::default());
        let replacement = runtime_with_tasks(2, "b.example", new_tasks.clone());
        fixture
            .refresher
            .publish_candidate(
                3,
                HashMap::from([
                    ("a.example".to_owned(), first),
                    ("b.example".to_owned(), replacement.clone()),
                ]),
                vec![replacement],
            )
            .await
            .unwrap();
        assert_eq!(kept.stops.load(Ordering::SeqCst), 0);
        assert_eq!(replaced.stops.load(Ordering::SeqCst), 1);
        assert_eq!(removed.stops.load(Ordering::SeqCst), 1);
        assert_eq!(new_tasks.starts.load(Ordering::SeqCst), 1);
        fixture.refresher.shutdown().await;
        assert_eq!(kept.stops.load(Ordering::SeqCst), 1);
        assert_eq!(new_tasks.stops.load(Ordering::SeqCst), 1);
        assert!(fixture.registry.load().by_host.is_empty());
        assert!(
            fixture
                .refresher
                .apply_snapshot(&snapshot(4, vec![]))
                .await
                .is_err()
        );
    });
}

#[test]
fn failed_candidate_start_signals_every_started_lifecycle_before_waiting() {
    futures_executor::block_on(async {
        let fixture = Fixture::new(snapshot(1, vec![]), [], 1, []).await;
        let first_tasks = Arc::new(RecordingLifecycle {
            pending_stop: true,
            ..Default::default()
        });
        let failing_tasks = Arc::new(RecordingLifecycle {
            fail_start: true,
            ..Default::default()
        });
        let first = runtime_with_tasks(1, "a.example", first_tasks.clone());
        let failing = runtime_with_tasks(2, "b.example", failing_tasks.clone());
        let mut publication = Box::pin(fixture.refresher.publish_candidate(
            2,
            HashMap::from([
                ("a.example".to_owned(), first.clone()),
                ("b.example".to_owned(), failing.clone()),
            ]),
            vec![first, failing],
        ));
        assert!(futures_util::poll!(&mut publication).is_pending());
        assert_eq!(first_tasks.stops.load(Ordering::SeqCst), 1);
        assert_eq!(failing_tasks.stops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.registry.revision(), 1);
        drop(publication);
    });
}

#[test]
fn cancelled_shutdown_has_already_withdrawn_routes_and_signalled_all_lifecycles() {
    futures_executor::block_on(async {
        let fixture = Fixture::new(snapshot(1, vec![]), [], 1, []).await;
        let first_tasks = Arc::new(RecordingLifecycle {
            pending_stop: true,
            ..Default::default()
        });
        let second_tasks = Arc::new(RecordingLifecycle {
            pending_stop: true,
            ..Default::default()
        });
        let first = runtime_with_tasks(1, "a.example", first_tasks.clone());
        let second = runtime_with_tasks(2, "b.example", second_tasks.clone());
        fixture
            .refresher
            .publish_candidate(
                2,
                HashMap::from([
                    ("a.example".to_owned(), first.clone()),
                    ("b.example".to_owned(), second.clone()),
                ]),
                vec![first, second],
            )
            .await
            .unwrap();
        let mut shutdown = Box::pin(fixture.refresher.shutdown());
        assert!(futures_util::poll!(&mut shutdown).is_pending());
        assert!(fixture.registry.load().by_host.is_empty());
        assert_eq!(first_tasks.stops.load(Ordering::SeqCst), 1);
        assert_eq!(second_tasks.stops.load(Ordering::SeqCst), 1);
        drop(shutdown);
    });
}

#[test]
fn a_builder_cannot_publish_a_different_tenant_binding() {
    struct WrongBuilder;
    impl TenantRuntimeBuildPort for WrongBuilder {
        fn build(&self, _: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
            Box::pin(async {
                Ok(TenantRuntime::for_test(binding(
                    99,
                    "wrong.example",
                    "https://wrong.example",
                )))
            })
        }
    }
    futures_executor::block_on(async {
        let registry = TenantRuntimeRegistry::empty();
        let refresher = TenantRuntimeRefresher::new(
            registry.clone(),
            Arc::new(RecordingDirectory::new(1, [])),
            Arc::new(RecordingCache::new([])),
            Arc::new(WrongBuilder),
        );
        assert!(
            refresher
                .install_initial(snapshot(
                    1,
                    vec![binding(1, "a.example", "https://a.example")]
                ))
                .await
                .is_err()
        );
        assert!(registry.load().by_host.is_empty());
    });
}

#[test]
fn uninitialized_initial_directory_cannot_start() {
    futures_executor::block_on(async {
        let registry = TenantRuntimeRegistry::empty();
        let refresher = TenantRuntimeRefresher::new(
            registry.clone(),
            Arc::new(RecordingDirectory::new(0, [])),
            Arc::new(RecordingCache::new([])),
            Arc::new(RecordingBuilder::new()),
        );
        assert!(
            refresher
                .install_initial(snapshot(0, vec![]))
                .await
                .is_err()
        );
        assert_eq!(registry.revision(), 0);
    });
}

#[test]
fn directory_validation_rejects_ambiguous_or_inconsistent_authorities() {
    let valid = binding(1, "a.example", "https://a.example/auth");
    assert!(validate_snapshot(&snapshot(1, vec![valid.clone()])).is_ok());
    let mut invalid = valid.clone();
    invalid.runtime_revision = 0;
    assert!(validate_snapshot(&snapshot(1, vec![invalid])).is_err());
    let mut invalid = valid.clone();
    invalid.external_host = "A.Example.".to_owned();
    assert!(validate_snapshot(&snapshot(1, vec![invalid])).is_err());
    let mut invalid = valid.clone();
    invalid.issuer = "https://other.example/auth".to_owned();
    assert!(validate_snapshot(&snapshot(1, vec![invalid])).is_err());
    assert!(validate_snapshot(&snapshot(1, vec![valid.clone(), valid.clone()])).is_err());
    assert!(
        validate_snapshot(&snapshot(
            1,
            vec![valid.clone(), binding(1, "b.example", "https://b.example")]
        ))
        .is_err()
    );
    assert!(
        validate_snapshot(&snapshot(
            1,
            vec![
                valid,
                binding(2, "a.example", "https://a.example/different-prefix")
            ]
        ))
        .is_err()
    );
}

#[test]
fn closing_a_registry_rejects_an_already_started_candidate_and_signals_it() {
    futures_executor::block_on(async {
        let fixture = Fixture::new(snapshot(1, vec![]), [], 1, []).await;
        let tasks = Arc::new(RecordingLifecycle::default());
        let candidate = runtime_with_tasks(1, "a.example", tasks.clone());
        fixture.refresher.close();
        assert!(
            fixture
                .refresher
                .publish_candidate(
                    2,
                    HashMap::from([("a.example".to_owned(), candidate.clone())]),
                    vec![candidate]
                )
                .await
                .is_err()
        );
        assert_eq!(tasks.starts.load(Ordering::SeqCst), 1);
        assert_eq!(tasks.stops.load(Ordering::SeqCst), 1);
        assert!(fixture.registry.load().by_host.is_empty());
    });
}
