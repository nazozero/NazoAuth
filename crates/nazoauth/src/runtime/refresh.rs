//! Authoritative directory reconciliation and atomic tenant graph publication.
use super::*;

/// Observable result for one refresh attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantDirectoryRefreshOutcome {
    Applied { revision: u64 },
    Unchanged,
}

#[derive(Default)]
struct TenantDirectoryRefreshState {
    // The last authoritative payload is reused to repair a missing cache
    // when the database revision has not changed.
    last_database_snapshot: Option<Arc<TenantDirectorySnapshot>>,
    // A cache revision proven ahead of the authoritative store is ignored until the DB
    // catches up, rather than being re-applied every one-second cache tick.
    rejected_cache_revision: Option<u64>,
}

/// Coordinates cache and authoritative-directory refreshes. Its mutex is
/// control-plane-only and prevents concurrent builds/retirements.
pub struct TenantRuntimeRefresher {
    registry: TenantRuntimeRegistry,
    directory: Arc<dyn nazo_persistence::TenantDirectoryStore>,
    cache: Arc<dyn nazo_oauth_server::ports::transient_state::TenantDirectoryCachePort>,
    builder: Arc<dyn TenantRuntimeBuildPort>,
    state: futures_util::lock::Mutex<TenantDirectoryRefreshState>,
}

impl TenantRuntimeRefresher {
    pub fn new(
        registry: TenantRuntimeRegistry,
        directory: Arc<dyn nazo_persistence::TenantDirectoryStore>,
        cache: Arc<dyn nazo_oauth_server::ports::transient_state::TenantDirectoryCachePort>,
        builder: Arc<dyn TenantRuntimeBuildPort>,
    ) -> Self {
        Self {
            registry,
            directory,
            cache,
            builder,
            state: futures_util::lock::Mutex::new(TenantDirectoryRefreshState::default()),
        }
    }

    pub async fn install_initial(
        &self,
        snapshot: TenantDirectorySnapshot,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        anyhow::ensure!(
            snapshot.revision > 0,
            "tenant runtime directory is not initialized"
        );
        let mut state = self.state.lock().await;
        let snapshot = Arc::new(snapshot);
        let outcome = self.apply_snapshot(&snapshot).await?;
        state.last_database_snapshot = Some(snapshot.clone());
        if let Err(error) = self.cache.publish_authoritative(&snapshot).await {
            tracing::warn!(%error, "tenant directory initial cache publish failed; retaining authoritative local snapshot");
        }
        Ok(outcome)
    }

    /// High-frequency cache path. An equal/older hit never touches the authoritative store;
    /// a miss, corrupt value, or unavailable cache uses the DB reconciliation.
    pub async fn refresh_cache_once(&self) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let mut state = self.state.lock().await;
        let local_revision = self.registry.revision();
        match self.cache.load().await {
            Ok(Some(snapshot))
                if snapshot.revision > local_revision
                    && state.rejected_cache_revision != Some(snapshot.revision) =>
            {
                // The shared cache is an untrusted invalidation hint, never a routing
                // authority. Even a well-formed newer value must be confirmed
                // against the authoritative store before a tenant generation is visible.
                let candidate_revision = snapshot.revision;
                let outcome = self.reconcile_database_locked(&mut state, true).await?;
                if self.registry.revision() < candidate_revision {
                    state.rejected_cache_revision = Some(candidate_revision);
                }
                Ok(outcome)
            }
            Ok(Some(_)) => Ok(TenantDirectoryRefreshOutcome::Unchanged),
            Ok(None) | Err(_) => self.reconcile_database_locked(&mut state, true).await,
        }
    }

    /// Low-frequency authoritative reconciliation. It loads the full directory
    /// only after its compact revision fence proves a newer value exists.
    pub async fn reconcile_database_once(&self) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let mut state = self.state.lock().await;
        self.reconcile_database_locked(&mut state, false).await
    }

    /// Withdraw every route and prevent further publication. The returned
    /// snapshot retains the lifecycles for the owner to signal with `stop`.
    pub fn close(&self) -> Arc<TenantHostIndex> {
        self.registry.close()
    }

    /// Withdraw all routes, signal every tenant lifecycle and await completion.
    /// Stop scheduling refreshes and drain requests before calling this method.
    pub async fn shutdown(&self) {
        let previous = self.close();
        let completions = previous
            .by_host
            .values()
            .map(|runtime| runtime.stop())
            .collect::<Vec<_>>();
        for completion in completions {
            completion.await;
        }
        // A builder already in flight can finish, but publication is closed and
        // its candidate tasks are stopped before releasing the state lock.
        let _state = self.state.lock().await;
    }

    async fn reconcile_database_locked(
        &self,
        state: &mut TenantDirectoryRefreshState,
        repair_cache: bool,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let local_revision = self.registry.revision();
        let last_database_snapshot = state.last_database_snapshot.clone();
        let revision =
            self.directory.current_revision().await.map_err(|error| {
                anyhow::anyhow!("tenant directory revision read failed: {error}")
            })?;
        if let Some(snapshot) = last_database_snapshot
            && revision == snapshot.revision
            && revision == local_revision
        {
            // Only a database-confirmed payload may repair the cache.
            if repair_cache && let Err(error) = self.cache.publish_authoritative(&snapshot).await {
                tracing::warn!(%error, "tenant directory cache repair failed; retaining authoritative local snapshot");
            }
            return Ok(TenantDirectoryRefreshOutcome::Unchanged);
        }
        let snapshot = self
            .directory
            .load_active()
            .await
            .map_err(|error| anyhow::anyhow!("tenant directory read failed: {error}"))?;
        if snapshot.revision < revision {
            anyhow::bail!(
                "tenant directory snapshot precedes revision check (expected at least {revision}, got {})",
                snapshot.revision
            );
        }
        // The authoritative read owns one complete coherent snapshot. A commit
        // between the compact precheck and that read may advance its revision.
        let authoritative_revision = snapshot.revision;
        let cache_was_ahead = local_revision > authoritative_revision;
        let snapshot = Arc::new(snapshot);
        let outcome = self.apply_snapshot(&snapshot).await?;
        state.last_database_snapshot = Some(snapshot.clone());
        if cache_was_ahead {
            state.rejected_cache_revision = Some(local_revision);
        } else if state
            .rejected_cache_revision
            .is_some_and(|rejected| authoritative_revision >= rejected)
        {
            state.rejected_cache_revision = None;
        }
        if (repair_cache || matches!(outcome, TenantDirectoryRefreshOutcome::Applied { .. }))
            && let Err(error) = self.cache.publish_authoritative(&snapshot).await
        {
            tracing::warn!(%error, "tenant directory cache update failed after local publish");
        }
        Ok(outcome)
    }

    async fn apply_snapshot(
        &self,
        snapshot: &TenantDirectorySnapshot,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let current = self.registry.load();
        validate_snapshot(snapshot)?;

        let existing = current
            .by_host
            .values()
            .map(|runtime| (runtime.binding.tenant.tenant_id, runtime.clone()))
            .collect::<HashMap<_, _>>();
        // A confirmed directory removal or routing-identity change takes effect
        // before any fallible replacement work. A runtime-only revision may keep
        // its last-good graph, but cannot keep a withdrawn host/tenant binding.
        let retained = snapshot
            .tenants
            .iter()
            .filter_map(|binding| {
                let runtime = existing.get(&binding.tenant.tenant_id)?;
                (runtime.binding.tenant == binding.tenant
                    && runtime.binding.issuer == binding.issuer
                    && runtime.binding.external_host == binding.external_host)
                    .then(|| (binding.external_host.clone(), runtime.clone()))
            })
            .collect::<HashMap<_, _>>();
        if retained.len() != current.by_host.len() {
            // Do not advance the applied revision until every candidate is
            // ready: the same authoritative revision must remain retryable.
            self.publish_candidate(current.revision, retained, Vec::new())
                .await?;
        }
        let mut by_host = HashMap::with_capacity(snapshot.tenants.len());
        let mut newly_built = Vec::new();
        for binding in &snapshot.tenants {
            let runtime = match existing.get(&binding.tenant.tenant_id) {
                Some(runtime) if runtime.binding == *binding => runtime.clone(),
                _ => {
                    let runtime = self.builder.build(binding).await?;
                    anyhow::ensure!(
                        runtime.binding == *binding,
                        "tenant builder returned a different directory binding"
                    );
                    newly_built.push(runtime.clone());
                    runtime
                }
            };
            by_host.insert(binding.external_host.clone(), runtime);
        }

        self.publish_candidate(snapshot.revision, by_host, newly_built)
            .await
    }

    async fn publish_candidate(
        &self,
        revision: u64,
        by_host: HashMap<String, Arc<TenantRuntime>>,
        newly_built: Vec<Arc<TenantRuntime>>,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        // Candidate lifecycles have no request visibility yet. If any start
        // fails, retire the already-started candidates and retain last-good.
        for (started, runtime) in newly_built.iter().enumerate() {
            if let Err(error) = runtime.lifecycle.start() {
                let completions = newly_built[..=started]
                    .iter()
                    .map(|runtime| runtime.stop())
                    .collect::<Vec<_>>();
                for completion in completions {
                    completion.await;
                }
                return Err(error);
            }
        }

        let next = Arc::new(TenantHostIndex { revision, by_host });
        let previous = match self.registry.replace(next.clone()) {
            Ok(previous) => previous,
            Err(error) => {
                let completions = newly_built
                    .iter()
                    .map(|runtime| runtime.stop())
                    .collect::<Vec<_>>();
                for completion in completions {
                    completion.await;
                }
                return Err(error);
            }
        };
        let completions = previous
            .by_host
            .values()
            .filter(|runtime| {
                !next
                    .by_host
                    .get(&runtime.binding.external_host)
                    .is_some_and(|next_runtime| Arc::ptr_eq(runtime, next_runtime))
            })
            .map(|runtime| runtime.stop())
            .collect::<Vec<_>>();
        for completion in completions {
            completion.await;
        }
        Ok(TenantDirectoryRefreshOutcome::Applied { revision })
    }
}

fn validate_snapshot(snapshot: &TenantDirectorySnapshot) -> anyhow::Result<()> {
    let mut tenant_ids = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for binding in &snapshot.tenants {
        if binding.runtime_revision == 0 {
            anyhow::bail!("tenant runtime revision must be positive");
        }
        let external_host = canonical_tenant_host(&binding.external_host).map_err(|error| {
            anyhow::anyhow!("tenant directory external_host is invalid: {error}")
        })?;
        if external_host != binding.external_host {
            anyhow::bail!("tenant directory external_host must be canonical");
        }
        let issuer = nazo_auth::validate_issuer_url(&binding.issuer)
            .map_err(|error| anyhow::anyhow!("tenant directory issuer is invalid: {error}"))?;
        let issuer_host = nazo_identity::tenant_host_from_issuer(&issuer)
            .map_err(|error| anyhow::anyhow!("tenant directory issuer host is invalid: {error}"))?;
        if issuer_host != external_host {
            anyhow::bail!(
                "tenant directory issuer host {issuer_host} does not match external_host {external_host}"
            );
        }
        if !tenant_ids.insert(binding.tenant.tenant_id.as_uuid()) {
            anyhow::bail!("tenant directory contains duplicate tenant_id");
        }
        if !issuers.insert(issuer.to_string()) {
            anyhow::bail!("tenant directory contains duplicate issuer");
        }
        if !hosts.insert(external_host) {
            anyhow::bail!("tenant directory contains duplicate external_host");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/refresh.rs"]
mod tests;
