use std::{collections::BTreeSet, sync::Arc, time::Duration};

use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use nazo_runtime_modules::{
    ModuleId, ModuleLifecycle, ModuleRevision, ReconcileOutcome, RegistryError,
};

#[derive(Clone)]
pub struct StoredTransactionLifecycle {
    store: Arc<dyn nazo_persistence::RuntimeModuleStore>,
}

impl StoredTransactionLifecycle {
    pub fn new(store: Arc<dyn nazo_persistence::RuntimeModuleStore>) -> Self {
        Self { store }
    }
}

impl ModuleLifecycle for StoredTransactionLifecycle {
    fn drain_stored_transactions(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        remaining_duration: Duration,
    ) -> nazo_runtime_modules::LifecycleFuture<
        '_,
        Result<bool, nazo_runtime_modules::LifecycleFailure>,
    > {
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + remaining_duration;
            loop {
                if !self
                    .store
                    .validate_revision(module_id, revision)
                    .await
                    .map_err(|_| nazo_runtime_modules::LifecycleFailure {
                        code: "drain_revision_lookup_failed",
                    })?
                {
                    return Err(nazo_runtime_modules::LifecycleFailure {
                        code: "revision_changed",
                    });
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Ok(true);
                }
                tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
            }
        })
    }
}

pub(crate) fn spawn_reconciler(
    application: Arc<nazoauth::NazoAuth>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let planning = application.clone();
        run_reconciler(
            move || {
                let application = planning.clone();
                Box::pin(async move { application.plan_reconciliation().await })
            },
            move |module_id| {
                let application = application.clone();
                Box::pin(async move { application.reconcile_once(module_id).await })
            },
        )
        .await;
    })
}

type ReconcileError = RegistryError<nazo_identity::ports::RepositoryError>;

// The tenant owns this loop and every in-flight future. The narrow closures
// expose the existing registry operations to deterministic scheduling tests.
async fn run_reconciler(
    mut plan: impl FnMut() -> BoxFuture<'static, Result<Vec<ModuleId>, ReconcileError>> + Send,
    mut reconcile: impl FnMut(ModuleId) -> BoxFuture<'static, Result<ReconcileOutcome, ReconcileError>>
    + Send,
) {
    type Error = ReconcileError;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut planning: Option<BoxFuture<'static, Result<Vec<ModuleId>, Error>>> = None;
    let mut transitions: FuturesUnordered<
        BoxFuture<'static, (ModuleId, Result<ReconcileOutcome, Error>)>,
    > = FuturesUnordered::new();
    let mut busy = BTreeSet::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if planning.is_none() {
                    planning = Some(plan());
                }
            }
            plan = async { planning.as_mut().expect("guarded planning future").await }, if planning.is_some() => {
                planning = None;
                match plan {
                    Ok(ids) => for module_id in ids {
                        if busy.insert(module_id) {
                            let transition = reconcile(module_id);
                            transitions.push(Box::pin(async move { (module_id, transition.await) }));
                        }
                    },
                    Err(error) => tracing::error!(?error, "runtime module snapshot read failed"),
                }
            }
            Some((module_id, outcome)) = transitions.next(), if !transitions.is_empty() => {
                busy.remove(&module_id);
                match outcome {
                    Ok(ReconcileOutcome::NoChange) => {}
                    Ok(outcome) => tracing::info!(?module_id, ?outcome, "runtime module reconciled"),
                    Err(error) => tracing::error!(?module_id, ?error, "runtime module reconcile failed"),
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/runtime_modules.rs"]
mod tests;
