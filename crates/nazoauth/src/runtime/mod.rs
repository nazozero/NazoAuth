//! Shared tenant selection, directory synchronization and runtime ownership.
//!
//! Request selection reads one immutable snapshot. Only directory reconciliation
//! constructs graphs; persistence and scheduling enter through existing ports
//! and [`TenantLifecycle`]. Fixed tenants keep using `Arc<NazoAuth>` directly.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use futures_util::future::BoxFuture;
use nazo_identity::{TenantDirectoryBinding, TenantDirectorySnapshot, canonical_tenant_host};

use crate::NazoAuth;

mod refresh;
pub use refresh::{TenantDirectoryRefreshOutcome, TenantRuntimeRefresher};

/// Environment-owned scheduling for one fully assembled tenant graph.
///
/// Starting must be idempotent. `stop` must signal or cancel every owned task
/// before returning its completion future, so dropping that future cannot leave
/// unsignalled tasks running. In-flight key writes must finish cooperatively.
/// Dropping the lifecycle must also stop its tasks.
pub trait TenantLifecycle: Send + Sync {
    fn start(&self) -> anyhow::Result<()>;
    fn stop(&self) -> BoxFuture<'_, ()>;
}

/// A directory binding and its complete immutable application graph.
pub struct TenantRuntime {
    binding: TenantDirectoryBinding,
    application: Application,
    lifecycle: Arc<dyn TenantLifecycle>,
}

// Production contains only the complete graph. The explicit fixture exists
// solely for control-plane tests that exercise publication without HTTP ports.
enum Application {
    Ready(Arc<NazoAuth>),
    #[cfg(any(test, feature = "test-support"))]
    Fixture,
}

impl TenantRuntime {
    /// Bind a graph to one directory hostname. Its public and mTLS endpoints
    /// must use that hostname; the mTLS listener may use a different port.
    pub fn new(
        binding: TenantDirectoryBinding,
        application: Arc<NazoAuth>,
        lifecycle: Arc<dyn TenantLifecycle>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            application.settings.tenant.context == binding.tenant,
            "tenant runtime application does not match its directory tenant"
        );
        anyhow::ensure!(
            application.settings.endpoint.issuer == binding.issuer,
            "tenant runtime application does not match its directory issuer"
        );
        let mtls = url::Url::parse(&application.settings.endpoint.mtls_endpoint_base_url)?;
        anyhow::ensure!(
            nazo_identity::tenant_host_from_issuer(&mtls)? == binding.external_host,
            "dynamic tenant mTLS endpoint must use its directory hostname"
        );
        Ok(Self {
            binding,
            application: Application::Ready(application),
            lifecycle,
        })
    }

    pub fn binding(&self) -> &TenantDirectoryBinding {
        &self.binding
    }

    pub fn application(&self) -> &Arc<NazoAuth> {
        match &self.application {
            Application::Ready(application) => application,
            #[cfg(any(test, feature = "test-support"))]
            Application::Fixture => panic!("directory fixture has no application graph"),
        }
    }

    /// Signal all owned tasks synchronously, then await their completion.
    pub fn stop(&self) -> BoxFuture<'_, ()> {
        self.lifecycle.stop()
    }

    fn check_mount_paths(&self, occupied_paths: &[&str]) -> anyhow::Result<()> {
        match &self.application {
            Application::Ready(application) => application.mount().check_conflicts(occupied_paths),
            #[cfg(any(test, feature = "test-support"))]
            Application::Fixture => Ok(()),
        }
    }
}

/// Immutable host index. Retaining a snapshot keeps its graphs alive for
/// requests already admitted while a newer directory is published.
pub struct TenantHostIndex {
    pub revision: u64,
    pub by_host: HashMap<String, Arc<TenantRuntime>>,
}

impl TenantHostIndex {
    fn empty() -> Self {
        Self {
            revision: 0,
            by_host: HashMap::new(),
        }
    }

    /// Resolve actual HTTP authority and authenticated TLS server name.
    /// Canonical hosts borrow their request bytes; normalization allocates only
    /// for aliases such as uppercase DNS names or noncanonical IP spellings.
    pub fn resolve(
        &self,
        authority: &str,
        server_name: Option<&str>,
    ) -> Result<&Arc<TenantRuntime>, http::StatusCode> {
        let host = authority_host(authority).ok_or(http::StatusCode::NOT_FOUND)?;
        if let Some(runtime) = self.by_host.get(host) {
            return require_server_name(server_name, host).map(|()| runtime);
        }
        let canonical = canonical_tenant_host(host).map_err(|_| http::StatusCode::NOT_FOUND)?;
        require_server_name(server_name, &canonical)?;
        self.by_host
            .get(&canonical)
            .ok_or(http::StatusCode::NOT_FOUND)
    }
}

fn require_server_name(server_name: Option<&str>, host: &str) -> Result<(), http::StatusCode> {
    if server_name.is_none_or(|server_name| {
        server_name == host
            || canonical_tenant_host(server_name).is_ok_and(|canonical| canonical == host)
    }) {
        Ok(())
    } else {
        Err(http::StatusCode::MISDIRECTED_REQUEST)
    }
}

/// Borrow the host from an authority without allocating an HTTP URI object.
/// Userinfo and malformed ports cannot become tenant-routing aliases.
fn authority_host(authority: &str) -> Option<&str> {
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'@' | b'/' | b'?' | b'#' | b'\\')
        })
    {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')? + 1;
        let suffix = &authority[end..];
        (
            &authority[..end],
            if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(':')?)
            },
        )
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host, Some(port))
    } else {
        (authority, None)
    };
    if host.is_empty() || port.is_some_and(|port| !port.bytes().all(|byte| byte.is_ascii_digit())) {
        return None;
    }
    Some(host)
}

#[derive(Default)]
struct PublicationPolicy {
    occupied_paths: Vec<String>,
    closed: bool,
}

struct RegistryState {
    current: ArcSwap<TenantHostIndex>,
    // Only registration, publication and close take this lock. Requests never do.
    publication: Mutex<PublicationPolicy>,
}

/// One shared atomically published directory for every transport adapter.
#[derive(Clone)]
pub struct TenantRuntimeRegistry {
    state: Arc<RegistryState>,
}

impl Default for TenantRuntimeRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl TenantRuntimeRegistry {
    pub fn empty() -> Self {
        Self {
            state: Arc::new(RegistryState {
                current: ArcSwap::from_pointee(TenantHostIndex::empty()),
                publication: Mutex::new(PublicationPolicy::default()),
            }),
        }
    }

    pub fn load(&self) -> Arc<TenantHostIndex> {
        self.state.current.load_full()
    }

    pub fn revision(&self) -> u64 {
        self.state.current.load().revision
    }

    pub fn resolve(
        &self,
        authority: &str,
        server_name: Option<&str>,
    ) -> Result<Arc<TenantRuntime>, http::StatusCode> {
        self.state
            .current
            .load()
            .resolve(authority, server_name)
            .cloned()
    }

    /// Register host namespaces for current and future tenant graphs. Multiple
    /// mounts sharing a registry share the union of their namespace constraints.
    /// Validation and publication use the same control-plane lock.
    pub fn require_mount_paths(&self, occupied_paths: &[&str]) -> anyhow::Result<()> {
        for path in occupied_paths {
            anyhow::ensure!(
                path.starts_with('/') && !path.contains(['?', '#']),
                "reserved paths must start with / and contain no query or fragment"
            );
        }
        let mut publication = self
            .state
            .publication
            .lock()
            .expect("tenant publication mutex");
        anyhow::ensure!(!publication.closed, "tenant runtime registry is closed");
        for runtime in self.state.current.load().by_host.values() {
            runtime.check_mount_paths(occupied_paths)?;
        }
        for path in occupied_paths {
            let path = path.trim_end_matches('/');
            let path = if path.is_empty() { "/" } else { path };
            if !publication
                .occupied_paths
                .iter()
                .any(|existing| existing == path)
            {
                publication.occupied_paths.push(path.to_owned());
            }
        }
        Ok(())
    }

    #[cfg(feature = "deployment-control")]
    pub fn availability(&self) -> Arc<dyn crate::capabilities::TenantAvailability> {
        Arc::new(PublishedTenantAvailability(Arc::downgrade(&self.state)))
    }

    fn replace(&self, next: Arc<TenantHostIndex>) -> anyhow::Result<Arc<TenantHostIndex>> {
        let publication = self
            .state
            .publication
            .lock()
            .expect("tenant publication mutex");
        anyhow::ensure!(!publication.closed, "tenant runtime registry is closed");
        let occupied_paths = publication
            .occupied_paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        for runtime in next.by_host.values() {
            runtime.check_mount_paths(&occupied_paths)?;
        }
        Ok(self.state.current.swap(next))
    }

    /// Permanently reject future publications and withdraw every route. The
    /// returned snapshot owns the retired graphs; call `stop` on each runtime
    /// before awaiting any of their completion futures.
    pub fn close(&self) -> Arc<TenantHostIndex> {
        let mut publication = self
            .state
            .publication
            .lock()
            .expect("tenant publication mutex");
        publication.closed = true;
        self.state.current.swap(Arc::new(TenantHostIndex::empty()))
    }
}

#[cfg(feature = "deployment-control")]
struct PublishedTenantAvailability(std::sync::Weak<RegistryState>);

#[cfg(feature = "deployment-control")]
impl crate::capabilities::TenantAvailability for PublishedTenantAvailability {
    fn contains_tenant(&self, tenant: nazo_identity::TenantId) -> bool {
        self.0.upgrade().is_some_and(|state| {
            state
                .current
                .load()
                .by_host
                .values()
                .any(|runtime| runtime.binding.tenant.tenant_id == tenant)
        })
    }
}

pub type TenantRuntimeBuildFuture<'a> = BoxFuture<'a, anyhow::Result<Arc<TenantRuntime>>>;

/// Construct one complete graph from a confirmed directory binding. This runs
/// only when the binding changes, never while dispatching a request.
pub trait TenantRuntimeBuildPort: Send + Sync {
    fn build(&self, binding: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_>;
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    use super::*;

    struct NoTasks;
    impl TenantLifecycle for NoTasks {
        fn start(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn stop(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    pub fn runtime(binding: TenantDirectoryBinding) -> Arc<TenantRuntime> {
        runtime_with_lifecycle(binding, Arc::new(NoTasks))
    }

    pub fn runtime_with_lifecycle(
        binding: TenantDirectoryBinding,
        lifecycle: Arc<dyn TenantLifecycle>,
    ) -> Arc<TenantRuntime> {
        Arc::new(TenantRuntime {
            binding,
            application: Application::Fixture,
            lifecycle,
        })
    }

    pub fn registry(binding: TenantDirectoryBinding) -> TenantRuntimeRegistry {
        let registry = TenantRuntimeRegistry::empty();
        registry
            .replace(Arc::new(TenantHostIndex {
                revision: 1,
                by_host: HashMap::from([(binding.external_host.clone(), runtime(binding))]),
            }))
            .expect("fixture registry");
        registry
    }
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/selection.rs"]
mod selection_tests;
