use super::*;
pub(crate) fn registry(binding: TenantDirectoryBinding) -> TenantRuntimeRegistry {
    let runtime = Arc::new(TenantRuntime {
        binding: binding.clone(),
        assembly: None,
        lifecycle: Arc::new(Mutex::new(TenantRuntimeLifecycle::default())),
    });
    TenantRuntimeRegistry {
        current: Arc::new(ArcSwap::from_pointee(TenantHostIndex {
            revision: 1,
            by_host: HashMap::from([(binding.external_host, runtime)]),
        })),
    }
}
