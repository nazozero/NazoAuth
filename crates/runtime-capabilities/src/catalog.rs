use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::policy::validate_dependencies;
use crate::{DisablePolicy, ModuleCatalogError, ModuleId, ModuleSpec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogDurations {
    pub device_authorization: Duration,
    pub ciba: Duration,
    pub authorization_code: Duration,
    pub refresh_token: Duration,
    pub session: Duration,
    pub presentation_transaction: Duration,
    pub scim_security_events: Duration,
}

#[derive(Clone, Debug)]
pub struct ModuleCatalog {
    specs: BTreeMap<ModuleId, ModuleSpec>,
    runtime_disable_blocked: BTreeSet<ModuleId>,
    unavailable: BTreeSet<ModuleId>,
}

impl ModuleCatalog {
    #[must_use]
    pub fn fixed(durations: CatalogDurations) -> Self {
        let specs = ModuleId::ALL
            .into_iter()
            .map(|id| {
                let drain = |max_duration| DisablePolicy::DrainStoredTransactions { max_duration };
                let disable_policy = match id {
                    ModuleId::DeviceAuthorization => drain(durations.device_authorization),
                    ModuleId::Ciba => drain(durations.ciba),
                    ModuleId::Jarm => drain(durations.authorization_code),
                    ModuleId::AuthorizationDetails
                    | ModuleId::NativeSso
                    | ModuleId::Openid4vciIssuer => drain(durations.refresh_token),
                    ModuleId::ScimSecurityEvents => drain(durations.scim_security_events),
                    // Existing OP browser sessions can poll until their Valkey TTL expires.
                    ModuleId::SessionManagement => drain(durations.session),
                    ModuleId::Openid4vpVerifier => drain(durations.presentation_transaction),
                    ModuleId::TokenExchange
                    | ModuleId::JwtBearerGrant
                    | ModuleId::DynamicClientRegistration
                    | ModuleId::RequestObjects
                    | ModuleId::HttpMessageSignatures
                    | ModuleId::Scim
                    | ModuleId::FrontchannelLogout => DisablePolicy::FinishExecutingRequests,
                };
                (
                    id,
                    ModuleSpec {
                        id,
                        dependencies: BTreeSet::new(),
                        disable_policy,
                    },
                )
            })
            .collect();
        Self {
            specs,
            runtime_disable_blocked: BTreeSet::new(),
            unavailable: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_constructed_availability(
        mut self,
        availability: impl IntoIterator<Item = (ModuleId, bool)>,
    ) -> Self {
        for (module_id, constructed) in availability {
            if !constructed {
                self.unavailable.insert(module_id);
            }
        }
        self
    }

    #[must_use]
    pub fn is_available(&self, module_id: ModuleId) -> bool {
        !self.unavailable.contains(&module_id)
    }

    #[must_use]
    pub fn effective_enabled(&self, module_id: ModuleId, desired_enabled: bool) -> bool {
        desired_enabled && self.is_available(module_id)
    }

    #[must_use]
    pub fn with_runtime_disable_blocked(
        mut self,
        modules: impl IntoIterator<Item = ModuleId>,
    ) -> Self {
        self.runtime_disable_blocked.extend(modules);
        self
    }

    pub fn with_dependencies(
        mut self,
        module_id: ModuleId,
        dependencies: impl IntoIterator<Item = ModuleId>,
    ) -> Result<Self, ModuleCatalogError> {
        self.specs
            .get_mut(&module_id)
            .expect("the fixed catalog contains every closed module ID")
            .dependencies = dependencies.into_iter().collect();
        validate_dependencies(&self.specs)?;
        Ok(self)
    }

    #[must_use]
    pub fn specs(&self) -> &BTreeMap<ModuleId, ModuleSpec> {
        &self.specs
    }

    #[must_use]
    pub fn spec(&self, module_id: ModuleId) -> &ModuleSpec {
        &self.specs[&module_id]
    }

    #[must_use]
    pub fn runtime_disable_blocked(&self, module_id: ModuleId) -> bool {
        self.runtime_disable_blocked.contains(&module_id)
    }

    #[must_use]
    pub fn effective_disable_policy(&self, module_id: ModuleId) -> DisablePolicy {
        if !self.is_available(module_id) {
            DisablePolicy::Immediate
        } else if self.runtime_disable_blocked(module_id) {
            DisablePolicy::NotRuntimeDisableable
        } else {
            self.spec(module_id).disable_policy
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/catalog.rs"]
mod tests;
