use crate::{
    contracts::token_endpoint::TokenRequestFacts,
    crypto::blake3_hex,
    ports::audit::audit_fields,
    services::{ServerCibaService, ServerTokenService},
    token::issue::TokenIssuanceContext,
};
use nazo_auth::CibaRequestState;
use nazo_runtime_modules::SnapshotStore;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
pub const CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
pub const CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;
pub const CIBA_BINDING_MESSAGE_MAX_CHARS: usize = 64;

pub fn ciba_grant_key(
    auth_req_id: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> String {
    let binding = json!({
        "auth_req_id": auth_req_id,
        "dpop_jkt": dpop_jkt,
        "mtls_x5t_s256": mtls_x5t_s256,
    });
    format!("ciba:{}", blake3_hex(&binding.to_string()))
}

#[derive(Clone)]
pub struct CibaConfig {
    pub issuer: Box<str>,
    pub mtls_endpoint_base_url: Box<str>,
    pub frontend_base_url: Box<str>,
    pub client_secret_pepper: Box<str>,
    pub default_audience: Box<str>,
    // CIBA state is tenant-scoped even though this process selects one active
    // tenant at startup. This is ordinary protocol ownership.
    pub tenant_id: Uuid,
    pub auth_req_id_ttl_seconds: u64,
    pub poll_interval_seconds: u64,
    pub ciba_fapi_profile: bool,
    pub ciba_fapi2_hardening: bool,
}

#[derive(Clone)]
pub struct CibaTokenHandles {
    pub service: Arc<ServerCibaService>,
    pub users: Arc<dyn nazo_persistence::CibaAccountStore>,
    pub config: Arc<CibaConfig>,
}

impl CibaTokenHandles {
    pub fn new(
        service: Arc<ServerCibaService>,
        users: Arc<dyn nazo_persistence::CibaAccountStore>,
        config: Arc<CibaConfig>,
    ) -> Self {
        Self {
            service,
            users,
            config,
        }
    }
}

pub struct CibaTokenContext<'request, 'issuance> {
    pub token_service: &'request ServerTokenService,
    pub issuance: &'request TokenIssuanceContext<'issuance>,
    pub handles: &'request CibaTokenHandles,
    pub request: &'request TokenRequestFacts<'request>,
}

pub fn ciba_module_admissible(
    runtime: &SnapshotStore,
    admission: nazo_auth::CapabilityAdmission,
) -> bool {
    nazo_auth::module_admissible(
        runtime.load_full().as_ref(),
        nazo_runtime_modules::ModuleId::Ciba,
        admission,
    )
}

#[derive(Clone, Copy, Debug)]
pub enum CibaDecisionSource {
    User,
}

impl CibaDecisionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
        }
    }
}

pub fn ciba_start_audit_fields(
    state: &CibaRequestState,
    auth_req_id: &str,
    source_ip_hash: Option<String>,
) -> serde_json::Map<String, Value> {
    let mut fields = audit_fields(&[
        ("client_id", json!(state.client_id)),
        ("user_id", json!(state.user_id)),
        ("auth_req_id_hash", json!(blake3_hex(auth_req_id))),
        ("scopes", json!(state.scopes)),
        ("audiences", json!(state.audiences)),
    ]);
    if let Some(source_ip_hash) = source_ip_hash {
        fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
    }
    fields
}
