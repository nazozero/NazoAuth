//! Prepared deployment identity and its signed control discovery response.
use chrono::Utc;
use nazo_crypto::ed25519::SigningKey;
use nazo_operator_protocol::{
    DeploymentStatement, DiscoveryRequest, DiscoveryResponse, DiscoveryStatement,
    encode_instance_public_key, instance_key_id, sign_discovery_statement,
    validate_discovery_request,
};
use std::sync::Arc;
const DISCOVERY_RESPONSE_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct DeploymentIdentity {
    identity: Arc<InstanceIdentity>,
}
struct InstanceIdentity {
    signing_key: SigningKey,
    public_key: String,
    deployment: DeploymentStatement,
}
impl DeploymentIdentity {
    /// Bind already-loaded key material to the published deployment statement.
    pub fn new(signing_key: SigningKey, deployment: DeploymentStatement) -> anyhow::Result<Self> {
        let verifying = signing_key.verifying_key();
        anyhow::ensure!(
            instance_key_id(&verifying) == deployment.instance_key_id,
            "deployment statement key does not match the supplied signing key"
        );
        let public_key = encode_instance_public_key(&verifying);
        Ok(Self {
            identity: Arc::new(InstanceIdentity {
                signing_key,
                public_key,
                deployment,
            }),
        })
    }
    pub fn runtime_instance_id(&self) -> &str {
        &self.identity.deployment.runtime_instance_id
    }

    pub fn deployment_id(&self) -> &str {
        &self.identity.deployment.deployment_id
    }

    pub fn respond(&self, request: DiscoveryRequest) -> anyhow::Result<DiscoveryResponse> {
        validate_discovery_request(&request)?;
        let issued_at = Utc::now().timestamp();
        let deployment = &self.identity.deployment;
        let statement = DiscoveryStatement {
            schema: deployment.schema,
            product: deployment.product.clone(),
            deployment_id: deployment.deployment_id.clone(),
            runtime_instance_id: deployment.runtime_instance_id.clone(),
            issuer: deployment.issuer.clone(),
            release: deployment.release.clone(),
            control_protocol_versions: deployment.control_protocol_versions.clone(),
            operator_protocol_versions: deployment.operator_protocol_versions.clone(),
            instance_key_id: deployment.instance_key_id.clone(),
            nonce: request.nonce,
            issued_at,
            expires_at: issued_at + DISCOVERY_RESPONSE_SECONDS,
        };
        Ok(DiscoveryResponse {
            statement: sign_discovery_statement(
                &statement,
                &deployment.instance_key_id,
                &self.identity.signing_key,
            )?,
            instance_public_key: self.identity.public_key.clone(),
        })
    }
}

pub async fn control_discovery(
    endpoint: &DeploymentIdentity,
    request: DiscoveryRequest,
) -> crate::http::Response {
    match endpoint.respond(request) {
        Ok(response) => crate::http::json_response(response),
        Err(error) => crate::http::json_response_status(
            http::StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": "invalid_control_discovery_request",
                "error_description": error.to_string(),
            }),
        ),
    }
}
