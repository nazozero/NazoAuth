//! Authorization decisions own their grant mutation, replay fences and audit.
use jiff::Timestamp;
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
    AuthorizationFuture, AuthorizationPortError, AuthorizationRepositoryPort,
    ClientAuthenticationSnapshot, ClientPresentation, DeviceGrantFuture, DeviceGrantPortError,
    DeviceGrantRepositoryPort, DeviceGrantWrite, OAuthClient, StoredAuthorizationGrant,
};
use nazo_identity::{
    Principal, TenantId,
    ports::{MtlsTrustAnchorStore, RepositoryError},
};
use nazo_persistence::SecurityAuditEvent;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    clients::{self, CLIENT_PRINCIPAL, CLIENT_PUBLIC_ID, ClientPrincipal},
    db::{key, map_error, put_expiring, read_snapshot, read_tx},
    grants::{self, GrantRecord},
    users::USER_PRINCIPAL,
};

pub(crate) const REQUEST: u8 = 0x85;
pub(crate) const PAR: u8 = 0x86;
pub(crate) const DEVICE: u8 = 0x87;

fn error(error: RepositoryError) -> AuthorizationPortError {
    match error {
        RepositoryError::Unavailable => AuthorizationPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            AuthorizationPortError::Conflict
        }
        RepositoryError::Consistency(_) => AuthorizationPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            AuthorizationPortError::Unexpected
        }
    }
}

fn device_error(error: RepositoryError) -> DeviceGrantPortError {
    match error {
        RepositoryError::Unavailable => DeviceGrantPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            DeviceGrantPortError::Conflict
        }
        RepositoryError::Consistency(_) => DeviceGrantPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            DeviceGrantPortError::Unexpected
        }
    }
}

fn invalid() -> RepositoryError {
    RepositoryError::Consistency("invalid authorization decision".into())
}

fn digest(value: &[u8]) -> Value {
    Value::String(blake3::hash(value).to_hex().to_string())
}

fn prepare_event(
    input: &AuthorizationDecisionCommit,
    tenant: Uuid,
) -> Result<SecurityAuditEvent, RepositoryError> {
    if input.tenant_id != tenant
        || tenant.is_nil()
        || input.user_id.is_nil()
        || input.user_epoch < 0
        || input.event_id.is_nil()
        || input.request_id.is_empty()
        || input.request_id.len() > 512
        || input.client_id.is_empty()
        || input.client_id.len() > 512
        || input
            .pushed_request_uri
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 1024)
        || input.retain_until < input.valid_until
        || input.retain_until < input.occurred_at
        || !input.audit_fields.is_object()
        || !input.authorization_details.is_array()
    {
        return Err(invalid());
    }
    let hex_digest = |value: &Value| {
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    let mut payload = json!({
        "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
        "event_category": "authorization", "tenant_id": tenant,
        "user_id": input.user_id, "client_id": input.client_id,
        "decision": input.decision.as_str(), "valid_until": input.valid_until,
        "retain_until": input.retain_until, "scope": input.scopes.join(" "),
        "request_id_hash": digest(input.request_id.as_bytes()),
    });
    // Caller-supplied fields are deliberately restricted to public evidence.
    // Request/PAR/resources/detail hashes are bound to this exact operation.
    for field in ["source_ip_hash", "pushed_request_digest"] {
        if let Some(value) = input.audit_fields.get(field) {
            if !hex_digest(value) {
                return Err(invalid());
            }
            payload[field] = value.clone();
        }
    }
    match input.decision {
        AuthorizationDecisionKind::Approve | AuthorizationDecisionKind::PromptNone => {
            if !input
                .audit_fields
                .get("code_id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
                || !input.audit_fields.get("code_hash").is_some_and(hex_digest)
                || !input
                    .audit_fields
                    .get("code_payload_digest")
                    .is_some_and(hex_digest)
            {
                return Err(invalid());
            }
            for field in ["code_id", "code_hash", "code_payload_digest"] {
                payload[field] = input.audit_fields[field].clone();
            }
        }
        AuthorizationDecisionKind::Deny => {
            if ["code_id", "code_hash", "code_payload_digest"]
                .iter()
                .any(|field| input.audit_fields.get(field).is_some())
            {
                return Err(invalid());
            }
        }
    }
    if let Some(par) = &input.pushed_request_uri {
        payload["pushed_request_uri_hash"] = digest(par.as_bytes());
    }
    if !input.resource_indicators.is_empty() {
        let mut hash = blake3::Hasher::new();
        for (index, resource) in input.resource_indicators.iter().enumerate() {
            if index > 0 {
                hash.update(b"\x1f");
            }
            hash.update(resource.as_bytes());
        }
        payload["resource_digest"] = Value::String(hash.finalize().to_hex().to_string());
    }
    if input
        .authorization_details
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        let mut hash = blake3::Hasher::new();
        serde_json::to_writer(&mut hash, &input.authorization_details).map_err(|_| invalid())?;
        payload["authorization_details_digest"] =
            Value::String(hash.finalize().to_hex().to_string());
    }
    if !nazo_persistence::security_audit_payload_within_limit(&payload) {
        return Err(invalid());
    }
    Ok(SecurityAuditEvent {
        event_id: input.event_id,
        event_type: "authorization_decision_committed".into(),
        event_category: "authorization".into(),
        payload,
        occurred_at: input.occurred_at,
    })
}

fn commit(
    store: &RocksDb,
    input: AuthorizationDecisionCommit,
) -> Result<AuthorizationDecisionCommitResult, RepositoryError> {
    let event = prepare_event(&input, store.tenant_id)?;
    let tx = store.transaction();
    let tenant = input.tenant_id;
    // The public identifier is immutable. Lock the actual authority records in
    // the same client -> user -> grant order as token issuance and revocation.
    let Some(client_id) = tx
        .get_pinned(key(CLIENT_PUBLIC_ID, tenant, input.client_id.as_bytes()))
        .map_err(map_error)?
        .map(|raw| crate::db::decode::<Uuid>(&raw))
        .transpose()?
    else {
        return Ok(AuthorizationDecisionCommitResult::ClientUnavailable);
    };
    if !read_tx::<ClientPrincipal>(
        &tx,
        &key(CLIENT_PRINCIPAL, tenant, client_id.as_bytes()),
        false,
    )?
    .is_some_and(|c| c.active)
    {
        return Ok(AuthorizationDecisionCommitResult::ClientUnavailable);
    }
    if !read_tx::<Principal>(
        &tx,
        &key(USER_PRINCIPAL, tenant, input.user_id.as_bytes()),
        false,
    )?
    .is_some_and(|u| u.active && u.authorization_epoch == input.user_epoch)
    {
        return Ok(AuthorizationDecisionCommitResult::SubjectUnavailable);
    }
    match input.decision {
        AuthorizationDecisionKind::Approve => {
            let _ = tx
                .get_pinned_for_update(grants::grant_key(tenant, input.user_id, client_id), true)
                .map_err(map_error)?;
        }
        AuthorizationDecisionKind::PromptNone => {
            let Some(grant) = grants::read_grant_tx(&tx, tenant, input.user_id, client_id, false)?
            else {
                return Ok(AuthorizationDecisionCommitResult::GrantUnavailable);
            };
            if !nazo_auth::stored_grant_covers_requested_authorization(
                &grant.authorization(),
                &input.scopes,
                &input.resource_indicators,
                &input.authorization_details,
            ) {
                return Ok(AuthorizationDecisionCommitResult::GrantUnavailable);
            }
        }
        AuthorizationDecisionKind::Deny => {}
    }
    let request_key = key(
        REQUEST,
        tenant,
        blake3::hash(input.request_id.as_bytes()).as_bytes(),
    );
    let par_key = input
        .pushed_request_uri
        .as_ref()
        .map(|uri| key(PAR, tenant, blake3::hash(uri.as_bytes()).as_bytes()));
    if tx
        .get_pinned_for_update(&request_key, true)
        .map_err(map_error)?
        .is_some()
    {
        return Ok(AuthorizationDecisionCommitResult::Conflict);
    }
    if let Some(par) = &par_key
        && tx
            .get_pinned_for_update(par, true)
            .map_err(map_error)?
            .is_some()
    {
        return Ok(AuthorizationDecisionCommitResult::Conflict);
    }
    if tx
        .get_pinned_for_update(
            key(crate::audit::EVENTS, Uuid::nil(), input.event_id.as_bytes()),
            true,
        )
        .map_err(map_error)?
        .is_some()
    {
        return Ok(AuthorizationDecisionCommitResult::Conflict);
    }
    if input.valid_until <= Timestamp::now() {
        return Ok(AuthorizationDecisionCommitResult::Expired);
    }
    if input.decision == AuthorizationDecisionKind::Approve {
        grants::write_grant_tx(
            &tx,
            tenant,
            input.user_id,
            client_id,
            &input.scopes,
            &input.resource_indicators,
            &input.authorization_details,
            true,
            input.occurred_at,
        )?;
    }
    put_expiring(&tx, &request_key, &input.event_id, input.retain_until)?;
    if let Some(par) = par_key {
        put_expiring(&tx, &par, &input.event_id, input.retain_until)?;
    }
    append_in_tx(&tx, &event)?;
    if input.valid_until <= Timestamp::now() {
        return Ok(AuthorizationDecisionCommitResult::Expired);
    }
    tx.commit().map_err(map_error)?;
    Ok(AuthorizationDecisionCommitResult::Committed)
}

impl AuthorizationRepositoryPort for RocksDb {
    fn commit_decision<'a>(
        &'a self,
        input: AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'a, AuthorizationDecisionCommitResult> {
        Box::pin(async move {
            self.run(move |store| commit(store, input))
                .await
                .map_err(error)
        })
    }

    fn client_by_id<'a>(
        &'a self,
        public_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        let public_id = public_id.to_owned();
        Box::pin(async move {
            self.run(move |store| {
                clients::public_id_snapshot(&store.db.snapshot(), store.tenant_id, &public_id)
            })
            .await
            .map_err(error)
        })
    }

    fn active_client_presentation<'a>(
        &'a self,
        public_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ClientPresentation>> {
        let public_id = public_id.to_owned();
        Box::pin(async move {
            self.run(move |store| {
                clients::client_presentation(&store.db.snapshot(), store.tenant_id, &public_id)
            })
            .await
            .map_err(error)
        })
    }

    fn client_authentication_snapshot<'a>(
        &'a self,
        public_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ClientAuthenticationSnapshot>> {
        let public_id = public_id.to_owned();
        Box::pin(async move {
            self.run(move |store| {
                clients::client_authentication(&store.db.snapshot(), store.tenant_id, &public_id)
            })
            .await
            .map_err(error)
        })
    }

    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        Box::pin(async move {
            let tenant =
                TenantId::new(self.tenant_id).map_err(|_| AuthorizationPortError::CorruptData)?;
            self.active_bundle(tenant, Some(client_id))
                .await
                .map_err(error)
        })
    }

    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        Box::pin(async move {
            self.run(move |store| {
                Ok(read_snapshot::<GrantRecord>(
                    &store.db.snapshot(),
                    &grants::grant_key(store.tenant_id, user_id, client_id),
                )?
                .map(GrantRecord::authorization))
            })
            .await
            .map_err(error)
        })
    }
}

impl DeviceGrantRepositoryPort for RocksDb {
    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()> {
        let device_digest = *blake3::hash(write.device_code_hash.as_bytes()).as_bytes();
        let (tenant, user, client, expires) = (
            write.tenant_id,
            write.user_id,
            write.client_id,
            write.expires_at,
        );
        let (scopes, resources, details) = (
            write.scopes.to_vec(),
            write.resource_indicators.to_vec(),
            write.authorization_details.clone(),
        );
        Box::pin(async move {
            self.run(move |store| {
                if tenant != store.tenant_id {
                    return Err(invalid());
                }
                let tx = store.transaction();
                read_tx::<ClientPrincipal>(
                    &tx,
                    &key(CLIENT_PRINCIPAL, tenant, client.as_bytes()),
                    false,
                )?
                .filter(|c| c.active)
                .ok_or(RepositoryError::NotFound)?;
                read_tx::<Principal>(&tx, &key(USER_PRINCIPAL, tenant, user.as_bytes()), false)?
                    .filter(|u| u.active)
                    .ok_or(RepositoryError::NotFound)?;
                let _ = tx
                    .get_pinned_for_update(grants::grant_key(tenant, user, client), true)
                    .map_err(map_error)?;
                let receipt = key(DEVICE, tenant, &device_digest);
                let previous = tx
                    .get_pinned_for_update(&receipt, true)
                    .map_err(map_error)?
                    .is_some();
                if expires <= Timestamp::now() {
                    return Err(RepositoryError::Conflict);
                }
                if previous {
                    return Ok(());
                }
                grants::write_grant_tx(
                    &tx,
                    tenant,
                    user,
                    client,
                    &scopes,
                    &resources,
                    &details,
                    true,
                    Timestamp::now(),
                )?;
                put_expiring(&tx, &receipt, &(), expires)?;
                tx.commit().map_err(map_error)
            })
            .await
            .map_err(device_error)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization.rs"]
mod tests;
