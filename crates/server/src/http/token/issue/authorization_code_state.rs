use super::*;

const MARK_CONSUMED_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

const MARK_FAILED_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

pub(super) fn consumed_authorization_code_transition_result(result: &str) -> anyhow::Result<()> {
    if result == "ok" {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming")
    }
}

pub(super) fn failed_authorization_code_transition_result(result: &str) -> anyhow::Result<()> {
    if matches!(result, "ok" | "missing" | "failed" | "consumed") {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming")
    }
}

pub(super) fn consumed_authorization_code_ttl_seconds(
    access_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    refresh_token_family_id: Option<Uuid>,
) -> u64 {
    let ttl_seconds = if refresh_token_family_id.is_some() {
        refresh_token_ttl_seconds
    } else {
        access_token_ttl_seconds
    };
    ttl_seconds.max(1) as u64
}

pub(super) async fn persist_consumed_authorization_code(
    state: &AppState,
    code_hash: &str,
    client_id: Uuid,
    access_token_jti: String,
    access_token_expires_at: i64,
    refresh_token_family_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let payload = ConsumedAuthorizationCode {
        client_id,
        access_token_jti,
        access_token_expires_at,
        refresh_token_family_id,
        consumed_at: Utc::now(),
    };
    let body = serde_json::to_string(&AuthorizationCodeState::Consumed { marker: payload })?;
    let ttl_seconds = consumed_authorization_code_ttl_seconds(
        state.settings.access_token_ttl_seconds,
        state.settings.refresh_token_ttl_seconds,
        refresh_token_family_id,
    );
    let result = valkey_eval_string(
        &state.valkey,
        MARK_CONSUMED_AUTHORIZATION_CODE_SCRIPT,
        vec![authorization_code_key_from_hash(code_hash)],
        vec![body, ttl_seconds.to_string()],
    )
    .await?;
    consumed_authorization_code_transition_result(&result)
}

pub(crate) async fn mark_failed_authorization_code(
    state: &AppState,
    code_hash: &str,
    error_code: &str,
) -> anyhow::Result<()> {
    let body = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: error_code.to_owned(),
    })?;
    let result = valkey_eval_string(
        &state.valkey,
        MARK_FAILED_AUTHORIZATION_CODE_SCRIPT,
        vec![authorization_code_key_from_hash(code_hash)],
        vec![
            body,
            state.settings.auth_code_ttl_seconds.max(1).to_string(),
        ],
    )
    .await?;
    failed_authorization_code_transition_result(&result)
}

pub(super) async fn mark_failed_authorization_code_if_needed(
    state: &AppState,
    code_hash: Option<&str>,
    error_code: &str,
) {
    if let Some(code_hash) = code_hash
        && let Err(error) = mark_failed_authorization_code(state, code_hash, error_code).await
    {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

pub(crate) async fn revoke_issued_authorization_code_tokens(
    state: &AppState,
    client: &ClientRow,
    access_token_jti: &str,
    access_token_expires_at: i64,
    refresh_token_family_id: Option<Uuid>,
) -> anyhow::Result<()> {
    nazo_postgres::AuthorizationRepository::new(state.diesel_db.clone())
        .revoke_issued_tokens(
            client.tenant_id,
            client.id,
            access_token_jti,
            DateTime::<Utc>::from_timestamp(access_token_expires_at, 0),
            refresh_token_family_id,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to revoke authorization-code tokens: {error}"))
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/token/tests/authorization_code_state.rs"]
mod tests;
