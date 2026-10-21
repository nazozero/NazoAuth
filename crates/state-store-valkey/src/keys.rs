use nazo_identity::TenantId;

pub(crate) fn fapi_http_signature_replay(tenant_id: TenantId, fingerprint: &[u8; 32]) -> String {
    format!(
        "fapi_http_signature_replay:{}:{}",
        tenant_id.as_uuid(),
        blake3::Hash::from_bytes(*fingerprint).to_hex()
    )
}

fn digest(value: &str) -> blake3::Hash {
    blake3::hash(value.as_bytes())
}

pub(crate) fn dpop_replay(jkt: &str, jti: &str) -> String {
    format!("oauth:dpop:jti:{jkt}:{}", digest(jti))
}

pub(crate) fn dpop_nonce(nonce: &str) -> String {
    format!("oauth:dpop:nonce:{}", digest(nonce))
}

pub(crate) fn client_attestation_replay(client_id: &str, jti: &str) -> String {
    // Preserve the existing shared token/PAR namespace through this repair.
    private_key_jwt_replay(&format!("client-attestation:{client_id}"), jti)
}

pub(crate) fn private_key_jwt_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:client_assertion:jti:{}:{}",
        digest(client_id),
        digest(jti)
    )
}

#[cfg(test)]
#[path = "../tests/unit/keys.rs"]
mod tests;

pub(crate) fn jar_replay(client_id: &str, jti: &str) -> String {
    format!("oauth:jar:jti:{}:{}", digest(client_id), digest(jti))
}

pub(crate) fn jwt_bearer_replay(client_id: &str, jti: &str) -> String {
    format!("oauth:jwt_bearer:jti:{}:{}", digest(client_id), digest(jti))
}

pub(crate) fn ciba_request_object_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:ciba:request_object:jti:{}:{}",
        digest(client_id),
        digest(jti)
    )
}

pub(crate) fn session(session_id: &str) -> String {
    format!("oauth:session:v2:{session_id}")
}

pub(crate) fn client_delivery(user_id: nazo_identity::UserId, token: &str) -> String {
    format!("oauth:client_delivery:{}:{token}", user_id.as_uuid())
}

pub(crate) fn consent(request_id: &str) -> String {
    format!("oauth:consent:{request_id}")
}

pub(crate) fn par(request_uri: &str) -> String {
    format!("oauth:par:{}", digest(request_uri))
}

pub(crate) fn authorization_code_hash(code_hash: &str) -> String {
    format!("oauth:auth_code:{code_hash}")
}

pub(crate) fn authorization_code(code: &str) -> String {
    authorization_code_hash(&digest(code).to_hex())
}

pub(crate) fn reauth_nonce(nonce: &str) -> String {
    format!("oauth:authorization:reauth:{}", digest(nonce))
}

pub(crate) fn ciba(auth_req_id: &str) -> String {
    ciba_from_hash(&digest(auth_req_id).to_hex())
}

pub(crate) fn ciba_hash(auth_req_id: &str) -> String {
    digest(auth_req_id).to_hex().to_string()
}

pub(crate) fn ciba_from_hash(auth_req_id_hash: &str) -> String {
    format!("oauth:ciba:{auth_req_id_hash}")
}

pub(crate) fn ciba_ping_queue() -> String {
    "oauth:ciba:ping:due".to_owned()
}

pub(crate) fn device_code(device_code: &str) -> String {
    device_code_hash(&digest(device_code).to_hex())
}

pub(crate) fn device_code_hash(device_code_hash: &str) -> String {
    format!("oauth:device:code:{device_code_hash}")
}

pub(crate) fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

pub(crate) fn device_user_code(user_code: &str) -> String {
    format!(
        "oauth:device:user_code:{}",
        digest(&normalize_user_code(user_code))
    )
}

pub(crate) fn email_send(tenant_id: TenantId, email: &str) -> String {
    format!(
        "oauth:email_verify:{}:send:{}",
        tenant_id.as_uuid(),
        digest(email)
    )
}
pub(crate) fn email_peer_send(tenant_id: TenantId, subject: &str) -> String {
    format!(
        "oauth:email_verify:{}:peer_send:{}",
        tenant_id.as_uuid(),
        digest(subject)
    )
}
pub(crate) fn email_code(tenant_id: TenantId, email: &str) -> String {
    format!(
        "oauth:email_verify:{}:code:{}",
        tenant_id.as_uuid(),
        digest(email)
    )
}
pub(crate) fn passkey_registration(ceremony_id: &str) -> String {
    format!("oauth:passkey:registration:{ceremony_id}")
}
pub(crate) fn passkey_authentication(ceremony_id: &str) -> String {
    format!("oauth:passkey:authentication:{ceremony_id}")
}
pub(crate) fn oidc_federation(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", digest(state))
}
pub(crate) fn social_federation(state: &str) -> String {
    format!("oauth:federation:social:state:{}", digest(state))
}
pub(crate) fn saml_federation_replay(signature: &str) -> String {
    format!("oauth:federation:saml:replay:{}", digest(signature))
}
pub(crate) fn rate(dimension: &str, subject: &str) -> String {
    format!("oauth:rate:{dimension}:{}", digest(subject.trim()))
}
pub(crate) fn login_failure(dimension: &str, subject: &str) -> String {
    format!("oauth:login_failure:{dimension}:{}", digest(subject.trim()))
}

pub(crate) fn mfa_failure(subject: &str) -> String {
    format!("oauth:mfa_failure:{}", digest(subject.trim()))
}
pub(crate) fn native_sso(secret: &str) -> String {
    format!("oauth:native_sso:device_secret:{}", digest(secret))
}

pub(crate) fn avatar_upload(upload_id: &str) -> String {
    format!("oauth:avatar:upload:{}", digest(upload_id))
}
