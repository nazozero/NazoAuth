use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{Flag, NOW, digest, encode, timestamp},
};
use jiff::Timestamp;
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, PreparedTokenSubject, RefreshToken,
    RefreshTokenCommit, RefreshTokenSnapshot, SingleUseRedemption, TokenFuture, TokenPortError,
    TokenPrincipalState, TokenRepositoryPort, UserinfoClient, UserinfoSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
struct UserinfoRegistration {
    client_id: String,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<std::sync::Arc<Value>>,
    security_policy: nazo_auth::ClientSecurityPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
struct Member {
    id: Uuid,
    audience: Vec<String>,
    issued_at: i64,
    expires_at: i64,
    id_token_sid: Option<String>,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    client_attestation_jkt: Option<String>,
}
impl Member {
    fn new(token: &nazo_auth::NewRefreshToken) -> Self {
        Self {
            id: token.member_id,
            audience: token.audiences.clone(),
            issued_at: token.issued_at.as_microsecond(),
            expires_at: token.expires_at.as_microsecond(),
            id_token_sid: token.id_token_sid.clone(),
            dpop_jkt: token.dpop_jkt.clone(),
            mtls_x5t_s256: token.mtls_x5t_s256.clone(),
            client_attestation_jkt: token.client_attestation_jkt.clone(),
        }
    }
}
#[derive(Deserialize)]
struct FamilyRow {
    tenant_id: Uuid,
    id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
    contract: String,
    contract_hash: String,
    member: String,
    token_hash: String,
    revoked_at: Option<i64>,
    spent_hash: Option<String>,
    spent_member: Option<Uuid>,
    spent_at: Option<i64>,
    spent_expiry: Option<i64>,
    successor_id: Option<Uuid>,
    subject_claims: Option<String>,
    user_epoch: Option<i64>,
    bound_user: Option<Uuid>,
}
fn digest_bytes(value: &str) -> Result<[u8; 32], DbError> {
    let hash = blake3::Hash::from_hex(value).map_err(|_| DbError::CorruptData)?;
    Ok(*hash.as_bytes())
}
impl FamilyRow {
    fn into_snapshot(
        self,
        client_id: Option<Uuid>,
        retry_started_at: Timestamp,
        prepare: bool,
    ) -> Result<RefreshTokenSnapshot, DbError> {
        let member: Member =
            serde_json::from_str(&self.member).map_err(|_| DbError::CorruptData)?;
        let contract: nazo_auth::RefreshContract =
            serde_json::from_str(&self.contract).map_err(|_| DbError::CorruptData)?;
        let current = RefreshToken {
            id_token_sid: member.id_token_sid,
            id: member.id,
            token_blake3: digest_bytes(&self.token_hash)?,
            tenant_id: self.tenant_id,
            token_family_id: self.id,
            client_id: self.client_id,
            user_id: self.user_id,
            contract_key: digest_bytes(&self.contract_hash)?,
            contract,
            audience: member.audience,
            issued_at: timestamp(member.issued_at)?,
            expires_at: timestamp(member.expires_at)?,
            revoked_at: self.revoked_at.map(timestamp).transpose()?,
            dpop_jkt: member.dpop_jkt,
            mtls_x5t_s256: member.mtls_x5t_s256,
            client_attestation_jkt: member.client_attestation_jkt,
        };
        let prepared_subject = if prepare && self.spent_hash.is_none() {
            self.subject_claims
                .zip(self.user_epoch)
                .and_then(|(claims, epoch)| {
                    let claims: nazo_identity::SubjectClaims =
                        serde_json::from_str(&claims).ok()?;
                    if Some(claims.subject.as_uuid()) != current.user_id
                        || self
                            .bound_user
                            .is_some_and(|owner| Some(owner) != current.user_id)
                    {
                        return None;
                    }
                    Some(PreparedTokenSubject {
                        tenant_id: self.tenant_id,
                        claims,
                        user_epoch: epoch,
                        token_subject: current.contract.subject.clone(),
                        subject_bound: self.bound_user.is_some(),
                    })
                })
        } else {
            None
        };
        match (
            self.spent_hash,
            self.spent_member,
            self.spent_at,
            self.spent_expiry,
            self.successor_id,
        ) {
            (None, None, None, None, None) => Ok(RefreshTokenSnapshot {
                presented: current,
                successor: Ok(None),
                prepared_subject,
            }),
            (Some(hash), Some(id), Some(spent_at), Some(expiry), Some(successor_id)) => {
                let elapsed = retry_started_at.as_microsecond() - spent_at;
                let eligible = client_id == Some(current.client_id)
                    && (current.dpop_jkt.is_some() || current.mtls_x5t_s256.is_some())
                    && current.id == successor_id
                    && current.revoked_at.is_none()
                    && current.expires_at > retry_started_at
                    && (0..=60_000_000).contains(&elapsed);
                let successor = if eligible {
                    Some(current.clone())
                } else {
                    None
                };
                let mut presented = current;
                presented.id = id;
                presented.token_blake3 = digest_bytes(&hash)?;
                presented.audience = presented.contract.audiences.clone();
                presented.issued_at = timestamp(spent_at)?;
                presented.expires_at = timestamp(expiry)?;
                presented.revoked_at = Some(timestamp(spent_at)?);
                Ok(RefreshTokenSnapshot {
                    presented,
                    successor: Ok(successor),
                    prepared_subject: None,
                })
            }
            _ => Err(DbError::CorruptData),
        }
    }
}
const REFRESH_READ: &str = "WITH presentation AS (SELECT id AS family_id,NULL AS spent_hash,NULL AS spent_member,NULL AS spent_at,NULL AS spent_expiry,NULL AS successor_id,0 AS priority FROM nazo_refresh_families WHERE tenant_id=?1 AND token_hash=?2 UNION ALL SELECT family_id,token_hash,member_id,spent_at,expires_at,successor_id,1 FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash=?2), selected AS (SELECT * FROM presentation ORDER BY priority LIMIT 1) SELECT f.*,p.spent_hash,p.spent_member,p.spent_at,p.spent_expiry,p.successor_id,u.claims AS subject_claims,u.epoch AS user_epoch,b.user_id AS bound_user FROM selected p JOIN nazo_refresh_families f ON f.tenant_id=?1 AND f.id=p.family_id LEFT JOIN nazo_users u ON ?3=1 AND p.spent_hash IS NULL AND u.tenant_id=f.tenant_id AND u.id=f.user_id AND u.active=1 LEFT JOIN nazo_subjects b ON b.tenant_id=f.tenant_id AND b.subject=json_extract(f.contract,'$.subject')";

impl D1Provider {
    async fn read_refresh(
        &self,
        raw: &str,
        client: Option<Uuid>,
        started: Timestamp,
        prepare: bool,
    ) -> Result<Option<RefreshTokenSnapshot>, TokenPortError> {
        self.database
            .query::<FamilyRow>(
                REFRESH_READ,
                vec![json!(self.tenant_id), json!(digest(raw)), json!(prepare)],
            )
            .await?
            .into_iter()
            .next()
            .map(|row| {
                row.into_snapshot(client, started, prepare)
                    .map_err(Into::into)
            })
            .transpose()
    }
    async fn subject(
        &self,
        user: Uuid,
        subject: &str,
    ) -> Result<Option<PreparedTokenSubject>, TokenPortError> {
        #[derive(Deserialize)]
        struct Row {
            claims: String,
            epoch: i64,
            bound_user: Option<Uuid>,
        }
        let row=self.database.query::<Row>("SELECT u.claims,u.epoch,(SELECT user_id FROM nazo_subjects WHERE tenant_id=?1 AND subject=?3) AS bound_user FROM nazo_users u WHERE u.tenant_id=?1 AND u.id=?2 AND u.active=1",vec![json!(self.tenant_id),json!(user),json!(subject)]).await?.into_iter().next();
        row.map(|row| {
            if row.bound_user.is_some_and(|id| id != user) {
                return Err(TokenPortError::CorruptData);
            }
            let claims: nazo_identity::SubjectClaims =
                serde_json::from_str(&row.claims).map_err(|_| TokenPortError::CorruptData)?;
            if claims.subject.as_uuid() != user {
                return Err(TokenPortError::CorruptData);
            }
            Ok(PreparedTokenSubject {
                tenant_id: self.tenant_id,
                claims,
                user_epoch: row.epoch,
                token_subject: subject.into(),
                subject_bound: row.bound_user.is_some(),
            })
        })
        .transpose()
    }
}
impl TokenRepositoryPort for D1Provider {
    fn machine_client_active(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        epoch: i64,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let row = self.database.query::<Flag>(
                "SELECT EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND active=1 AND epoch=?3) AS value",
                vec![json!(tenant_id), json!(client_id), json!(epoch)],
            ).await?;
            Ok(row.first().ok_or(TokenPortError::CorruptData)?.value != 0)
        })
    }

    fn token_principal_state<'a>(
        &'a self,
        tenant_id: Uuid,
        client_epoch: i64,
        user_id: Option<Uuid>,
        subject: &'a str,
    ) -> TokenFuture<'a, TokenPrincipalState> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            #[derive(Deserialize)]
            struct Row {
                epoch: Option<i64>,
                owner: Option<Uuid>,
            }
            let row=self.database.query::<Row>("SELECT (SELECT epoch FROM nazo_users WHERE tenant_id=?1 AND id=?2) AS epoch,(SELECT user_id FROM nazo_subjects WHERE tenant_id=?1 AND subject=?3) AS owner",vec![json!(self.tenant_id),json!(user_id),json!(subject)]).await?.pop().ok_or(TokenPortError::CorruptData)?;
            if row.owner.is_some() && row.owner != user_id {
                return Err(TokenPortError::CorruptData);
            }
            Ok(TokenPrincipalState {
                client_epoch,
                user_epoch: user_id.map(|_| row.epoch.unwrap_or(0)),
                subject_bound: row.owner.is_some(),
            })
        })
    }
    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        Box::pin(async move { self.commit_token(input).await })
    }
    fn single_use_redemption<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            #[derive(Deserialize)]
            struct Row {
                holder: Option<String>,
                jti: String,
                expires_at: i64,
                family_id: Option<Uuid>,
            }
            self.database.query::<Row>(&format!("SELECT holder,jti,expires_at,family_id FROM nazo_redemptions WHERE tenant_id=?1 AND client_id=?2 AND grant_hash=?3 AND retain_until>{NOW}"),vec![json!(self.tenant_id),json!(client_id),json!(digest(grant_key))]).await?.into_iter().next().map(|row|{
                let holder=row.holder.map(|holder|{let value=serde_json::from_str(&holder).map_err(|_|TokenPortError::CorruptData)?;nazo_auth::AuthorizationCodeHolderEvidence::from_persisted(value).ok_or(TokenPortError::CorruptData)}).transpose()?;
                Ok(SingleUseRedemption{authorization_code_holder:holder,access_token_jti:row.jti,access_token_expires_at:timestamp(row.expires_at)?,refresh_token_family_id:row.family_id})
            }).transpose()
        })
    }
    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        verified_claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            if Uuid::parse_str(&verified_claims.tenant_id).ok() != Some(tenant_id)
                || verified_claims.subject_type != "user"
            {
                return Ok(None);
            }
            let legacy = match (verified_claims.client_epoch, verified_claims.user_epoch) {
                (None, None) => true,
                (Some(client), Some(user)) if client >= 0 && user >= 0 => false,
                _ => return Ok(None),
            };
            let user = match verified_claims.user_id.as_deref().map(Uuid::parse_str) {
                Some(Ok(user)) => Some(user),
                Some(Err(_)) if !legacy => return Ok(None),
                _ => None,
            };
            // D1 stores reusable subject bindings; no issuance ownership row is
            // needed for its tokens. All current authority and response facts
            // come from this one statement snapshot.
            let Some(row) = self.database.query::<Value>(
                "SELECT u.id AS userinfo_user_id,u.claims AS userinfo_claims, \
                 c.active AS userinfo_client_active,c.registration AS userinfo_client_registration \
                 FROM nazo_users u LEFT JOIN nazo_clients c ON c.tenant_id=u.tenant_id AND c.client_id=?4 \
                 WHERE u.tenant_id=?1 AND u.id=COALESCE(?2,(SELECT user_id FROM nazo_subjects WHERE tenant_id=?1 AND subject=?3)) AND u.active=1 \
                 AND NOT EXISTS(SELECT 1 FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash=?5) \
                 AND (?6 OR (c.active=1 AND c.epoch=?7 AND u.epoch=?8))",
                vec![json!(self.tenant_id),json!(user),json!(verified_claims.sub),
                    json!(verified_claims.client_id),json!(digest(&verified_claims.jti)),
                    json!(legacy),json!(verified_claims.client_epoch),json!(verified_claims.user_epoch)],
            ).await?.into_iter().next() else {
                return Ok(None);
            };
            let user_id = row
                .get("userinfo_user_id")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or(TokenPortError::CorruptData)?;
            let claims = row
                .get("userinfo_claims")
                .and_then(Value::as_str)
                .ok_or(TokenPortError::CorruptData)?;
            let subject: nazo_identity::SubjectClaims =
                serde_json::from_str(claims).map_err(|_| TokenPortError::CorruptData)?;
            if subject.subject.as_uuid() != user_id {
                return Err(TokenPortError::CorruptData);
            }
            let client = if row
                .get("userinfo_client_active")
                .is_some_and(Value::is_null)
            {
                None
            } else {
                let active = row
                    .get("userinfo_client_active")
                    .and_then(Value::as_i64)
                    .ok_or(TokenPortError::CorruptData)?;
                let registration = row
                    .get("userinfo_client_registration")
                    .and_then(Value::as_str)
                    .ok_or(TokenPortError::CorruptData)?;
                let registration: UserinfoRegistration =
                    serde_json::from_str(registration).map_err(|_| TokenPortError::CorruptData)?;
                if registration.client_id != verified_claims.client_id {
                    return Err(TokenPortError::CorruptData);
                }
                registration
                    .security_policy
                    .validate()
                    .map_err(|_| TokenPortError::CorruptData)?;
                Some(UserinfoClient {
                    is_active: active != 0,
                    signed_response_alg: registration.userinfo_signed_response_alg,
                    encrypted_response_alg: registration.userinfo_encrypted_response_alg,
                    encrypted_response_enc: registration.userinfo_encrypted_response_enc,
                    jwks_uri: registration.jwks_uri,
                    jwks: registration.jwks,
                    require_fapi2: registration.security_policy.requires_fapi2_security(),
                })
            };
            Ok(Some(UserinfoSnapshot { subject, client }))
        })
    }
    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            Ok(self
                .read_refresh(raw_token, None, Timestamp::now(), false)
                .await?
                .map(|snapshot| snapshot.presented))
        })
    }
    fn refresh_token_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
        client_id: Uuid,
        retry_started_at: Timestamp,
        prepare_oidc_subject: bool,
    ) -> TokenFuture<'a, Option<RefreshTokenSnapshot>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            self.read_refresh(
                raw_token,
                Some(client_id),
                retry_started_at,
                prepare_oidc_subject,
            )
            .await
        })
    }
    fn active_subject_claims<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        token_subject: &'a str,
    ) -> TokenFuture<'a, Option<PreparedTokenSubject>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            self.subject(user_id, token_subject).await
        })
    }
    fn active_subject_id(&self, tenant_id: Uuid, user_id: Uuid) -> TokenFuture<'_, Option<Uuid>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            #[derive(Deserialize)]
            struct Id {
                id: Uuid,
            }
            Ok(self
                .database
                .query::<Id>(
                    "SELECT id FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| row.id))
        })
    }
    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        _jti: &'a str,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            #[derive(Deserialize)]
            struct Id {
                id: Uuid,
            }
            Ok(self.database.query::<Id>("SELECT u.id FROM nazo_subjects b JOIN nazo_users u ON u.tenant_id=b.tenant_id AND u.id=b.user_id WHERE b.tenant_id=?1 AND b.subject=?2 AND u.active=1",vec![json!(self.tenant_id),json!(subject)]).await?.pop().map(|row|row.id))
        })
    }
    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<Timestamp>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let mut statements = Vec::new();
            if let Some(expiry) = access_token_expires_at {
                // A different owner must violate NOT NULL and abort the whole
                // batch, rather than silently extending another client's JTI.
                statements.push(Statement::new("INSERT INTO nazo_revocations(tenant_id,jti_hash,client_id,expires_at) VALUES(?1,?2,?3,?4) ON CONFLICT(tenant_id,jti_hash) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at),client_id=CASE WHEN nazo_revocations.client_id=excluded.client_id THEN nazo_revocations.client_id ELSE NULL END",vec![json!(self.tenant_id),json!(digest(access_token_jti)),json!(client_id),json!(expiry.as_microsecond()+nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS*1_000_000)]));
                statements.push(Statement::new("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash=?2 AND client_id=?3 AND expires_at>=?4) THEN 1 ELSE json('access revocation was not committed') END",vec![json!(self.tenant_id),json!(digest(access_token_jti)),json!(client_id),json!(expiry.as_microsecond()+nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS*1_000_000)]));
            }
            if let Some(family) = refresh_token_family_id {
                statements.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND client_id=?2 AND id=?3"),vec![json!(self.tenant_id),json!(client_id),json!(family)]));
                statements.push(Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND id=?3 AND revoked_at IS NULL) THEN 1 ELSE json('refresh revocation was not committed') END",vec![json!(self.tenant_id),json!(client_id),json!(family)]));
            }
            if !statements.is_empty() {
                self.database.batch(statements).await?;
            }
            Ok(())
        })
    }
    fn access_token_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            self.revocation(nazo_resource_server::RevocationLookupKey {
                client_id: &claims.client_id,
                subject: &claims.sub,
                user_id: claims.user_id.as_deref(),
                subject_type: Some(&claims.subject_type),
                client_epoch: claims.client_epoch,
                user_epoch: claims.user_epoch,
                tenant_id: &claims.tenant_id,
                jti: &claims.jti,
            })
            .await
        })
    }
    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            Ok(self.database.query::<Flag>(&format!("SELECT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND id=?2 AND user_id=?3 AND revoked_at IS NULL AND expires_at>{NOW}) AS value"),vec![json!(self.tenant_id),json!(family_id),json!(user_id)]).await?.first().is_some_and(|row|row.value!=0))
        })
    }
    fn revoke_token_with_audit<'a>(
        &'a self,
        input: nazo_auth::TokenRevocation<'a>,
        client_public_id: &'a str,
        source_ip_hash: &'a str,
    ) -> TokenFuture<'a, usize> {
        Box::pin(async move {
            self.require_tenant(input.tenant_id)?;
            let event = Uuid::new_v4();
            let payload = json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"tenant_id":self.tenant_id,"client_id":client_public_id,"source_ip_hash":source_ip_hash});
            let mut statements = vec![Statement::new(
                format!(
                    "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) VALUES(?1,?2,'token_revoked','token_lifecycle',{NOW},?3)"
                ),
                vec![
                    json!(self.tenant_id),
                    json!(event),
                    json!(encode(&payload)?),
                ],
            )];
            if let Some(access) = input.access_token {
                // The same owner guard also rolls back the required audit.
                statements.push(Statement::new("INSERT INTO nazo_revocations(tenant_id,jti_hash,client_id,expires_at) VALUES(?1,?2,?3,?4) ON CONFLICT(tenant_id,jti_hash) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at),client_id=CASE WHEN nazo_revocations.client_id=excluded.client_id THEN nazo_revocations.client_id ELSE NULL END RETURNING jti_hash",vec![json!(self.tenant_id),json!(digest(&access.jti)),json!(input.client_id),json!(access.expires_at.as_microsecond()+nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS*1_000_000)]));
                statements.push(Statement::new("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash=?2 AND client_id=?3 AND expires_at>=?4) THEN 1 ELSE json('access revocation was not committed') END",vec![json!(self.tenant_id),json!(digest(&access.jti)),json!(input.client_id),json!(access.expires_at.as_microsecond()+nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS*1_000_000)]));
            } else {
                statements.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND client_id=?2 AND (token_hash=?3 OR id=(SELECT family_id FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash=?3)) RETURNING id"),vec![json!(self.tenant_id),json!(input.client_id),json!(digest(input.raw_token))]));
                statements.push(Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND (token_hash=?3 OR id=(SELECT family_id FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash=?3)) AND revoked_at IS NULL) THEN 1 ELSE json('refresh revocation was not committed') END",vec![json!(self.tenant_id),json!(input.client_id),json!(digest(input.raw_token))]));
            }
            statements.push(Statement::new("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='token_revoked' AND category='token_lifecycle' AND payload=?3) THEN 1 ELSE json('revocation audit was not committed') END",vec![json!(self.tenant_id),json!(event),json!(encode(&payload)?)]));
            Ok(self
                .database
                .batch(statements)
                .await?
                .get(1)
                .map_or(0, |result| result.rows.len()))
        })
    }
}

impl D1Provider {
    async fn revocation(
        &self,
        key: nazo_resource_server::RevocationLookupKey<'_>,
    ) -> Result<bool, TokenPortError> {
        if key.tenant_id != self.tenant_id.to_string() {
            return Ok(true);
        }
        if key.client_epoch.is_none() {
            if key.user_epoch.is_some() {
                return Ok(true);
            }
            // Standalone OpenID4VCI pre-authorized grants, like native tokens
            // predating principal epochs, use individual JTI revocation here.
            // Their issuer-owned access record and active subject are checked
            // by the shared credential service, not fabricated as OAuth epochs.
            return Ok(self
                .database
                .query::<Flag>(
                    "SELECT EXISTS(SELECT 1 FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash=?2) AS value",
                    vec![json!(self.tenant_id), json!(digest(key.jti))],
                )
                .await?
                .first()
                .ok_or(TokenPortError::CorruptData)?
                .value
                != 0);
        }
        Ok(self.database.query::<Flag>("SELECT EXISTS(SELECT 1 FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash=?2) OR NOT EXISTS(SELECT 1 FROM nazo_clients c LEFT JOIN nazo_users u ON ?7='user' AND u.tenant_id=c.tenant_id AND u.id=COALESCE(?6,(SELECT user_id FROM nazo_subjects WHERE tenant_id=?1 AND subject=?5)) WHERE c.tenant_id=?1 AND c.client_id=?3 AND c.active=1 AND c.epoch=?4 AND ((?7='client' AND ?6 IS NULL AND ?8 IS NULL) OR (?7='user' AND u.active=1 AND u.epoch=?8))) AS value",vec![json!(self.tenant_id),json!(digest(key.jti)),json!(key.client_id),json!(key.client_epoch),json!(key.subject),json!(key.user_id),json!(key.subject_type),json!(key.user_epoch)]).await?.first().ok_or(TokenPortError::CorruptData)?.value!=0)
    }
}
impl nazo_resource_server::AccessTokenRevocationLookup for D1Provider {
    fn is_revoked<'a>(
        &'a self,
        key: nazo_resource_server::RevocationLookupKey<'a>,
    ) -> nazo_resource_server::ResourceServerPortFuture<
        'a,
        Result<bool, nazo_resource_server::ProtectedResourceDependencyError>,
    > {
        Box::pin(async move {
            self.revocation(key).await.map_err(|_| {
                nazo_resource_server::ProtectedResourceDependencyError::RevocationLookupUnavailable
            })
        })
    }
}

impl D1Provider {
    async fn commit_token(
        &self,
        input: CommitTokenIssuance,
    ) -> Result<CommitTokenIssuanceResult, TokenPortError> {
        use nazo_auth::TokenIssuanceMode;
        self.require_tenant(input.tenant_id)?;
        if let Some(source) = &input.native_sso_source
            && (source.tenant_id != input.tenant_id
                || Some(source.user_id) != input.user_id
                || source.family_id.is_nil()
                || source.source_client_id.is_empty()
                || !matches!(input.mode, TokenIssuanceMode::Fresh)
                || !matches!(
                    input.refresh_token,
                    Some(RefreshTokenCommit::IssueNew { .. })
                ))
        {
            return Err(TokenPortError::CorruptData);
        }
        if input.issuance_id.is_nil()
            || input.tenant_id.is_nil()
            || input.client_id.is_nil()
            || input.access_token_jti.trim().is_empty()
            || input.subject.is_empty()
            || input.subject.chars().count() > 255
            || input.principal_state.client_epoch < 0
            || input
                .principal_state
                .user_epoch
                .is_some_and(|epoch| epoch < 0)
            || input.principal_state.user_epoch.is_some() != input.user_id.is_some()
        {
            return Err(TokenPortError::CorruptData);
        }
        let (grant_hash, grant_expiry, holder) = match &input.mode {
            TokenIssuanceMode::Fresh => (None, None, None),
            TokenIssuanceMode::SingleUse {
                grant_key,
                grant_expires_at,
            } => {
                if grant_key.trim().is_empty() || grant_key.starts_with("authorization_code:") {
                    return Err(TokenPortError::CorruptData);
                }
                (
                    Some(digest(grant_key)),
                    Some(grant_expires_at.as_microsecond()),
                    None,
                )
            }
            TokenIssuanceMode::AuthorizationCode {
                code_identity,
                grant_expires_at,
                holder,
            } => {
                if !code_identity.starts_with("authorization_code:v2:") {
                    return Err(TokenPortError::CorruptData);
                }
                (
                    Some(digest(code_identity)),
                    Some(grant_expires_at.as_microsecond()),
                    Some(encode(holder)?),
                )
            }
        };
        let access_expiry = Timestamp::from_second(input.access_token_expires_at)
            .map_err(|_| TokenPortError::CorruptData)?
            .as_microsecond();
        let retain_until = grant_expiry.unwrap_or(0).max(
            access_expiry + nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS * 1_000_000,
        );
        let mut plan = json!({"client":input.client_id,"user":input.user_id,"client_epoch":input.principal_state.client_epoch,"user_epoch":input.principal_state.user_epoch,"subject":input.subject,"grant":grant_hash,"grant_expiry":grant_expiry,"holder":holder,"jti":input.access_token_jti,"access_expiry":access_expiry,"retain_until":retain_until,"family":null,"refresh":"none","rotate":false});
        if let Some(source) = &input.native_sso_source {
            plan["native_family"] = json!(source.family_id);
            plan["native_client"] = json!(source.source_client_id);
            plan["native_expiry"] = json!(source.device_secret_expires_at.as_microsecond());
        }
        let mut prune_limit = None;
        if let Some(refresh) = &input.refresh_token {
            let valid_audiences = |values: &[String]| {
                !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
            };
            if refresh.contract().subject != input.subject
                || refresh.contract().subject.trim().is_empty()
                || !refresh.contract().authentication_context.is_well_formed()
                || !valid_audiences(&refresh.contract().audiences)
            {
                return Err(TokenPortError::CorruptData);
            }
            let (expected_tenant, expected_client, expected_user) = match refresh {
                RefreshTokenCommit::IssueNew { token, .. } => {
                    (token.tenant_id, token.client_id, token.user_id)
                }
                RefreshTokenCommit::UseExisting { authority, .. } => {
                    (authority.tenant_id, authority.client_id, authority.user_id)
                }
            };
            if expected_tenant != self.tenant_id
                || expected_client != input.client_id
                || expected_user != input.user_id
            {
                return Err(TokenPortError::CorruptData);
            }
            let contract = encode(refresh.contract())?;
            plan["family"] = json!(refresh.family_id());
            plan["contract"] = json!(contract);
            match refresh {
                RefreshTokenCommit::IssueNew {
                    token,
                    contract: original_contract,
                } => {
                    if token.rotated_from_id.is_some()
                        || token.lost_response_retry.is_some()
                        || token.audiences != original_contract.audiences
                        || original_contract.authentication_context.version
                            != nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION
                    {
                        return Err(TokenPortError::CorruptData);
                    }
                    plan["refresh"] = json!("new");
                    plan["contract_hash"] = json!(digest(&contract));
                }
                RefreshTokenCommit::UseExisting {
                    authority,
                    rotation,
                } => {
                    if !matches!(input.mode, TokenIssuanceMode::Fresh) {
                        return Err(TokenPortError::CorruptData);
                    }
                    if authority.family_id.is_nil()
                        || authority.member_id.is_nil()
                        || authority
                            .id_token_sid
                            .as_deref()
                            .is_some_and(|sid| sid.trim().is_empty())
                        || !valid_audiences(&authority.current_audiences)
                        || !nazo_auth::is_subset(
                            &authority.current_audiences,
                            &refresh.contract().audiences,
                        )
                    {
                        return Err(TokenPortError::CorruptData);
                    }
                    plan["refresh"] = json!("existing");
                    plan["contract_hash"] =
                        json!(blake3::Hash::from(authority.contract_key).to_hex().as_str());
                    plan["source_id"] = json!(authority.member_id);
                    plan["source_hash"] =
                        json!(blake3::Hash::from(authority.token_blake3).to_hex().as_str());
                    let expected = Member {
                        id: authority.member_id,
                        audience: authority.current_audiences.clone(),
                        issued_at: 0,
                        expires_at: authority.expires_at.as_microsecond(),
                        id_token_sid: authority.id_token_sid.clone(),
                        dpop_jkt: authority.dpop_jkt.clone(),
                        mtls_x5t_s256: authority.mtls_x5t_s256.clone(),
                        client_attestation_jkt: authority.client_attestation_jkt.clone(),
                    };
                    plan["source_member"] = json!(encode(&expected)?);
                    plan["rotate"] = json!(rotation.is_some());
                    if let Some(token) = rotation {
                        if token.rotated_from_id != Some(authority.member_id)
                            || token.family_id != authority.family_id
                            || token.tenant_id != authority.tenant_id
                            || token.client_id != authority.client_id
                            || token.user_id != authority.user_id
                            || !nazo_auth::is_subset(&token.audiences, &authority.current_audiences)
                            || token.dpop_jkt != authority.dpop_jkt
                            || token.mtls_x5t_s256 != authority.mtls_x5t_s256
                            || token.client_attestation_jkt != authority.client_attestation_jkt
                        {
                            return Err(TokenPortError::CorruptData);
                        }
                        if let Some(retry) = token.lost_response_retry {
                            plan["retry_hash"] =
                                json!(blake3::Hash::from(retry.original_blake3).to_hex().as_str());
                            plan["retry_id"] = json!(retry.original_id);
                            plan["retry_started"] = json!(retry.retry_started_at.as_microsecond());
                        }
                        #[derive(Deserialize)]
                        struct Classification {
                            client_type: String,
                        }
                        let row=self.database.query::<Classification>("SELECT json_extract(registration,'$.client_type') AS client_type FROM nazo_clients WHERE tenant_id=?1 AND id=?2",vec![json!(self.tenant_id),json!(input.client_id)]).await?.pop().ok_or(TokenPortError::Unavailable)?;
                        prune_limit = nazo_auth::refresh_spent_proof_limit(
                            &row.client_type,
                            authority.dpop_jkt.as_deref(),
                            authority.mtls_x5t_s256.as_deref(),
                        );
                        plan["client_type"] = json!(row.client_type);
                    }
                }
            }
            if let Some(token) = refresh.token() {
                if token.family_id.is_nil()
                    || token.member_id.is_nil()
                    || token.raw_token.is_empty()
                    || token
                        .id_token_sid
                        .as_deref()
                        .is_some_and(|sid| sid.trim().is_empty())
                    || !valid_audiences(&token.audiences)
                    || refresh.contract().authentication_context.auth_time
                        > token.issued_at.as_second()
                    || token.expires_at <= token.issued_at
                {
                    return Err(TokenPortError::CorruptData);
                }
                plan["new_member"] = json!(encode(&Member::new(token))?);
                plan["new_id"] = json!(token.member_id);
                plan["new_hash"] = json!(digest(&token.raw_token));
                plan["new_expiry"] = json!(token.expires_at.as_microsecond());
                plan["issued_at"] = json!(token.issued_at.as_microsecond());
            }
        }
        if input.authorization_id.is_some_and(|id| {
            id != input
                .refresh_token
                .as_ref()
                .map(RefreshTokenCommit::family_id)
                .unwrap_or(input.issuance_id)
        }) {
            return Err(TokenPortError::CorruptData);
        }
        let payload = json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"tenant_id":self.tenant_id,"issuance_id":input.issuance_id,"event_category":"token_lifecycle","user_id":input.user_id,"client_id":input.audit_fields.client_id,"subject_hash":input.audit_fields.subject_hash,"scope":input.audit_fields.scope,"audience":input.audit_fields.audience,"access_token_jti":input.access_token_jti,"refresh_token_family_id":input.refresh_token.as_ref().map(RefreshTokenCommit::family_id),"rotated_from_id":input.refresh_token.as_ref().and_then(RefreshTokenCommit::token).and_then(|token|token.rotated_from_id)});
        plan["audit"] = json!(encode(&payload)?);
        let params: std::sync::Arc<[Value]> = vec![
            json!(self.tenant_id),
            json!(input.issuance_id),
            json!(encode(&plan)?),
        ]
        .into();
        let client_ok = "EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=json_extract(?3,'$.client') AND active=1 AND epoch=json_extract(?3,'$.client_epoch') AND (json_extract(?3,'$.client_type') IS NULL OR json_extract(registration,'$.client_type')=json_extract(?3,'$.client_type')))";
        let user_ok = "(json_extract(?3,'$.user') IS NULL OR EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=json_extract(?3,'$.user') AND active=1 AND epoch=json_extract(?3,'$.user_epoch'))) AND NOT EXISTS(SELECT 1 FROM nazo_subjects WHERE tenant_id=?1 AND subject=json_extract(?3,'$.subject') AND user_id IS NOT json_extract(?3,'$.user'))";
        let grant_ok = format!(
            "(json_extract(?3,'$.grant') IS NULL OR (json_extract(?3,'$.grant_expiry')>{NOW} AND NOT EXISTS(SELECT 1 FROM nazo_redemptions WHERE tenant_id=?1 AND client_id=json_extract(?3,'$.client') AND grant_hash=json_extract(?3,'$.grant'))))"
        );
        let source_ok = "f.member_id=json_extract(?3,'$.source_id') AND f.token_hash=json_extract(?3,'$.source_hash') AND f.client_id=json_extract(?3,'$.client') AND f.user_id IS json_extract(?3,'$.user') AND f.contract_hash=json_extract(?3,'$.contract_hash') AND f.contract=json_extract(?3,'$.contract') AND json_remove(f.member,'$.issued_at')=json_remove(json_extract(?3,'$.source_member'),'$.issued_at') AND (json_extract(?3,'$.retry_hash') IS NULL OR EXISTS(SELECT 1 FROM nazo_refresh_spent s WHERE s.tenant_id=?1 AND s.family_id=f.id AND s.token_hash=json_extract(?3,'$.retry_hash') AND s.member_id=json_extract(?3,'$.retry_id') AND s.successor_id=f.member_id AND json_extract(?3,'$.retry_started') BETWEEN s.spent_at AND s.spent_at+60000000))";
        let refresh_ok = format!(
            "(json_extract(?3,'$.refresh')='none' OR (json_extract(?3,'$.refresh')='new' AND NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND id=json_extract(?3,'$.family'))) OR (json_extract(?3,'$.refresh')='existing' AND EXISTS(SELECT 1 FROM nazo_refresh_families f WHERE f.tenant_id=?1 AND f.id=json_extract(?3,'$.family') AND f.revoked_at IS NULL AND f.expires_at>{NOW} AND {source_ok})))"
        );
        // D1 holds this primary transaction across the source check and all
        // destination writes. Member rotation does not invalidate the family;
        // concurrent source revocation cannot interleave after this fence.
        // The same transaction may then retire its source under the family cap.
        let native_sso_ok = format!(
            "(json_extract(?3,'$.native_family') IS NULL OR (json_extract(?3,'$.native_expiry')>{NOW} AND EXISTS(SELECT 1 FROM nazo_refresh_families f JOIN nazo_clients c ON c.tenant_id=f.tenant_id AND c.id=f.client_id WHERE f.tenant_id=?1 AND f.id=json_extract(?3,'$.native_family') AND f.user_id=json_extract(?3,'$.user') AND c.client_id=json_extract(?3,'$.native_client') AND f.revoked_at IS NULL AND f.expires_at>{NOW})))"
        );
        let gate = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='token_issued')";
        let reuse_gate = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='refresh_reuse_detected')";
        let admission = format!(
            "{client_ok} AND {user_ok} AND {grant_ok} AND {refresh_ok} AND {native_sso_ok}"
        );
        let reuse_admission = format!(
            "EXISTS(SELECT 1 FROM nazo_refresh_families f WHERE f.tenant_id=?1 AND f.id=json_extract(?3,'$.family') AND f.revoked_at IS NULL AND f.expires_at>{NOW} AND f.client_id=json_extract(?3,'$.client') AND f.user_id IS json_extract(?3,'$.user') AND {client_ok} AND {user_ok} AND NOT ({source_ok}))"
        );
        let mut effects = vec!["EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='token_issued' AND category='token_lifecycle' AND payload=json_extract(?3,'$.audit'))".to_owned()];
        let mut batch = Vec::new();
        if plan["rotate"] == true {
            batch.push(Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,'refresh_reuse_detected','token_replay',{NOW},json_extract(?3,'$.audit') WHERE ({reuse_admission}) OR {reuse_gate}"),params.clone()));
            batch.push(Statement::new(format!("SELECT CASE WHEN NOT ({reuse_gate}) OR changes()=1 THEN 1 ELSE json('refresh reuse audit was not inserted') END"),vec![json!(self.tenant_id),json!(input.issuance_id)]));
            batch.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND id=json_extract(?3,'$.family') AND {reuse_gate}"),params.clone()));
        }
        // An old event can never authorize this batch: force its UNIQUE
        // constraint to abort even when this attempt's admission is false.
        batch.push(Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,'token_issued','token_lifecycle',{NOW},json_extract(?3,'$.audit') WHERE ({admission}) OR {gate}"),params.clone()));
        batch.push(Statement::new(format!("SELECT CASE WHEN NOT ({gate}) OR changes()=1 THEN 1 ELSE json('token issuance audit was not inserted') END"),vec![json!(self.tenant_id),json!(input.issuance_id)]));
        if grant_hash.is_some() {
            batch.push(Statement::new(format!("INSERT INTO nazo_redemptions(tenant_id,client_id,grant_hash,issuance_id,holder,jti,expires_at,family_id,retain_until) SELECT ?1,json_extract(?3,'$.client'),json_extract(?3,'$.grant'),?2,json_extract(?3,'$.holder'),json_extract(?3,'$.jti'),json_extract(?3,'$.access_expiry'),json_extract(?3,'$.family'),json_extract(?3,'$.retain_until') WHERE {gate}"),params.clone()));
            effects.push("EXISTS(SELECT 1 FROM nazo_redemptions WHERE tenant_id=?1 AND client_id=json_extract(?3,'$.client') AND grant_hash=json_extract(?3,'$.grant') AND issuance_id=?2 AND holder IS json_extract(?3,'$.holder') AND jti=json_extract(?3,'$.jti') AND expires_at=json_extract(?3,'$.access_expiry') AND family_id IS json_extract(?3,'$.family') AND retain_until=json_extract(?3,'$.retain_until'))".into());
        }
        if input
            .user_id
            .is_some_and(|id| input.subject != id.to_string())
        {
            batch.push(Statement::new(format!("INSERT INTO nazo_subjects(tenant_id,subject,user_id) SELECT ?1,json_extract(?3,'$.subject'),json_extract(?3,'$.user') WHERE {gate} ON CONFLICT(tenant_id,subject) DO NOTHING"),params.clone()));
            effects.push("EXISTS(SELECT 1 FROM nazo_subjects WHERE tenant_id=?1 AND subject=json_extract(?3,'$.subject') AND user_id=json_extract(?3,'$.user'))".into());
        }
        match input.refresh_token.as_ref() {
            Some(RefreshTokenCommit::IssueNew { .. }) => {
                batch.push(Statement::new(format!("INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at) SELECT ?1,json_extract(?3,'$.family'),json_extract(?3,'$.client'),json_extract(?3,'$.user'),json_extract(?3,'$.contract'),json_extract(?3,'$.contract_hash'),json_extract(?3,'$.new_member'),json_extract(?3,'$.new_id'),json_extract(?3,'$.new_hash'),json_extract(?3,'$.issued_at'),json_extract(?3,'$.new_expiry') WHERE {gate}"),params.clone()));
                batch.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND id IN(SELECT id FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=json_extract(?3,'$.client') AND user_id IS json_extract(?3,'$.user') AND revoked_at IS NULL AND expires_at>{NOW} ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET {}) AND {gate}",nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE),params.clone()));
                effects.push(format!("(SELECT count(*) FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=json_extract(?3,'$.client') AND user_id IS json_extract(?3,'$.user') AND revoked_at IS NULL AND expires_at>{NOW})<={}",nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE));
            }
            Some(RefreshTokenCommit::UseExisting {
                rotation: Some(_), ..
            }) => {
                batch.push(Statement::new(format!("INSERT INTO nazo_refresh_spent(tenant_id,token_hash,family_id,member_id,successor_id,spent_at,expires_at) SELECT tenant_id,token_hash,id,member_id,json_extract(?3,'$.new_id'),{NOW},expires_at FROM nazo_refresh_families WHERE tenant_id=?1 AND id=json_extract(?3,'$.family') AND {gate}"),params.clone()));
                // Verify the new edge before applying the shared bounded-history policy.
                batch.push(Statement::new(format!("SELECT CASE WHEN NOT ({gate}) OR (changes()=1 AND EXISTS(SELECT 1 FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash=json_extract(?3,'$.source_hash') AND family_id=json_extract(?3,'$.family') AND member_id=json_extract(?3,'$.source_id') AND successor_id=json_extract(?3,'$.new_id') AND expires_at=json_extract(json_extract(?3,'$.source_member'),'$.expires_at'))) THEN 1 ELSE json('refresh spent proof was not inserted') END"),params.clone()));
                batch.push(Statement::new(format!("UPDATE nazo_refresh_families SET member=json_extract(?3,'$.new_member'),member_id=json_extract(?3,'$.new_id'),token_hash=json_extract(?3,'$.new_hash'),expires_at=json_extract(?3,'$.new_expiry') WHERE tenant_id=?1 AND id=json_extract(?3,'$.family') AND {gate}"),params.clone()));
                if let Some(limit) = prune_limit {
                    batch.push(Statement::new(format!("DELETE FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash IN(SELECT token_hash FROM nazo_refresh_spent WHERE tenant_id=?1 AND family_id=json_extract(?3,'$.family') ORDER BY spent_at DESC,member_id DESC LIMIT -1 OFFSET {limit}) AND {gate}"),params.clone()));
                    effects.push(format!("(SELECT count(*) FROM nazo_refresh_spent WHERE tenant_id=?1 AND family_id=json_extract(?3,'$.family'))<={limit}"));
                }
            }
            _ => {}
        }
        if input
            .refresh_token
            .as_ref()
            .and_then(RefreshTokenCommit::token)
            .is_some()
        {
            effects.push("EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND id=json_extract(?3,'$.family') AND client_id=json_extract(?3,'$.client') AND user_id IS json_extract(?3,'$.user') AND contract=json_extract(?3,'$.contract') AND contract_hash=json_extract(?3,'$.contract_hash') AND member=json_extract(?3,'$.new_member') AND member_id=json_extract(?3,'$.new_id') AND token_hash=json_extract(?3,'$.new_hash') AND expires_at=json_extract(?3,'$.new_expiry'))".into());
        }
        let unchanged = if plan["rotate"] == true {
            format!("NOT ({admission}) AND NOT ({reuse_admission})")
        } else {
            format!("NOT ({admission})")
        };
        // A committed audit admits the writes; the final predicate proves their
        // effects before D1 commits, including replay evidence and family caps.
        batch.push(Statement::new(format!("SELECT CASE WHEN (CASE
            WHEN {gate} THEN ({})
            WHEN {reuse_gate} THEN EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND id=json_extract(?3,'$.family') AND client_id=json_extract(?3,'$.client') AND user_id IS json_extract(?3,'$.user') AND revoked_at IS NOT NULL)
            ELSE ({unchanged}) END) THEN 1 ELSE json('token issuance atomicity failure') END AS checked", effects.join(" AND ")),params.clone()));
        batch.push(Statement::new(format!("SELECT CASE WHEN {gate} THEN 'committed' WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='refresh_reuse_detected') THEN 'reuse' WHEN NOT ({client_ok}) THEN 'client' WHEN NOT ({user_ok}) THEN 'user' WHEN json_extract(?3,'$.grant') IS NOT NULL AND json_extract(?3,'$.grant_expiry')<={NOW} THEN 'expired' WHEN json_extract(?3,'$.grant') IS NOT NULL AND EXISTS(SELECT 1 FROM nazo_redemptions WHERE tenant_id=?1 AND client_id=json_extract(?3,'$.client') AND grant_hash=json_extract(?3,'$.grant')) THEN 'used' ELSE 'refresh' END AS outcome"),params));
        let result = self.database.batch(batch).await?;
        match result
            .last()
            .and_then(|result| result.rows.first())
            .and_then(|row| row.get("outcome"))
            .and_then(Value::as_str)
        {
            Some("committed") => Ok(CommitTokenIssuanceResult::Committed),
            Some("reuse") => Ok(CommitTokenIssuanceResult::RotationConflict),
            Some("client") => Ok(CommitTokenIssuanceResult::ClientInactive),
            Some("user") => Ok(CommitTokenIssuanceResult::SubjectInactive),
            Some("expired") => Ok(CommitTokenIssuanceResult::GrantExpired),
            Some("used") => Ok(CommitTokenIssuanceResult::AlreadyUsed),
            Some("refresh") => Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable),
            _ => Err(TokenPortError::CorruptData),
        }
    }
}
