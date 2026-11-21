//! Audited dynamic client registration and compare-and-swap management authority.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, encode, validate_client_capabilities},
    rows::ClientRow,
};
use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError as Error,
    DynamicRegistrationFuture, OAuthClient, PreparedClientRegistration, RegistrationClientSnapshot,
};
use serde_json::{Value, json};
use uuid::Uuid;

impl From<DbError> for Error {
    fn from(_: DbError) -> Self {
        Self::Unavailable
    }
}

enum Mutation<'a> {
    Replace {
        client: &'a OAuthClient,
        secret: Option<&'a str>,
        token: Option<&'a str>,
        source: &'a str,
    },
    Rotate {
        secret: Option<&'a str>,
        token: &'a str,
    },
    Deactivate {
        source: &'a str,
    },
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl DynamicRegistrationClientStore for D1Provider {
    fn insert<'a>(
        &'a self,
        prepared: PreparedClientRegistration,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            let write = prepared.into_write();
            let client = write.client;
            self.require_tenant(client.tenant_id)?;
            validate_client_capabilities(&client).map_err(|_| Error::Unavailable)?;
            let token = write
                .registration_access_token_blake3
                .as_deref()
                .filter(|token| valid_hash(token))
                .ok_or(Error::Unavailable)?;
            if !valid_hash(source_ip_hash) || client.id.is_nil() || !client.is_active {
                return Err(Error::Unavailable);
            }
            let payload = json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "client_lifecycle", "tenant_id": client.tenant_id,
                "client_id": client.client_id, "client_type": client.client_type,
                "grant_types": client.grant_types, "token_endpoint_auth_method": client.token_endpoint_auth_method,
                "source_ip_hash": source_ip_hash,
            });
            let event = Uuid::new_v4();
            let payload = encode(&payload)?;
            let registration = encode(&client.registration)?;
            self.database.batch(vec![
                Statement::new("INSERT INTO nazo_clients(tenant_id,id,client_id,realm_id,organization_id,registration,secret_digest,epoch,active,require_mtls_bound_tokens) VALUES(?1,?2,?3,?4,?5,?6,?7,0,1,?8)", vec![json!(self.tenant_id), json!(client.id), json!(client.client_id), json!(client.realm_id), json!(client.organization_id), json!(registration), json!(write.client_secret_hash),json!(client.require_mtls_bound_tokens)]),
                Statement::new("INSERT INTO nazo_client_registrations(tenant_id,client_id,token_hash) VALUES(?1,?2,?3)", vec![json!(self.tenant_id), json!(client.id), json!(token)]),
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) VALUES(?1,?2,'dynamic_client_registered','client_lifecycle',{NOW},?3)"), vec![json!(self.tenant_id), json!(event), json!(payload)]),
                Statement::new("SELECT CASE WHEN
                    EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND client_id=?3 AND realm_id=?4 AND organization_id=?5 AND registration=?6 AND secret_digest IS ?7 AND epoch=0 AND active=1 AND require_mtls_bound_tokens=?8)
                    AND EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?2 AND token_hash=?9)
                    AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?10 AND event_type='dynamic_client_registered' AND category='client_lifecycle' AND payload=?11)
                    THEN 1 ELSE json('dynamic registration effects were not accepted') END",
                    vec![json!(self.tenant_id),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(registration),json!(write.client_secret_hash),json!(client.require_mtls_bound_tokens),json!(token),json!(event),json!(payload)]),
            ]).await?;
            Ok(client)
        })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<RegistrationClientSnapshot>> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            let row = self.database.query::<ClientRow>(
                "SELECT c.* FROM nazo_clients c JOIN nazo_client_registrations r ON r.tenant_id=c.tenant_id AND r.client_id=c.id WHERE c.tenant_id=?1 AND c.client_id=?2 AND c.active=1 AND r.token_hash=?3",
                vec![json!(tenant_id),json!(client_id),json!(token_hash)],
            ).await?.into_iter().next();
            row.map(|row| {
                let has_client_secret = row.secret_digest.is_some();
                let secret_salt = row
                    .secret_digest
                    .as_deref()
                    .and_then(|digest| digest.strip_prefix("client-secret-v1:"))
                    .and_then(|value| value.split_once(':'))
                    .map(|(salt, _)| salt.to_owned());
                Ok(RegistrationClientSnapshot {
                    client: row.into_domain()?,
                    has_client_secret,
                    secret_salt,
                })
            })
            .transpose()
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id)?;
            nazo_auth::AuthorizationRepositoryPort::client_secret_digest_matches(
                self,
                client_id,
                candidate_digest,
            )
            .await
            .map_err(|_| Error::Unavailable)
        })
    }

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            self.mutate_registration(
                tenant_id,
                client_id,
                expected_registration_access_token_hash,
                Mutation::Rotate {
                    secret: client_secret_hash,
                    token: new_registration_access_token_hash,
                },
            )
            .await
        })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            self.mutate_registration(
                client.tenant_id,
                client.id,
                expected_registration_access_token_hash,
                Mutation::Replace {
                    client,
                    secret: client_secret_hash,
                    token: new_registration_access_token_hash,
                    source: source_ip_hash,
                },
            )
            .await
        })
    }

    fn deactivate<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_registration_access_token_hash: &'a str,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            self.mutate_registration(
                tenant_id,
                client_id,
                expected_registration_access_token_hash,
                Mutation::Deactivate {
                    source: source_ip_hash,
                },
            )
            .await
            .map(|_| true)
        })
    }
}

impl D1Provider {
    async fn mutate_registration(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_token: &str,
        mutation: Mutation<'_>,
    ) -> Result<OAuthClient, Error> {
        self.require_tenant(tenant_id)?;
        if client_id.is_nil() || !valid_hash(expected_token) {
            return Err(Error::StaleCredentials);
        }
        let plan = match mutation {
            Mutation::Replace {
                client,
                secret,
                token,
                source,
            } => {
                validate_client_capabilities(client).map_err(|_| Error::Unavailable)?;
                if !valid_hash(source) || token.is_some_and(|token| !valid_hash(token)) {
                    return Err(Error::Unavailable);
                }
                json!({"event":"dynamic_client_configuration_updated", "registration":client.registration,
                    "secret":secret, "token":token, "source":source, "deactivate":false,"require_mtls_bound_tokens":client.require_mtls_bound_tokens})
            }
            Mutation::Rotate { secret, token } => {
                if !valid_hash(token) {
                    return Err(Error::Unavailable);
                }
                json!({"event":"dynamic_client_credentials_rotated", "secret":secret, "token":token, "deactivate":false})
            }
            Mutation::Deactivate { source } => {
                if !valid_hash(source) {
                    return Err(Error::Unavailable);
                }
                json!({"event":"dynamic_client_deleted", "source":source, "deactivate":true})
            }
        };
        let plan = encode(&plan)?;
        let event = Uuid::new_v4();
        // Audit admission and all effects execute in one D1 primary transaction.
        // Live scopes and administrator-owned policy are checked after acquiring
        // authority, so concurrent edits cannot re-expand a stale registration.
        let authority = "c.tenant_id=?1 AND c.id=?2 AND c.active=1 AND EXISTS(SELECT 1 FROM nazo_client_registrations r WHERE r.tenant_id=c.tenant_id AND r.client_id=c.id AND r.token_hash=?3)";
        // JSON object member order is not policy authority. Comparing typed
        // paths accepts equivalent serialization without equating true and 1.
        let policy_equal = "NOT EXISTS(SELECT fullkey,type,atom FROM json_tree(json_extract(c.registration,'$.security_policy')) EXCEPT SELECT fullkey,type,atom FROM json_tree(json_extract(?5,'$.registration.security_policy')))
            AND NOT EXISTS(SELECT fullkey,type,atom FROM json_tree(json_extract(?5,'$.registration.security_policy')) EXCEPT SELECT fullkey,type,atom FROM json_tree(json_extract(c.registration,'$.security_policy')))";
        let ceiling = format!(
            "json_extract(?5,'$.registration') IS NULL OR ({policy_equal} AND NOT EXISTS(SELECT 1 FROM json_each(?5,'$.registration.scopes') wanted WHERE NOT EXISTS(SELECT 1 FROM json_each(c.registration,'$.scopes') allowed WHERE allowed.value=wanted.value)))"
        );
        let admitted = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3 AND category='client_lifecycle')";
        let effect_params = || {
            vec![
                json!(tenant_id),
                json!(client_id),
                json!(event),
                json!(plan),
            ]
        };
        let mut outcomes = self.database.batch(vec![
            Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT ?1,?4,json_extract(?5,'$.event'),'client_lifecycle',{NOW},
                   json_object('schema_version','nazo.audit.v1','event_category','client_lifecycle',
                     'tenant_id',c.tenant_id,'client_id',c.client_id,
                     'client_type',json_extract(COALESCE(json_extract(?5,'$.registration'),c.registration),'$.client_type'),
                     'grant_types',json_extract(COALESCE(json_extract(?5,'$.registration'),c.registration),'$.grant_types'),
                     'token_endpoint_auth_method',json_extract(COALESCE(json_extract(?5,'$.registration'),c.registration),'$.token_endpoint_auth_method'),
                     'previous_client_type',json_extract(c.registration,'$.client_type'),
                     'previous_epoch',c.epoch,
                     'refresh_invalidation_reason',CASE WHEN json_extract(?5,'$.deactivate')=1 THEN 'client_deleted'
                       WHEN json_extract(?5,'$.registration.client_type')='public' AND json_extract(c.registration,'$.client_type')='confidential'
                       THEN 'client_authentication_class_downgrade' ELSE NULL END,
                     'source_ip_hash',json_extract(?5,'$.source'))
                 FROM nazo_clients c WHERE ({authority}) AND ({ceiling})
                 UNION ALL SELECT ?1,?4,'duplicate','client_lifecycle',{NOW},'{{}}' WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?4)"),
                vec![json!(tenant_id),json!(client_id),json!(expected_token),json!(event),json!(plan)]),
            // Keep the native per-family revocation evidence in the same
            // transaction. SQLite supplies non-secret UUID identifiers for a
            // set whose live membership must be read under this write lock.
            Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT tenant_id,lower(hex(randomblob(16))),'refresh_family_security_revoked','token_lifecycle',{NOW},
                   json_object('schema_version','nazo.audit.v1','tenant_id',tenant_id,'token_family_id',id,
                     'client_id',client_id,'event_category','token_lifecycle','reason','client_authentication_class_downgrade','mutation_id',?3)
                 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL AND {admitted}
                   AND json_extract(?4,'$.registration.client_type')='public'
                   AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND json_extract(registration,'$.client_type')='confidential')"), effect_params()),
            Statement::new(format!(
                "SELECT CASE WHEN NOT ({admitted}) OR NOT EXISTS(
                    SELECT 1 FROM nazo_refresh_families f WHERE f.tenant_id=?1 AND f.client_id=?2 AND f.revoked_at IS NULL
                    AND json_extract(?4,'$.registration.client_type')='public'
                    AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND json_extract(registration,'$.client_type')='confidential')
                    AND NOT EXISTS(SELECT 1 FROM nazo_audit a WHERE a.tenant_id=f.tenant_id AND a.event_type='refresh_family_security_revoked' AND a.category='token_lifecycle'
                        AND json_extract(a.payload,'$.mutation_id')=?3 AND json_extract(a.payload,'$.token_family_id')=f.id
                        AND json_extract(a.payload,'$.client_id')=f.client_id AND json_extract(a.payload,'$.reason')='client_authentication_class_downgrade'))
                    THEN 1 ELSE json('dynamic registration revocation audit was not accepted') END"),effect_params()),
            Statement::new(format!(
                "UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL AND {admitted}
                 AND (json_extract(?4,'$.deactivate')=1 OR (json_extract(?4,'$.registration.client_type')='public'
                 AND EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?2 AND json_extract(registration,'$.client_type')='confidential')))"), effect_params()),
            Statement::new(format!(
                "UPDATE nazo_clients SET
                   registration=CASE WHEN json_extract(?4,'$.registration') IS NULL THEN registration ELSE
                     json_set(json_extract(?4,'$.registration'),'$.client_id',client_id,'$.allowed_audiences',json_extract(registration,'$.allowed_audiences'),'$.security_policy',json_extract(registration,'$.security_policy')) END,
                   secret_digest=CASE WHEN json_extract(?4,'$.deactivate')=1 THEN NULL ELSE json_extract(?4,'$.secret') END,
                   require_mtls_bound_tokens=COALESCE(json_extract(?4,'$.require_mtls_bound_tokens'),require_mtls_bound_tokens),
                   epoch=epoch+json_extract(?4,'$.deactivate'), active=1-json_extract(?4,'$.deactivate')
                 WHERE tenant_id=?1 AND id=?2 AND {admitted}"), effect_params()),
            Statement::new(format!(
                "UPDATE nazo_client_registrations SET token_hash=json_extract(?4,'$.token')
                 WHERE tenant_id=?1 AND client_id=?2 AND {admitted} AND json_extract(?4,'$.token') IS NOT NULL"), effect_params()),
            Statement::new(format!(
                "DELETE FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?2 AND {admitted} AND json_extract(?4,'$.token') IS NULL"), effect_params()),
            Statement::new(format!(
                "DELETE FROM nazo_grants WHERE tenant_id=?1 AND client_id=?2 AND {admitted} AND json_extract(?4,'$.deactivate')=1"), effect_params()),
            Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3) OR (
                EXISTS(SELECT 1 FROM nazo_clients c JOIN nazo_audit a ON a.tenant_id=c.tenant_id AND a.event_id=?3
                    WHERE c.tenant_id=?1 AND c.id=?2 AND a.event_type=json_extract(?4,'$.event') AND a.category='client_lifecycle'
                    AND json_extract(a.payload,'$.tenant_id')=?1 AND json_extract(a.payload,'$.client_id')=c.client_id
                    AND c.active=1-json_extract(?4,'$.deactivate') AND c.epoch=json_extract(a.payload,'$.previous_epoch')+json_extract(?4,'$.deactivate')
                    AND c.secret_digest IS json_extract(?4,'$.secret')
                    AND (json_extract(?4,'$.require_mtls_bound_tokens') IS NULL OR c.require_mtls_bound_tokens=json_extract(?4,'$.require_mtls_bound_tokens'))
                    AND (json_extract(?4,'$.registration') IS NULL OR c.registration=json_set(json_extract(?4,'$.registration'),'$.client_id',c.client_id,'$.allowed_audiences',json_extract(c.registration,'$.allowed_audiences'),'$.security_policy',json_extract(c.registration,'$.security_policy')))
                    AND (json_extract(a.payload,'$.refresh_invalidation_reason') IS NULL OR NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE tenant_id=?1 AND client_id=?2 AND revoked_at IS NULL)))
                AND ((json_extract(?4,'$.token') IS NOT NULL AND EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?2 AND token_hash=json_extract(?4,'$.token')))
                    OR (json_extract(?4,'$.token') IS NULL AND NOT EXISTS(SELECT 1 FROM nazo_client_registrations WHERE tenant_id=?1 AND client_id=?2)))
                AND (json_extract(?4,'$.deactivate')=0 OR NOT EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?1 AND client_id=?2)))
                THEN 1 ELSE json('dynamic registration mutation effects were not accepted') END",effect_params()),
            Statement::new(format!(
                "SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) THEN 'committed'
                 WHEN EXISTS(SELECT 1 FROM nazo_clients c WHERE {authority}) THEN 'policy' ELSE 'stale' END AS outcome"),
                vec![json!(tenant_id),json!(client_id),json!(expected_token),json!(event)]),
            Statement::new("SELECT c.* FROM nazo_clients c WHERE c.tenant_id=?1 AND c.id=?2 AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3)",
                vec![json!(tenant_id),json!(client_id),json!(event)]),
        ]).await?;
        let client = outcomes
            .pop()
            .ok_or(Error::Unavailable)?
            .rows
            .into_iter()
            .next();
        let outcome = outcomes.pop().ok_or(Error::Unavailable)?;
        match outcome
            .rows
            .first()
            .and_then(|row| row.get("outcome"))
            .and_then(Value::as_str)
        {
            Some("committed") => {
                serde_json::from_value::<ClientRow>(client.ok_or(Error::Unavailable)?)
                    .map_err(|_| Error::Unavailable)?
                    .into_domain()
                    .map_err(Into::into)
            }
            Some("policy") => Err(Error::PolicyChanged),
            Some("stale") => Err(Error::StaleCredentials),
            _ => Err(Error::Unavailable),
        }
    }
}
