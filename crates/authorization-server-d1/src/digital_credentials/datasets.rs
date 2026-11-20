use super::{EncryptedStore, dataset_aad, encode, timestamp};
use crate::{D1Provider, db::Statement, persistence::NOW};
use futures_util::future::BoxFuture;
use jiff::Timestamp;
use nazo_openid4vci::CredentialStoreError;
use nazo_persistence::{
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, Openid4vciDatasetStore,
    SecurityAuditEvent,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct DatasetStore(EncryptedStore);

#[derive(Deserialize)]
struct DatasetRow {
    claims_ciphertext: String,
    valid_from: Option<i64>,
    valid_until: Option<i64>,
    updated_at: i64,
}

struct DatasetActor<'a> {
    tenant: Uuid,
    actor: Uuid,
    subject: Uuid,
    configuration: &'a str,
}

// The principal identity is checked alongside the authoritative row columns;
// a well-formed but misbound JSON projection cannot authorize an admin write.
const ACTOR: &str =
    "EXISTS(SELECT 1 FROM nazo_users a WHERE a.tenant_id=?1 AND a.id=?2 AND a.active=1
    AND json_extract(a.principal,'$.tenant.tenant_id')=a.tenant_id
    AND json_extract(a.principal,'$.user_id')=a.id
    AND json_type(a.principal,'$.role.Admin.level')='integer'
    AND json_extract(a.principal,'$.role.Admin.level') BETWEEN 1 AND 4294967295)";
const SUBJECT: &str =
    "EXISTS(SELECT 1 FROM nazo_users u WHERE u.tenant_id=?1 AND u.id=?3 AND u.active=1)";

impl DatasetStore {
    pub(crate) fn new(provider: D1Provider, key: [u8; 32]) -> Self {
        Self(EncryptedStore::new(provider, key))
    }

    fn view(
        &self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &str,
        row: DatasetRow,
    ) -> Result<ManagedCredentialDataset, CredentialStoreError> {
        let plaintext = self.0.open(
            &dataset_aad(tenant, subject, configuration),
            &row.claims_ciphertext,
        )?;
        Ok(ManagedCredentialDataset {
            claims: serde_json::from_slice(&plaintext)
                .map_err(|_| CredentialStoreError::InvalidTransition)?,
            valid_from: row.valid_from.map(timestamp).transpose()?,
            valid_until: row.valid_until.map(timestamp).transpose()?,
            updated_at: timestamp(row.updated_at)?,
        })
    }

    fn audit(
        &self,
        owner: DatasetActor<'_>,
        event_type: &str,
        event_id: Uuid,
        occurred_at: Timestamp,
    ) -> Result<Statement, CredentialStoreError> {
        let DatasetActor {
            tenant,
            actor,
            subject,
            configuration,
        } = owner;
        let event = SecurityAuditEvent {
            event_id,
            event_type: event_type.to_owned(),
            event_category: "credential_lifecycle".into(),
            occurred_at,
            payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category":"credential_lifecycle","tenant_id":tenant,
                "admin_user_id":actor,"subject_id":subject,
                "credential_configuration_id":configuration,"outcome":"success"}),
        };
        let mut statement = self
            .0
            .provider
            .audit_statement(&event)
            .map_err(|_| CredentialStoreError::Unavailable)?;
        statement.sql="INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
            SELECT ?1,?2,?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM nazo_vci_dataset_events WHERE tenant_id=?1 AND id=?2)".into();
        Ok(statement)
    }
}

impl Openid4vciDatasetStore for DatasetStore {
    fn datasets_available<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configurations: &'a [String],
    ) -> BoxFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.0.provider.require_tenant(tenant)?;
            #[derive(Deserialize)]
            struct Available {
                available: i64,
            }
            let rows=self.0.provider.database.query::<Available>(&format!("SELECT NOT EXISTS(
                SELECT 1 FROM json_each(?3) requested WHERE NOT EXISTS(
                    SELECT 1 FROM nazo_vci_datasets d WHERE d.tenant_id=?1 AND d.subject_id=?2 AND d.configuration_id=requested.value
                    AND (d.valid_from IS NULL OR d.valid_from<={NOW}) AND (d.valid_until IS NULL OR d.valid_until>{NOW}))) AS available"),
                vec![json!(tenant),json!(subject),json!(encode(&configurations)?)]).await?;
            Ok(rows
                .into_iter()
                .next()
                .ok_or(CredentialStoreError::Unavailable)?
                .available
                == 1)
        })
    }

    fn dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<Option<Value>, CredentialStoreError>> {
        Box::pin(async move {
            self.0.provider.require_tenant(tenant)?;
            let row=self.0.provider.database.query::<DatasetRow>(&format!("SELECT * FROM nazo_vci_datasets WHERE tenant_id=?1 AND subject_id=?2 AND configuration_id=?3
                AND (valid_from IS NULL OR valid_from<={NOW}) AND (valid_until IS NULL OR valid_until>{NOW})"),vec![json!(tenant),json!(subject),json!(configuration)]).await?.into_iter().next();
            row.map(|row| {
                self.view(tenant, subject, configuration, row)
                    .map(|view| view.claims)
            })
            .transpose()
        })
    }

    fn managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<Option<ManagedCredentialDataset>, CredentialStoreError>> {
        Box::pin(async move {
            self.0.provider.require_tenant(tenant)?;
            let row=self.0.provider.database.query::<DatasetRow>("SELECT * FROM nazo_vci_datasets WHERE tenant_id=?1 AND subject_id=?2 AND configuration_id=?3",vec![json!(tenant),json!(subject),json!(configuration)]).await?.into_iter().next();
            row.map(|row| self.view(tenant, subject, configuration, row))
                .transpose()
        })
    }

    fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite,
    ) -> BoxFuture<'_, Result<Option<ManagedCredentialDataset>, CredentialStoreError>> {
        Box::pin(async move {
            let ManagedCredentialDatasetWrite {
                tenant_id: tenant,
                actor_user_id: actor,
                subject_id: subject,
                credential_configuration_id: configuration,
                claims,
                valid_from,
                valid_until,
            } = write;
            self.0.provider.require_tenant(tenant)?;
            let now = timestamp(Timestamp::now().as_microsecond())?;
            let event_id = Uuid::new_v4();
            let cipher = self.0.seal(
                &dataset_aad(tenant, subject, &configuration),
                encode(&claims)?.as_bytes(),
            )?;
            // D1 executes the batch remotely and cannot call Rust inside its
            // transaction. Decode this ciphertext before dispatch, then make
            // the SQL guard prove the actual effect has exactly these bytes,
            // validity and timestamp before COMMIT. No post-commit decode can
            // turn an unacknowledged effect into a successful returned view.
            let view = self.view(
                tenant,
                subject,
                &configuration,
                DatasetRow {
                    claims_ciphertext: cipher.clone(),
                    valid_from: valid_from.map(|t| t.as_microsecond()),
                    valid_until: valid_until.map(|t| t.as_microsecond()),
                    updated_at: now.as_microsecond(),
                },
            )?;
            let permitted = format!(
                "{ACTOR} AND {SUBJECT} AND NOT EXISTS(SELECT 1 FROM nazo_vci_datasets d WHERE d.tenant_id=?1 AND d.subject_id=?3 AND d.configuration_id=?4 AND d.source<>'admin-session')"
            );
            let exact = "EXISTS(SELECT 1 FROM nazo_vci_datasets d WHERE d.tenant_id=?1 AND d.subject_id=?3 AND d.configuration_id=?4 AND d.claims_ciphertext=?5 AND d.valid_from IS ?6 AND d.valid_until IS ?7 AND d.updated_at=?8 AND d.revision=?9 AND d.source='admin-session')";
            let params = vec![
                json!(tenant),
                json!(actor),
                json!(subject),
                json!(configuration),
                json!(cipher),
                json!(view.valid_from.map(|t| t.as_microsecond())),
                json!(view.valid_until.map(|t| t.as_microsecond())),
                json!(now.as_microsecond()),
                json!(event_id),
            ];
            let audit = self.audit(
                DatasetActor {
                    tenant,
                    actor,
                    subject,
                    configuration: &configuration,
                },
                "openid4vci_credential_dataset_updated",
                event_id,
                now,
            )?;
            let audit_payload = audit.params[5].clone();
            let mut guard_params = params.clone();
            guard_params.push(audit_payload);
            let mut result=self.0.provider.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_vci_datasets(tenant_id,subject_id,configuration_id,claims_ciphertext,source,valid_from,valid_until,updated_at,revision)
                    SELECT ?1,?3,?4,?5,'admin-session',?6,?7,?8,?9 WHERE {permitted}
                    ON CONFLICT(tenant_id,subject_id,configuration_id) DO UPDATE SET claims_ciphertext=excluded.claims_ciphertext,valid_from=excluded.valid_from,valid_until=excluded.valid_until,updated_at=excluded.updated_at,revision=excluded.revision WHERE nazo_vci_datasets.source='admin-session'"),params.clone()),
                Statement::new(format!("INSERT INTO nazo_vci_dataset_events(tenant_id,id,subject_id,configuration_id,action,actor_user_id,source,occurred_at)
                    SELECT ?1,?9,?3,?4,1,?2,'admin-session',?8 WHERE {exact}"),params),
                audit,
                Statement::new(format!("SELECT CASE WHEN
                    (({permitted}) AND ({exact}) AND EXISTS(SELECT 1 FROM nazo_vci_dataset_events WHERE tenant_id=?1 AND id=?9 AND subject_id=?3 AND configuration_id=?4 AND action=1 AND actor_user_id=?2 AND source='admin-session' AND occurred_at=?8)
                        AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?9 AND event_type='openid4vci_credential_dataset_updated' AND category='credential_lifecycle' AND payload=?10))
                    OR (NOT ({permitted}) AND NOT EXISTS(SELECT 1 FROM nazo_vci_datasets WHERE tenant_id=?1 AND revision=?9)
                        AND NOT EXISTS(SELECT 1 FROM nazo_vci_dataset_events WHERE tenant_id=?1 AND id=?9) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?9))
                    THEN 1 ELSE json('credential dataset atomicity failure') END AS checked"),guard_params),
                Statement::new("SELECT revision FROM nazo_vci_datasets WHERE tenant_id=?1 AND revision=?2",vec![json!(tenant),json!(event_id)]),
            ]).await?;
            Ok((!result
                .pop()
                .ok_or(CredentialStoreError::Unavailable)?
                .rows
                .is_empty())
            .then_some(view))
        })
    }

    fn delete_managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        actor: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> BoxFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.0.provider.require_tenant(tenant)?;
            let event_id = Uuid::new_v4();
            let now = Timestamp::now();
            let target = "EXISTS(SELECT 1 FROM nazo_vci_datasets WHERE tenant_id=?1 AND subject_id=?3 AND configuration_id=?4 AND source='admin-session')";
            let event = "EXISTS(SELECT 1 FROM nazo_vci_dataset_events WHERE tenant_id=?1 AND id=?5 AND subject_id=?3 AND configuration_id=?4 AND actor_user_id=?2 AND action=2 AND source='admin-session' AND occurred_at=?6)";
            let params = vec![
                json!(tenant),
                json!(actor),
                json!(subject),
                json!(configuration),
                json!(event_id),
                json!(now.as_microsecond()),
            ];
            let audit = self.audit(
                DatasetActor {
                    tenant,
                    actor,
                    subject,
                    configuration,
                },
                "openid4vci_credential_dataset_deleted",
                event_id,
                now,
            )?;
            let mut guard_params = params.clone();
            guard_params.push(audit.params[5].clone());
            let mut result=self.0.provider.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_vci_dataset_events(tenant_id,id,subject_id,configuration_id,action,actor_user_id,source,occurred_at)
                    SELECT ?1,?5,?3,?4,2,?2,'admin-session',?6 WHERE {ACTOR} AND {target}"),params.clone()),
                Statement::new(format!("DELETE FROM nazo_vci_datasets WHERE tenant_id=?1 AND subject_id=?3 AND configuration_id=?4 AND source='admin-session' AND {event}"),params),
                audit,
                Statement::new(format!("SELECT CASE WHEN
                    (({event}) AND NOT ({target}) AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5 AND event_type='openid4vci_credential_dataset_deleted' AND category='credential_lifecycle' AND payload=?7))
                    OR (NOT ({event}) AND NOT (({ACTOR}) AND ({target})) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?5))
                    THEN 1 ELSE json('credential dataset atomicity failure') END AS checked"),guard_params),
                Statement::new("SELECT id FROM nazo_vci_dataset_events WHERE tenant_id=?1 AND id=?2",vec![json!(tenant),json!(event_id)]),
            ]).await?;
            Ok(!result
                .pop()
                .ok_or(CredentialStoreError::Unavailable)?
                .rows
                .is_empty())
        })
    }
}
