use std::sync::Arc;

use nazo_identity::ports::RepositoryError;
use nazo_persistence::RuntimeModuleStore;
use nazo_runtime_modules::{
    CasOutcome, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    InstanceStateMutation, InstanceStateObservation, InstanceStateRecord, ModuleEventRecord,
    ModuleEventState, ModuleEventType,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    DESIRED_JSON, INSTANCE_JSON, decode,
    records::{DesiredRow, EventRow, InstanceRow, invalid, revision},
};
use crate::{
    D1Provider,
    db::{DbError, Statement},
};

fn event_receipt(body: &str) -> String {
    format!(
        "EXISTS(SELECT 1 FROM nazo_module_events e WHERE e.tenant_id=?1 AND e.event_id=?2
        AND e.module_id=json_extract({body},'$.module_id')
        AND e.event_type=json_extract({body},'$.event_type')
        AND e.occurred_at=json_extract({body},'$.occurred_at') AND e.record={body})"
    )
}

fn insert_event(body: &str, predicate: &str, params: Arc<[Value]>) -> Statement {
    Statement::new(
        format!(
            "WITH chosen AS (SELECT {body} AS body WHERE {predicate})
         INSERT INTO nazo_module_events(event_id,tenant_id,module_id,event_type,occurred_at,record)
         SELECT ?2,?1,json_extract(body,'$.module_id'),json_extract(body,'$.event_type'),
                json_extract(body,'$.occurred_at'),body FROM chosen"
        ),
        params,
    )
}

fn parameters(
    provider: &D1Provider,
    event_id: &str,
    plan: Value,
) -> Result<Arc<[Value]>, RepositoryError> {
    Ok(vec![
        json!(provider.tenant_id),
        json!(event_id),
        json!(
            serde_json::to_string(&plan)
                .map_err(|_| invalid("runtime operation cannot be encoded"))?
        ),
    ]
    .into())
}

fn desired_matches(path: &str) -> String {
    format!(
        "d.module_id=json_extract(?3,'{path}.module_id')
        AND d.mode=json_extract(?3,'{path}.mode') AND d.revision=json_extract(?3,'{path}.revision')
        AND d.actor_id IS json_extract(?3,'{path}.actor_id')
        AND d.reason IS json_extract(?3,'{path}.reason')
        AND d.updated_at=json_extract(?3,'{path}.updated_at')"
    )
}

pub(super) async fn desired(
    provider: &D1Provider,
    change: DesiredStateChange,
    guards: Vec<DesiredRevisionGuard>,
) -> Result<CasOutcome<DesiredStateRecord>, RepositoryError> {
    let current = provider
        .read_desired(change.next.module_id)
        .await?
        .ok_or_else(|| invalid("runtime desired state is missing"))?;
    if change.expected_revision != Some(current.revision) {
        return Ok(CasOutcome::Stale {
            current: Some(current),
        });
    }
    let next = DesiredRow::from_record(&change.next)?;
    let old = DesiredRow::from_record(&current)?;
    let noop = current.mode == change.next.mode;
    if !noop && old.revision.checked_add(1) != Some(next.revision) {
        return Err(invalid("runtime desired revision must advance by one"));
    }
    let event = EventRow::from_record(&ModuleEventRecord {
        event_id: uuid::Uuid::new_v4().to_string(),
        module_id: change.next.module_id,
        event_type: ModuleEventType::DesiredStateChanged,
        revision: if noop {
            current.revision
        } else {
            change.next.revision
        },
        instance_id: None,
        actor_id: change.next.actor_id.clone(),
        reason: change.next.reason.clone(),
        before: Some(ModuleEventState::Desired(current.mode.into())),
        after: Some(ModuleEventState::Desired(change.next.mode.into())),
        outcome_code: noop.then(|| "noop".to_owned()),
        occurred_at: change.next.updated_at,
    })?;
    let guards = guards
        .into_iter()
        .map(|guard| {
            Ok(json!({
                "module_id":guard.module_id,
                "revision":guard.expected_revision.map(revision).transpose()?,
            }))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let params = parameters(
        provider,
        &event.event_id,
        json!({
            "current":old,"next":next,"committed":if noop { &old } else { &next },
            "event":event,"guards":guards,
        }),
    )?;
    let admission = format!(
        "EXISTS(SELECT 1 FROM nazo_module_desired d WHERE d.tenant_id=?1 AND {})
        AND NOT EXISTS(SELECT 1 FROM json_each(?3,'$.guards') g WHERE
            (SELECT revision FROM nazo_module_desired d WHERE d.tenant_id=?1
                AND d.module_id=json_extract(g.value,'$.module_id'))
            IS NOT json_extract(g.value,'$.revision'))",
        desired_matches("$.current")
    );
    let event_body = "json_extract(?3,'$.event')";
    let event_ack = event_receipt(event_body);
    let mut statements = vec![insert_event(event_body, &admission, params.clone())];
    if !noop {
        statements.push(Statement::new(
            format!(
                "UPDATE nazo_module_desired AS d SET
                mode=json_extract(?3,'$.next.mode'),revision=json_extract(?3,'$.next.revision'),
                actor_id=json_extract(?3,'$.next.actor_id'),reason=json_extract(?3,'$.next.reason'),
                updated_at=json_extract(?3,'$.next.updated_at')
             WHERE d.tenant_id=?1 AND {} AND ({event_ack})",
                desired_matches("$.current")
            ),
            params.clone(),
        ));
    }
    statements.push(Statement::new(
        format!(
            "SELECT CASE WHEN
            (({event_ack}) AND EXISTS(
                SELECT 1 FROM nazo_module_desired d WHERE d.tenant_id=?1 AND {}))
            OR (NOT EXISTS(SELECT 1 FROM nazo_module_events WHERE event_id=?2)
                AND NOT ({admission}))
         THEN 1 ELSE json_extract('runtime desired evidence was not committed','$') END AS committed",
            desired_matches("$.committed")
        ),
        params.clone(),
    ));
    statements.push(Statement::new(format!(
        "SELECT EXISTS(SELECT 1 FROM nazo_module_events WHERE tenant_id=?1 AND event_id=?2) AS applied,
                {DESIRED_JSON} AS record FROM nazo_module_desired d
         WHERE d.tenant_id=?1 AND d.module_id=json_extract(?3,'$.next.module_id')"),params));
    let mut result = provider.database.batch(statements).await?;
    #[derive(Deserialize)]
    struct ResultRow {
        applied: i64,
        record: String,
    }
    let row: ResultRow = serde_json::from_value(
        result
            .pop()
            .and_then(|result| result.rows.into_iter().next())
            .ok_or(DbError::CorruptData)?,
    )
    .map_err(|_| DbError::CorruptData)?;
    let current = decode::<DesiredRow>(&row.record)?.into_record()?;
    Ok(if row.applied == 1 {
        CasOutcome::Applied(current)
    } else {
        CasOutcome::Stale {
            current: Some(current),
        }
    })
}

fn instance_admission() -> &'static str {
    "EXISTS(SELECT 1 FROM nazo_module_desired WHERE tenant_id=?1
        AND module_id=json_extract(?3,'$.next.module_id')
        AND revision=json_extract(?3,'$.next.transition_revision'))
     AND (SELECT transition_revision FROM nazo_module_instances WHERE tenant_id=?1
        AND instance_id=json_extract(?3,'$.next.instance_id')
        AND module_id=json_extract(?3,'$.next.module_id')) IS json_extract(?3,'$.expected')"
}

pub(super) async fn instance(
    provider: &D1Provider,
    mutation: InstanceStateMutation,
) -> Result<CasOutcome<InstanceStateRecord>, RepositoryError> {
    let state = &mutation.change.next;
    let event = &mutation.event;
    if !matches!(
        event.event_type,
        ModuleEventType::TransitionStarted
            | ModuleEventType::TransitionCompleted
            | ModuleEventType::TransitionFailed
            | ModuleEventType::DrainStarted
            | ModuleEventType::DrainCompleted
    ) || event.module_id != state.module_id
        || event.instance_id.as_deref() != Some(state.instance_id.as_str())
        || event.revision != state.transition_revision
        || event.after != Some(ModuleEventState::Actual(state.state))
        || matches!(event.before, Some(ModuleEventState::Desired(_)))
        || mutation
            .change
            .expected_revision
            .is_some_and(|expected| state.transition_revision < expected)
    {
        return Err(invalid(
            "runtime instance event does not match its revision-bound mutation",
        ));
    }
    let next = InstanceRow::from_record(state)?;
    let event = EventRow::from_record(event)?;
    let mut stale = event.clone();
    stale.event_type = "stale_transition_discarded".to_owned();
    let params = parameters(
        provider,
        &event.event_id,
        json!({
            "expected":mutation.change.expected_revision.map(revision).transpose()?,
            "next":next,"event":event,"stale":stale,
        }),
    )?;
    let admission = instance_admission();
    let chosen = format!(
        "CASE WHEN {admission} THEN json_extract(?3,'$.event') ELSE json_extract(?3,'$.stale') END"
    );
    let applied = event_receipt("json_extract(?3,'$.event')");
    let discarded = event_receipt("json_extract(?3,'$.stale')");
    let statements = vec![
        insert_event(&chosen, "true", params.clone()),
        Statement::new(format!(
            "INSERT INTO nazo_module_instances(
                tenant_id,instance_id,module_id,state,transition_revision,applied_revision,
                drain_deadline,error_code,updated_at)
             SELECT ?1,json_extract(?3,'$.next.instance_id'),json_extract(?3,'$.next.module_id'),
                json_extract(?3,'$.next.state'),json_extract(?3,'$.next.transition_revision'),
                json_extract(?3,'$.next.applied_revision'),json_extract(?3,'$.next.drain_deadline'),
                json_extract(?3,'$.next.error_code'),json_extract(?3,'$.next.updated_at')
             WHERE ({applied}) AND ({admission})
             ON CONFLICT(tenant_id,instance_id,module_id) DO UPDATE SET
                state=excluded.state,transition_revision=excluded.transition_revision,
                applied_revision=excluded.applied_revision,drain_deadline=excluded.drain_deadline,
                error_code=excluded.error_code,updated_at=excluded.updated_at
             WHERE nazo_module_instances.transition_revision IS json_extract(?3,'$.expected')"),params.clone()),
        Statement::new(format!(
            "SELECT CASE WHEN (
                (({discarded}) AND NOT ({admission})) OR
                (({applied}) AND EXISTS(SELECT 1 FROM nazo_module_instances i
                    JOIN nazo_module_desired d ON d.tenant_id=i.tenant_id AND d.module_id=i.module_id
                    WHERE i.tenant_id=?1 AND i.instance_id=json_extract(?3,'$.next.instance_id')
                    AND i.module_id=json_extract(?3,'$.next.module_id')
                    AND d.revision=json_extract(?3,'$.next.transition_revision')
                    AND i.state=json_extract(?3,'$.next.state')
                    AND i.transition_revision=json_extract(?3,'$.next.transition_revision')
                    AND i.applied_revision IS json_extract(?3,'$.next.applied_revision')
                    AND i.drain_deadline IS json_extract(?3,'$.next.drain_deadline')
                    AND i.error_code IS json_extract(?3,'$.next.error_code')
                    AND i.updated_at=json_extract(?3,'$.next.updated_at'))))
             THEN 1 ELSE json_extract('runtime instance evidence was not committed','$') END AS committed"),params.clone()),
        Statement::new(format!(
            "SELECT CASE WHEN e.event_type='stale_transition_discarded' THEN 0 ELSE 1 END AS applied,
                CASE WHEN i.instance_id IS NULL THEN NULL ELSE {INSTANCE_JSON} END AS record
             FROM nazo_module_events e LEFT JOIN nazo_module_instances i
               ON i.tenant_id=e.tenant_id AND i.instance_id=json_extract(?3,'$.next.instance_id')
               AND i.module_id=json_extract(?3,'$.next.module_id')
             WHERE e.tenant_id=?1 AND e.event_id=?2"),params),
    ];
    let mut results = provider.database.batch(statements).await?;
    #[derive(Deserialize)]
    struct ResultRow {
        applied: i64,
        record: Option<String>,
    }
    let row: ResultRow = serde_json::from_value(
        results
            .pop()
            .and_then(|result| result.rows.into_iter().next())
            .ok_or(DbError::CorruptData)?,
    )
    .map_err(|_| DbError::CorruptData)?;
    let current = row
        .record
        .map(|record| decode::<InstanceRow>(&record)?.into_record())
        .transpose()?;
    Ok(if row.applied == 1 {
        CasOutcome::Applied(current.ok_or(DbError::CorruptData)?)
    } else {
        CasOutcome::Stale { current }
    })
}

pub(super) async fn observation(
    provider: &D1Provider,
    observation: InstanceStateObservation,
) -> Result<(), RepositoryError> {
    let event = observation.event;
    if event.event_type != ModuleEventType::StaleTransitionDiscarded
        || event.instance_id.as_ref().is_none_or(String::is_empty)
        || event.before != event.after
        || matches!(event.before, Some(ModuleEventState::Desired(_)))
    {
        return Err(invalid(
            "runtime observation must describe unchanged actual state and discarded work",
        ));
    }
    let event = EventRow::from_record(&event)?;
    let params = parameters(provider, &event.event_id, json!({"event":event}))?;
    let event_ack = event_receipt("json_extract(?3,'$.event')");
    provider
        .database
        .batch(vec![
            insert_event("json_extract(?3,'$.event')", "true", params.clone()),
            Statement::new(
                format!(
                    "SELECT CASE WHEN ({event_ack})
            THEN 1 ELSE json_extract('runtime observation evidence was not committed','$') END AS committed"
                ),
                params,
            ),
        ])
        .await?;
    Ok(())
}
