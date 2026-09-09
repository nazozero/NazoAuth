# Security audit ledger roles

The `20260805000100_security_audit_ledger` migration does not create or drop
cluster-global roles. A database administrator must provision separate roles
and run the migration as a dedicated, non-superuser migration owner. Runtime
roles are granted `EXECUTE` on narrowly scoped `SECURITY DEFINER` functions;
they are never granted table privileges.

## Provisioning boundary

Use deployment-specific role names. The following names are illustrative only:

```sql
CREATE ROLE nazoauth_migration_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
CREATE ROLE nazoauth_audit_writer LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
CREATE ROLE nazoauth_audit_exporter LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
```

The migration URL must execute the migration as `nazoauth_migration_owner` (or
as a short-lived migration runner that can `SET ROLE` to it). Do not use the
long-running application role as the owner. The owner must remain the owner of
the four ledger tables, their indexes/triggers, and all functions below; only
the owner can alter or disable the append-only trigger.

Before granting runtime access, remove the default schema creation path and
the table privileges inherited by application roles:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON TABLE
    public.security_audit_chain_state,
    public.security_audit_events,
    public.security_audit_chain_entries,
    public.security_audit_event_outbox
FROM nazoauth_audit_writer, nazoauth_audit_exporter;
GRANT USAGE ON SCHEMA public TO nazoauth_audit_writer, nazoauth_audit_exporter;
```

The migration itself also revokes table and function privileges from `PUBLIC`.
The explicit role revocation above is still required when a deployment role
inherits privileges from another application role. `has_table_privilege` in
the strict preflight reports effective privileges, not just direct grants.

## Function grants

Grant only the capability required by each process. The writer persists event
facts and their outbox entry atomically; the exporter owns chain assignment:

```sql
GRANT EXECUTE ON FUNCTION
    public.nazo_security_audit_shared_privilege_preflight(boolean, boolean, boolean),
    public.nazo_persist_security_audit_event(
        uuid, text, text, jsonb, timestamptz
    ),
    public.nazo_security_audit_shared_anchor_health()
TO nazoauth_audit_writer;
```

The exporter chains committed events, acknowledges outbox rows, and refreshes
the checkpoint. It cannot create raw events:

```sql
GRANT EXECUTE ON FUNCTION
    public.nazo_security_audit_shared_privilege_preflight(boolean, boolean, boolean),
    public.nazo_claim_security_audit_events(bigint, integer),
    public.nazo_security_audit_chain_head_for_update(),
    public.nazo_append_security_audit_chain(bigint, bytea, uuid[], bytea[]),
    public.nazo_ack_security_audit_event(uuid, integer, text),
    public.nazo_observe_security_audit_anchor(text),
    public.nazo_record_security_audit_genesis(text, bytea),
    public.nazo_reschedule_security_audit_event(uuid, integer, timestamptz, text),
    public.nazo_security_audit_shared_anchor_health()
TO nazoauth_audit_exporter;
```

If one process intentionally performs both jobs, grant both function sets to
one pre-created role and record that exception in the deployment inventory.
Never grant `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, or
`TRIGGER` on any of the four tables to that combined role. Runtime login roles
must not be members of the migration owner, a superuser role, or any role that
can acquire those privileges through `SET ROLE`.

## Fail-closed preflight

The repository calls the policy-driven preflight as the runtime role. A writer
uses `(require_least_privilege, require_append, require_exporter) =
 (true, true, false)`; an exporter uses `(true, false, true)`. Strict mode
requires the requested function `EXECUTE` grants, and all of
the following to be false for `session_user` or any role it can assume:
superuser, ledger table owner, or any effective ledger table privilege.
Therefore a writer cannot rewrite or
truncate the ledger and an exporter cannot bypass the claim/ack state machine.

The authorization-server setting `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE`
should remain enabled in production. A test fixture may explicitly pass
`false` to the repository policy method, but non-strict mode still requires the
function API. The worker and required-mode admission separately validate chain
health. A failed preflight is a startup/high-impact
operation failure; do not silently fall back to direct table writes.

Verify each role after grants, using the same connection identity as the
process:

```sql
SELECT *
FROM public.nazo_security_audit_shared_privilege_preflight(true, true, false);
-- writer: policy_satisfied = true; claim_execute/ack_execute = false

SELECT *
FROM public.nazo_security_audit_shared_privilege_preflight(true, false, true);
-- exporter: policy_satisfied = true; raw-event persistence is not granted
```

Run these checks after every role or grant change and after restoring a backup.
The migration owner and any superuser deliberately fail strict preflight and
must never be used as a long-running application or exporter identity.

## Exporter-owned chain cutover

`20260909000100_exporter_owned_audit_chain` is a coordinated schema cutover.
Stop all old application writers and exporters, take a restorable database
backup, and apply migrations with the migration owner before starting the new
binaries. Do not run old and new versions against this schema concurrently:
the old synchronous append function is removed.

The migration copies existing sequence/hash bytes into immutable chain entries,
preserves the outbox and external checkpoint, and transfers explicit writer and
exporter function grants. Verify the role checks above after migration. Start
the new exporter, verify its externally accepted checkpoint and backlog age,
then admit required-mode application traffic. No historical checkpoint is
rehashed or renumbered. New business transactions write only event facts and
the outbox; chain assignment occurs in a bounded exporter transaction.

The down migration intentionally refuses destructive reversal. Roll back by
stopping both processes and restoring the complete pre-cutover database and
matching binaries. Reconcile the receiver's immutable checkpoint with that
restore before resuming export; never erase externally accepted history.
