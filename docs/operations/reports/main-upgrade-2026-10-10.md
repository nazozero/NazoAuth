# Main upgrade preflight, 2026-10-10

Base main: `c9e9468f5ec5729acea6f1d53e3feb73e4774f34`. Validated source: `b2de42abcde74f4ababeab3bdde91e79823ec1ab`.
Candidate binary SHA-256: `fa57b2d3486889f2b21a5d5d7af9a854066350f8708b8baba1cb4a19caea1139`.
This is a source build, not a new signed release. Production remains on the
previous v0.2.16 artifact; deployment and official OIDF execution are **BLOCKED**
until the repair is available on main (or the validated branch is explicitly
selected for deployment). No official Suite plan has been started.

## Upgrade failures and repairs

The original main migration attempted to import all 40,712 pending chained
audit events as one batch, violating its 256-member constraint. A real
PostgreSQL regression with 513 historical events failed with exit 101 before
the fix and passed afterwards. The initial batch now imports only the first
256 events. Remaining events retain their ids, timestamps, payloads and chain
bytes and are delivered through the existing claimant in successive batches.
Nothing is acknowledged by migration. The unreleased September 20 migration
and its checksum are intentionally corrected: a later migration cannot repair
an earlier migration that never finishes.

Once that blocker was removed, the restored database failed in the September
29 cleanup migration: the existing function had different OUT-column names.
The released v0.2.16 issuance table also retained its old columns because the
historical saga migration had already been recorded. A rewritten historical
file cannot alter a deployed table. The explicit September 13 cutover runs
before unreleased consumers of the compact receipt schema. It preserves
terminal ownership and replay digests, and retains the maximum of both old
acceptance deadlines. It rejects incomplete terminal evidence and live opaque
responses without changing their data; old receipts stay old-contract receipts.
Function owner, EXECUTE grants and grant options are preserved at replacement.
The regression uses the authentic released SQL, tests atomic rejection,
preservation, an already compact schema, and resume after refresh storage was
already retired. No retired table is recreated on resume.

A cached build initially omitted the newly inserted migration because only the
latest-directory marker invalidated the embedded list. The existing complete
checksum manifest now owns invalidation; the obsolete separate marker is
removed. A regression checks every migration file against that manifest.

## Real restored-data rehearsal

The original tested backup was restored anew, then the actual candidate
`nazoauth migrate` applied the complete chain with exit 0 in 1.496 seconds.
The final migration is `20261010000600`; the initial audit batch is 1–256.
The same binary also migrated a fresh isolated database successfully (exit 0).

| Retained facts | Before | After | SHA-256 comparison |
| --- | ---: | ---: | --- |
| Audit events: id, type, category, payload, occurred_at | 43,576 | 43,576 | identical |
| Chain: sequence, id, predecessor hash, event hash | 40,712 | 40,712 | identical |
| Issuance: id, owners, grant digest, JTI, access expiry, maximum retention | 7,214 | 7,214 | identical |

The chain head remains 40,712 with the same hash; the anchor remains unset.
These comparisons cover the listed security facts, not superseded schema
metadata. The snapshot had no retained response bodies. No audit export,
signed receiver acceptance, TTL reduction, manual deletion of business data,
or vacuum was used to obtain these results. Production function ownership was
also checked read-only; the lifecycle role owns the function and can create in
its schema. Production doctor remains exit 0 and public discovery HTTP 200.

## Commands and scope

Credentials and private config paths are omitted. The actual command vectors,
exit codes, raw regression outcomes and SHA-256 comparisons are retained in
[acceptance evidence](../../../evidence/deployment-upgrade-20261010/acceptance.json).

```sh
cargo +1.99.0 build --release --locked -p nazoauth
cargo +1.99.0 fmt --check
python3 scripts/verify_static_contracts.py --check
python3 scripts/check_persistence_dependency_graph.py
cargo +1.99.0 test --release --locked -p nazo-postgres --test audit_chain_cutover --test audit_pending_upgrade --test released_issuance_cutover -- --nocapture
cargo +1.99.0 clippy --release --locked -p nazo-postgres --test audit_chain_cutover --test audit_pending_upgrade --test released_issuance_cutover --test migrations -- -D warnings
cargo +1.99.0 test --release --locked -p nazo-postgres --test migrations embedded_migration_manifest_tracks_all_files -- --exact --nocapture
cargo +1.99.0 test --release --locked -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables -- --exact --nocapture
nazoauth migrate
```

All positive commands above exited 0. The combined database regression ran
2 audit cutover cases, 5 pending-set cases and 1 released-schema case. The
manifest and fresh schema tests each ran one case. Required fixtures were
present; no early-return skip is used as acceptance evidence. One earlier
attempt at the existing role-creation test lacked CREATEROLE and failed; it was
rerun successfully on the CI-pinned independent PostgreSQL fixture without
expanding production role privileges.

Focused CODE and upgrade-data preservation: **PASS**. Full workspace CI is
pending publication. Deployment: **BLOCKED**. Official OIDF: **BLOCKED**;
its configured full scope is 11 groups and 44 plans, with none executed yet.
No performance conclusion is added by this migration repair.
