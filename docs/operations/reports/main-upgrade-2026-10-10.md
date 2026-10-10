# Main upgrade preflight, 2026-10-10

Base main: `c9e9468f5ec5729acea6f1d53e3feb73e4774f34`.
Final source: `bad5174d5f6609ef4d43aec54aacb1e3b8688cad`.
Candidate binary SHA-256: `e2049bc3aec9a8a3a26cf5e357ddf52466381152b7eee4732213420a6176af91`.
This is an explicitly authorized repair-branch build, not a new signed release.
Preflight is complete. Production cutover and official OIDF execution are blocked
on recovery of the existing expired production controller key. The previous
artifact is running again and public checks pass.
No official Suite plan has been started at this checkpoint.

## Upgrade failures and repairs

The original main migration attempted to import all 40,712 pending chained
audit events as one batch, violating its 256-member constraint. A real
PostgreSQL regression with 513 historical events failed with exit 101.
A count-only bootstrap then failed a second regression: 256 legal 4KB events
formed a 1,133,039-byte envelope despite the configured 131,072-byte bound.
The retired per-event protocol had no committed batch membership. Migration
now leaves the new lease empty and lets the existing claimant select under
both count and actual serialized byte bounds. The final 513-event regression
delivers 18 batches, at most 128,673 bytes each, with identical ids, timestamps,
payloads and chain bytes; only full ACKs remove evidence and the checkpoint
reaches 513. No event is acknowledged by migration. Modern committed batches
retain their existing identity. The unreleased September 20 migration and its
checksum are intentionally corrected: a later migration cannot repair an
earlier migration that never finishes.

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
The standard Containerfile explicitly copies this manifest. Its actual
`build-base` stage was built successfully, and the copied manifest's SHA-256
matches the repository. This validates the input stage; it does not claim a
second full OCI build or create a second Cargo target cache.

## Real restored-data rehearsal

The original tested backup was restored anew, then the actual candidate
`nazoauth migrate` applied the complete chain with exit 0.
The final migration is `20261010000600`; the audit lease remains empty until the first byte-bounded claim.
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
pending publication. Deployment: **BLOCKED** (existing controller key expired). Official OIDF: **BLOCKED**;
its configured full scope is 11 groups and 44 plans, with none executed yet.
No performance conclusion is added by this migration repair.

## Authorized deployment attempts

The selected candidate is `v0.2.16+repair.bad5174d`, built from the final source
above. First update exited 1 before the migration process started: candidate
packaging incorrectly used the image configuration digest as the registry
manifest digest. This was corrected without changing server code or image bytes;
the digest-pinned image reports protocol 3 and release v0.2.16.

Resuming the exact same operation then exited 1 at server controller admission.
The sole active production controller slot expired on
`2026-10-01T07:35:16.327567Z`. No accepted operator record or migration is
reported by this attempt; the production migration maximum remains the released
`20260909000100`. ctl conservatively stopped the writer on its unknown-outcome
classification. After inspecting the real pre-admission rejection and unchanged
schema, the unchanged runtime was restarted (exit 0). Doctor and public verify
both exit 0; discovery is HTTP 200 with the expected issuer. Pending operation
journals are preserved, not erased or replaced to manufacture success.

The user has been asked for the private offline recovery-secret file path or
to perform the formal controller recovery. No key expiry, registry authority,
MFA, signature or replay check is bypassed. Official OIDF remains unexecuted
(0/44 plans), rather than being reported as a suite failure or success.
