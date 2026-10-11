# Main upgrade and official OIDF, 2026-10-10

Base main: `c9e9468f5ec5729acea6f1d53e3feb73e4774f34`.
Upgrade-regression source: `bad5174d5f6609ef4d43aec54aacb1e3b8688cad`.
Final deployed server source: `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
Running binary SHA-256: `cf97faf9b6e8f0639aff031ebef2d7870dce5a7f2e2824150d8a1c11e78a0817`.
Current validation controller source: `dbd8b0647731dcf4fa3d725cd8269fc745f9e5ee`.
These are authorized repair-branch builds, not new signed releases.
Production deployment, snapshot/restore rehearsal, doctor and public verify pass.
The initial official suite and one interrupted correction run remain recorded
below. The final OpenID4VC correction run is complete with zero failures/incomplete
modules. The [2026-10-11 evidence review](oidf-review-2026-10-11.md) locally accepts
24 VP screenshot obligations and 12 scope warnings, identifies 17 missing OIDC
screenshots, and leaves two mdoc privacy warnings open. No certification PASS
is claimed.

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

Focused CODE and upgrade-data preservation: **PASS**. Exact-head CI is reported on the PR after
evidence publication. Deployment: **PASS**. Official OIDF initial run: **FAIL**;
its configured full scope is 11 groups, 44 plans and 1,173 modules.
No performance conclusion is added by this migration repair.

## Authorized deployment attempts

The original upgrade candidate was `v0.2.16+repair.bad5174d`, built from the
upgrade-regression source above. First update exited 1 before the migration process started: candidate
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

That checkpoint was superseded after the user authorized autonomous recovery.
The existing offline recovery secret was not available. The documented host-root
`admin create` operation provisioned one dedicated recovery administrator, followed
by real TOTP enrollment and the official MFA-authorized `controller rotate` flow
(exit 0). Existing accounts were not reset. The new recovery account remains
provisioned; its credentials and MFA recovery material are retained root-private.
No expiry, MFA, signature, replay or registry-authority check was bypassed.
The replacement controller slot expires on `2026-11-09T15:33:35.96822Z`.

Before retrying update, the definitively unaccepted old signed client intent was
archived under both controller and server task locks. The exact real admission
rejection, absence of both accepted and temporary server records, and changed
active key were checked. The original journal and host operation history remain
retained. No accepted operation was discarded.

The next `nazoauthctl-selected --json --instance production update --to
v0.2.16+repair.bad5174d` completed in 6.919 seconds (exit 0): migration accepted
once and completed, configuration revision 8, local health verified. A fresh
backup snapshot and restore-test both exited 0 before cutover. Post-update doctor
and public verify exited 0; discovery returns HTTP 200 with the expected issuer.
The running executable SHA-256 equals the built candidate. The requested pinned
registry manifest resolves to the same image configuration as the container.
The image revision is the final source SHA; the container revision label is old
metadata inherited by ctl replacement and is not used as deployment evidence.

The official run uses `nazoauthctl-selected --instance production oidf run --json
--jobs 4 --poll-timeout 1800` against `https://www.certification.openid.net`.
All 44 plans were created, with 1,173 defined modules and no plan exclusions.
The temporary tenant, browser workers and Suite resources belong to this run.
Final outcomes are recorded below; subsequent correction runs retain separate identities and evidence.

## Initial official-suite outcome and necessary follow-up

The official service reported version **5.3.2**. The controller bundled matrix
labels its original source as v5.2.2; these are distinct identities. The executed
matrix digest is recorded in `oidf-initial-summary.json`.

The initial run exited 1: **1,013 PASS, 17 REVIEW, 10 WARNING, 11 SKIPPED,
67 FAIL**, plus **7 created incomplete modules and 48 modules not instantiated**.
The run retained all 44 official plans for review. Run-owned tenant cleanup and
Suite resource settlement succeeded; this does not make incomplete modules pass.
The exact module ledger is `oidf-initial-modules.csv`.

Root causes independently established from official logs and code:

- 61 failing modules encounter an mdoc MSO `signed` timestamp before the document
  signer certificate's `notBefore`. Privacy rounding to midnight can predate a
  certificate generated later that day. Source
  `8abe4fe33891621ce2659f78d6bc2c224f042e17` clamps the privacy timestamp to the
  public certificate validity boundary, preserves credential expiry, and rejects
  impossible intervals. It does not weaken verification or extend safety TTLs.
- Two HAIP multiple-client modules failed PAR after the old controller stalled
  waiting for a second offer, allowing the five-minute wallet attestation to
  expire. Controller offer tracking must distinguish the bounded second client.
- Four HAIP negative modules accepted authorization without PAR because the
  bundled attested-client registrations did not enable the existing required-PAR
  policy. The fixture must explicitly enable that policy; wallet attestation
  authentication is retained. [HAIP 1.0 section 4](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#name-openid-for-verifiable-credent) requires PAR when the authorization endpoint is used.
- All seven VP plans stopped on their first module because the official wallet
  now displays a result page instead of redirecting. The target accepted the
  direct POST. The controller must visit the transaction-bound completion URL
  and require the target's actual verified result, retaining signed evidence and
  official human-review outcomes.

Four second offers were supplied through the normal issuer API during the first
run to unblock observation. Their module IDs are recorded in the summary. This
is an **assisted run**, not proof of corrected automatic orchestration. Later
runs must use the corrected controller without this assistance.

A fresh post-upgrade backup attempt failed before deployment because the old
controller sentinel queried the retired `oauth_tokens` table. The repair probes
the schema and counts durable `oauth_token_issuances` when the old table is absent.
Legacy snapshots keep their exact original sentinel format. Twenty backup tests
and a real isolated PostgreSQL legacy/current-schema check pass. A new complete
snapshot and restore rehearsal are still required before the next cutover.

Warnings remain official warnings, including unadvertised requested scopes.
REVIEW remains human review; neither exit status nor temporary-resource cleanup
can promote these outcomes to PASS. No performance conclusion follows from this run.

The first automatic correction run used server `8abe4fe3` and ctl `4b4984b5`.
Backup snapshot, real restore-test, deployment, doctor and public verify all
exited 0. The running executable and pinned image were independently matched.
This run was deliberately interrupted (exit 130) after 149 PASS, 3 WARNING,
2 SKIPPED and 3 interrupted modules: two-client issuer-initiated modules still
waited for an offer. It did not receive manual assistance. Run-owned resources
were cleaned. The local completed-browser cache was insufficient as a phase
authority; the next controller revision follows explicit official Offer-wait
transitions, including completion performed by other registered browser workers.

One fresh-certificate batch raised official `VCIEnsureBatchTimeClaimsNotLinkable`
WARNING: clamping to certificate notBefore produces a precise shared timestamp
near creation time. The certificate boundary is shared public material, not a
per-holder timestamp. The warning is retained for review, not relabeled PASS;
certificate validity is not backdated to suppress it.

## Final result

Server source: `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
Controller source: `dbd8b0647731dcf4fa3d725cd8269fc745f9e5ee`.
Both repair branches remain unmerged at publication time.

The final command was:

```sh
nazoauthctl-selected --instance production oidf run openid4vc --json --jobs 4 --poll-timeout 1800
```

It exited **0** after **671.742 seconds**. All **397 modules in 17 plans** were
created and settled: **364 PASS, 24 REVIEW, 6 WARNING, 3 expected SKIPPED,
0 FAIL, 0 incomplete**. No manual offers, excluded plans, extended lifetimes,
threshold relaxation or verifier bypass was used. All ordinary and HAIP
multiple-client issuer flows passed. Two recorded second offers arrived 415 ms
and 314 ms after their official second wait, with exactly two delivered offers
per module. All four HAIP non-PAR negative tests passed.

The 24 REVIEW results are VP screenshot review obligations. All 24 real
WebDriver screenshot files and all 397 module evidence files were hash-checked
against the final evidence manifest. Two warnings concern precise shared mdoc
certificate-boundary timestamps in newly created signer batches; four concern
requested scopes omitted from discovery. They retain their official outcomes.
`local_success=true` and `matrix_expectations_satisfied=true`, but
`suite_pass=false` and `acceptance_pass=false`: **execution complete is not
certification acceptance**.

Run-owned tenant cleanup succeeded, run/material journals are absent, all
Suite resources are settled, and retention and evidence manifest hashes match.
The 17 official plans remain retained for review; the report's generic
`cleanup_complete=false` reflects retention, not a leaked temporary tenant.
Post-suite doctor and public verification both exit 0.

The combined coverage ledger contains the 776 unaffected OIDC/FAPI/CIBA modules
from the first run and these 397 corrected OpenID4VC modules: **1,107 PASS,
41 REVIEW, 14 WARNING, 11 expected SKIPPED, 0 FAIL, 0 incomplete** across the
original 1,173 definitions. This is explicitly composite evidence with source
and run identities per row, not a second full-matrix run on the final SHA.

- [Final outcomes and retained plans](../../../evidence/deployment-upgrade-20261010/oidf-final-summary.json)
- [Composite module ledger](../../../evidence/deployment-upgrade-20261010/oidf-final-composite-modules.csv)
- [Commands, negative proofs and deployment verification](../../../evidence/deployment-upgrade-20261010/current-repair-validation.json)
- [Actual second-offer delivery timing](../../../evidence/deployment-upgrade-20261010/second-offer-delivery-proof.json)

The validated controller is retained root-private on the deployment host under
`/var/lib/nazoauthctl/evidence/main-oidf-20261010/offer-phase-fix/nazoauthctl-selected`.
The globally installed released v0.2.30 controller was not overwritten; use the
validated controller for upgraded-schema backups until the controller repair is
released. The formally provisioned recovery administrator, MFA recovery material
and controller keys remain root-private; existing accounts were not reset.

No new performance or long-term storage conclusion is made. The subsequent
[complete REVIEW/WARNING review](oidf-review-2026-10-11.md) found concrete remaining
evidence work: 17 OIDC screenshots are absent, and two mdoc privacy warnings
remain open. The 24 VP image obligations and 12 scope warnings are locally
accepted without changing official results. Final report-head CI passed
(9 checks passed, 2 workflow skips); the controller passed all four platforms.
The review is not OpenID Foundation certification approval.
