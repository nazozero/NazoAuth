# PG physical growth investigation and correction

Source candidate: `4ccd02de2767a7dd586f19ccb7cf502197e02aeb`.
Baseline report head: `432d87e523106b476dc5249390c29f82cb2615b4` (production files equal `667060893661dae2c2e31289d5d86ca6474132c3`).

## Current acceptance after retest (2026-10-10)

**PERFORMANCE: PASS for the completed current-candidate retests at the original workload and gates.** AUTH_CAP passes 180 formal seconds at 800 ops/s and 992 VUs (P95/P99 20/38 ms); CC_RETEST passes 600 formal seconds at 4,000 ops/s and 992 VUs (10/26 ms). Both have zero drop, unexpected error and unfinished operation. CC_RETEST also shows pending returning to low hundreds while requests continue, with no rising minute-level P99.

This is a candidate acceptance decision, distinct from immutable per-run measurements. AUTH_B30 and CC_B15 retain their measured FAIL verdicts below as historical anomalies, but those diagnostic windows no longer force the current candidate's scoped performance conclusion to FAIL after valid same-source retests. Shared resource contention and added observation cost limit causal attribution; shared CPU is not proven to be the sole cause. The authorization retest covers three minutes, not a repeated 30-minute window. No unmeasured path or unlimited-duration guarantee is implied.

The raw run verdicts, thresholds, counters and failure evidence are unchanged. See [evidence retention policy](../../README.md) for the compacted diagnostic inventory and retrieval of original snapshots.

## Findings and changes

Physical growth was not one phenomenon. The earlier authorization-code window included filling the valid receipt retention window, expired rows awaiting natural maintenance, MVCC dead tuples awaiting autovacuum, and allocated heap/index pages subsequently reused. Two byte costs were independently unnecessary and have been removed:

1. `AuthorizationCodeHolderEvidence` serialized unused proof options as explicit JSON nulls. In the actual PKCE workload, three null members carried no additional fact. Optional members now serialize only when present. The same checked restorer still accepts old explicit-null encodings; version, authenticated-client binding and every present proof remain validated. Measured actual PostgreSQL holder size falls from 187 to 116 bytes (71 bytes, 37.97%); this is the holder column, not a claim about total database reduction.
2. The single-use unique index repeated tenant UUID beside an internal globally unique client UUID. `oauth_clients.id` is the global primary key, and the validated, nondeferrable `(client_id, tenant_id)` foreign key remains authoritative. The index now uses `(client_id, single_use_key_blake3)` with the same non-null predicate. Every tenant predicate and stored tenant value remains. An isolated identical 300,000-key fresh-index comparison measured 28,688,384 → 23,265,280 bytes (18.90% reduction), independently of old-index fragmentation.

The second change is a coordinated application/schema change: the old three-column `ON CONFLICT` statement fails closed after the migration. Both populated upgrade and downgrade preserve facts. There is no new compatibility authority, queue or recovery layer.

## Why retained receipts cannot simply be deleted

In this scenario, authorization-code receipts bind a consumed code to the issued access-token identity and refresh family. They support replay rejection, associated-token revocation and recovery after an uncertain commit acknowledgement. RFC 6749 §4.1.2 requires rejecting code reuse and recommends revoking associated tokens when possible. The measured 360-second retention is this configuration's 300-second token lifetime plus 60-second verifier skew, not a duration prescribed by the RFC. At 800 successful operations/s, approximately 288,000 still-valid receipts are expected. Deleting those to make a graph flat would change security behavior.

References: [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2), [PostgreSQL 18 vacuum behavior](https://www.postgresql.org/docs/18/routine-vacuuming.html). Ordinary vacuum makes dead-row and index space reusable and does not generally return the whole allocation to the OS. Therefore live rows, eligible rows, dead tuples, reusable pages and physical file bytes are reported separately.

## Regression evidence

The old serializer actually fails the new absence-of-null assertion (exit 101); the old three-column index actually fails the new key-width assertion (exit 101). Neither is a build error or missing-fixture skip. Candidate results: core suite 180 passed; real PostgreSQL key-scope/migration tests 2 passed; issuance atomicity tests 16 passed; HTTP holder/uncertain-commit identity tests 4 passed. Real database tests ran with isolated PostgreSQL/Valkey credentials and CI=true. Format, touched-package all-target/all-feature Clippy, persistence dependency boundary, canonical static contracts and release build passed.

The initial static-contract command failed because the new migration had not yet been appended to the checksums. The supported append command corrected the manifest; existing migration history was unchanged. Exact commands and exits are retained in `quality/`.

## Measurement boundaries

All runs use the existing authorized CNB single checkout/target and isolated test databases. PostgreSQL durability stays enabled. No manual deletion, VACUUM, shortened TTL or lowered acceptance threshold was used. Shared-server UI Load 1m observations are retained; correlation does not prove environmental causation.

`AUTH_DIAG` and `AUTH_A_CAP` are INVALID as full capacity points because the request source SHA was `432d87e5...` while the reused image truthfully identified its build source as `6714d318...`. Their production inputs are byte-identical, but the strict provenance checks were not bypassed. `AUTH_A_CAP2` uses the actual image source SHA, with a saved successful `git diff --exit-code` proving equality of application inputs and the performance harness to the pre-revision report head.

The optional forensic trace also reached its bounded 512 MiB logical budget. The harness explicitly treats that as a forensic limitation, not by itself as INVALID. Formal cohort aggregates and independent storage observations remain separately complete. The request metadata flag `diagnostic_only=false` does not disable the original bounded forensic collector. Normal capacity arms keep the original sampler and omit only the added pgstattuple/pgstatindex scans; no claim of zero instrumentation overhead is made.

`AUTH_B` emitted no load: its initial 1,800-second harness budget was shorter than the 1,845-second planned total including warmup/guards. The failed preflight is preserved. `AUTH_B30` uses the existing load-budget setting of 2,700 seconds and unchanged workload/success thresholds. Physical page scanning makes long storage diagnostics unsuitable as clean causal performance comparisons. Capacity failures remain failures.

The paired capacity arms add the same small read-only WAL-directory-size and checkpoint-counter projections to their existing SQL observer. `pg_database_size` excludes WAL, and cumulative `wal_bytes` is a generation counter rather than retained disk occupancy. A late CC_B15 WAL-directory probe was attempted after its owned database container had already been cleaned up; its exit 1 and missing sample are preserved, never recorded as a zero-byte result.
## Classification of the observed growth

| Stored data / allocation | Necessity and measured lifecycle | Action in this revision |
| --- | --- | --- |
| Authorization-code issuance receipts | One-use/uncertain-commit evidence; live population fills the configured validity horizon. About 288,000 receipts at 800/s and 360 s are expected, not an unbounded request history. Expired eligible rows are reclaimed naturally. | Removed null proof members and redundant tenant index bytes; kept proof binding, transaction and retention. AUTH_B30 proves all final receipts naturally reach zero. |
| Authorization decisions | Required evidence can be removed only after export and business retention. | Tracked real application instance and natural maintenance cycles; final target batch zero, without changing schedule or TTL. |
| Audit event / chain pending rows | Events awaiting signed receiver ACK are real durable work. Their count can grow when export throughput is below event creation throughput. | Preserve identities and ACK checks; separately measure input/export rates and drain. This is not safe-to-delete redundancy. |
| Live refresh families / contracts | They support still-valid refresh and revocation. AUTH_B30 ends with 9,920 legal families, no eligible family or orphan contract. CC's 992 families are seeded fixture state, not one family per client-credentials request. | Keep legitimate state; no attempt to force the whole database to zero. |
| Spent refresh tokens / revocations | They are anti-replay / deny-list facts through their existing security horizon. Old raw series distinguish creation from scheduled reclamation. | No TTL reduction or premature erasure. |
| MVCC dead tuples and free heap pages | Physical slots left by normal delete/update and vacuum; they are not live domain records. Continuous insertion reused the receipt heap: 129.09 MiB at approximately 844, 963 and 1,084 seconds, then natural shrink to 109.96 MiB around 1,204 s. | No redundant reaper, forced VACUUM FULL or manual purge. Reuse is measured with pgstattuple, not inferred solely from file size. |
| B-tree high-water allocation | Vacuum marks empty index pages reusable. After AUTH_B30 all receipts are gone, the compact one-use index has 5,593 deleted pages and zero live-leaf density; other receipt indexes likewise retain deleted pages. These bytes are allocated space, not undeleted receipt facts. | Reduce proven unnecessary key width. Avoid a recurrent blocking rebuild merely to shrink the file after every burst. No claim that every allocated byte is a semantic minimum. |
| WAL files | WAL generation is required for unchanged durability; retained WAL disk is governed by checkpoint/recycling and differs from the ever-increasing generation counter. The measured configuration has no replication slots, archive off, checkpoint_timeout 300 s and max_wal_size 8,192 MiB. | Add actual WAL directory and checkpoint time series. No weakened fsync, synchronous_commit, checkpoint forcing or fabricated zero sample. |
| Valkey / receiver | Valkey is measured independently; the receiver append-only test journal is external audit output, not PostgreSQL table growth. | Retain aggregates and signed reconciliation; do not conflate the multi-GB receiver journal with application DB occupancy. |

The earlier matrix is retained in `historical-physical-growth.json`: mixed and mTLS tail allocations already decreased in some windows, PAR was flat, and short authorization/FAPI/cold windows were partly filling retention horizons. This follow-up establishes the physical mechanism in representative write-heavy authorization and client-credentials chains; it does not rerun or retroactively pass the entire matrix.
The all-relation ledger also accounts for growth outside the seven hot relations. In AUTH_B30, `user_client_grants` occupies 6,930,432 bytes after 1,450,894 updates but still has 992 live rows, zero estimated dead rows and 31 autovacuum runs. Its retained last authorization, scopes and count have actual grant-validation/admin-view consumers (`repositories/grants.rs`); this is a reused per-user/client projection, not an appended authorization history. The remaining fixture allocations include 993 users, six clients, one trust-anchor request and one SCIM token. The audit chain-state row remains one row. The complete per-relation before/after byte ledger and component-sum checks are published in `physical-ledger-*.txt` and `all-relation-deltas.json`; SQL statement text and credential-bearing environment files are excluded.

The valid normal-sampler comparison was collected in the order B (`AUTH_CAP`, UI Load 1m 83.72) then A (`AUTH_A_CAP2`, 70.04), after the earlier label-mismatched A was retained as INVALID. Both valid points use 180 formal seconds at 800 ops/s and 992 VUs. The difference is not presented as a causal percentage speedup; it establishes that both meet the unchanged gate in those windows. The 30-minute diagnostic's larger P95/P99 remains FAIL.

## Actual workload results

| Point | Capacity verdict | Formal seconds | Successful ops/s | P50/P95/P99 ms | Drop | Expected rejection | Other failed operations | Unfinished | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AUTH_DIAG | INVALID | 900.0 | 799.999 | 25.0/65.0/95.0 | 0 | 0 | 0 | 0 | 2 |
| AUTH_B | INVALID_NO_MEASUREMENT | — | — | — | — | — | — | — | — |
| AUTH_B30 | FAIL | 1800.0 | 799.385 | 125.0/347.0/948.0 | 1107 | 0 | 0 | 0 | 2 |
| CC_B15 | FAIL | 900.0 | 3540.747 | 220.0/361.0/430.0 | 413327 | 0 | 0 | 0 | 2 |
| AUTH_A_CAP | INVALID | 180.0 | 781.906 | 279.0/1414.0/1524.0 | 3256 | 0 | 0 | 0 | 2 |
| AUTH_CAP | PASS | 180.0 | 800.0 | 11.0/20.0/38.0 | 0 | 0 | 0 | 0 | 0 |
| AUTH_A_CAP2 | PASS | 180.0 | 800.0 | 12.0/24.0/56.01000000000931 | 0 | 0 | 0 | 0 | 0 |
| CC_RETEST | PASS | 600.0 | 4000.002 | 3.0/10.0/26.0 | 0 | 0 | 0 | 0 | 0 |

AUTH_DIAG/AUTH_B30/CC_B15/CC_RETEST are storage diagnostics. AUTH_A_CAP/AUTH_A_CAP2/AUTH_CAP use the original normal sampler without the added physical page scans. Capacity verdicts retain all original success and latency thresholds; diagnostic observer cost is not subtracted.

## Natural terminal state

| Point | Pending | Target decisions | Full cycle after target deadline | All receipts | Legal live families | Eligible families | Orphan contracts |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AUTH_DIAG | 0 | 0 | True | 291048 | 9920 | 3399 | 0 |
| AUTH_B30 | 0 | 0 | True | 0 | 9920 | 0 | 0 |
| CC_B15 | 0 | 0 | None | 0 | 992 | 0 | 0 |
| AUTH_A_CAP | 0 | 0 | True | 152745 | 9920 | 0 | 0 |
| AUTH_CAP | 0 | 0 | True | 156000 | 9920 | 0 | 0 |
| AUTH_A_CAP2 | 0 | 0 | True | 156000 | 9920 | 0 | 0 |
| CC_RETEST | 0 | 0 | None | 0 | 992 | 0 | 0 |

All 180-second capacity arms are shorter than the receipt retention horizon and are not used to prove receipt cleanup. AUTH_B30 covers the final receipt retention deadline and a full natural maintenance cycle; see its last-receipt-cohort.json and physical-analysis.json. N/A decision cycles in client credentials reflect absence of decision rows, not a skipped applicable case.

## Physical windows

| Point | Seconds from load launch | DB MiB median | Receipt table MiB | Receipt indexes MiB | Audit table MiB | Audit indexes MiB | Valid receipt count range | Max expired receipt age s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AUTH_DIAG | [0, 360] | 405.9 | 50.852 | 35.773 | 128.0 | 76.312 | [0, 275661] | 0 |
| AUTH_DIAG | [360, 600] | 593.986 | 137.699 | 96.562 | 130.855 | 98.82 | [283681, 287563] | 58.412332 |
| AUTH_DIAG | [600, 900] | 618.736 | 157.117 | 110.555 | 131.359 | 99.988 | [287510, 287638] | 57.402091 |
| AUTH_DIAG | [900, 1200] | 631.474 | 157.117 | 114.359 | 133.242 | 101.344 | [239852, 287601] | 63.401868 |
| AUTH_B30 | [0, 360] | 371.521 | 41.098 | 32.703 | 123.781 | 68.566 | [0, 275645] | 0 |
| AUTH_B30 | [360, 600] | 541.802 | 103.75 | 82.535 | 135.688 | 94.605 | [283628, 287958] | 54.867623 |
| AUTH_B30 | [600, 900] | 607.279 | 129.156 | 105.602 | 141.57 | 97.891 | [287505, 288006] | 57.901121 |
| AUTH_B30 | [900, 1200] | 614.783 | 129.156 | 109.0 | 144.141 | 103.578 | [287719, 288152] | 57.910803 |
| AUTH_B30 | [1200, 1500] | 618.998 | 118.102 | 109.883 | 146.625 | 104.922 | [287836, 288329] | 58.937805 |
| AUTH_B30 | [1500, 1800] | 623.263 | 121.703 | 113.48 | 145.008 | 105.562 | [285908, 288257] | 54.952772 |
| AUTH_B30 | [1800, 2400] | 441.146 | 110.656 | 113.789 | 0.023 | 106.312 | [0, 286885] | 58.9838 |
| CC_B15 | [0, 360] | 230.951 | 0.008 | 0.039 | 130.008 | 26.68 | [0, 0] | 0 |
| CC_B15 | [360, 600] | 256.384 | 0.008 | 0.039 | 145.219 | 30.273 | [0, 0] | 0 |
| CC_B15 | [600, 900] | 278.74 | 0.008 | 0.039 | 165.047 | 32.5 | [0, 0] | 0 |
| CC_B15 | [900, 1200] | 256.998 | 0.008 | 0.039 | 165.445 | 34.297 | [0, 0] | 0 |
| CC_RETEST | [0, 360] | 160.322 | 0.008 | 0.039 | 59.711 | 23.422 | [0, 0] | 0 |
| CC_RETEST | [360, 600] | 171.232 | 0.008 | 0.039 | 59.824 | 24.562 | [0, 0] | 0 |
| CC_RETEST | [600, 900] | 85.576 | 0.008 | 0.039 | 0.023 | 24.562 | [0, 0] | 0 |

These are allocation and row observations, not equal-work normalized total database savings. Detailed pgstattuple live/dead/free bytes and pgstatindex density/deleted pages are retained in physical-pages.csv and physical-indexes.csv.

## CPU and WAL

| Point | Application average cores | PG average cores | WAL bytes/success from collector | WAL raw endpoint delta bytes |
| --- | --- | --- | --- | --- |
| AUTH_DIAG | 1.763 | 4.058 | 11637.522 | 8373648498 |
| AUTH_B30 | 1.749 | 4.046 | 11628.168 | 16718338323 |
| CC_B15 | 2.344 | 2.035 | 1872.517 | 5961407280 |
| AUTH_A_CAP | 1.732 | 4.104 | 10799.305 | 1503864570 |
| AUTH_CAP | 1.63 | 3.473 | 10361.183 | 1479704316 |
| AUTH_A_CAP2 | 1.663 | 3.731 | 10505.859 | 1506176830 |
| CC_RETEST | 2.183 | 2.076 | 1772.487 | 4249386857 |

CPU uses owned service process jiffies, with explicit limitations for terminated PG backends in resource-analysis.json. WAL generation endpoints and full time series are preserved; retained WAL allocation and checkpoint counters are separately in wal-disk-series.csv and wal-disk-analysis.json. No host CPU/disk probes were used.

## Commands and integrity

Actual command arrays, start/end times and exit codes are in commands.json and per-command exit JSON. Source candidate is the exact image source in build.json. This report commit adds evidence only. SHA256SUMS covers retained published files. This documentation revision updates current acceptance and compacts repeated affinity diagnostics; historical per-run verdicts and essential raw measurements remain unchanged.

## Final scoped conclusions

| Dimension | Verdict | Evidence and scope |
| --- | --- | --- |
| CODE | PASS | Candidate 4ccd02de: 202 unique targeted cases; format, touched-package Clippy, static/boundary checks and release build all exit 0. Negative behavior failures are real assertion failures. |
| SECURITY | PASS for changed boundaries | Actual PostgreSQL tenant FK/global client identity, replay uniqueness, populated up/down migration, issuance atomicity and checked HTTP holder restoration remain enforced. |
| RECOVERY | PASS for observed drain/reconciliation and targeted identity cases | All valid points finish with signed database/receiver/checkpoint agreement. The prior unchanged physical late-commit/cancellation/disconnect fault suite is referenced, not represented as newly rerun. |
| PERFORMANCE | PASS for completed current-candidate retests | AUTH_CAP: 180 seconds at 800/s; CC_RETEST: 600 seconds at 4,000/s; original gates and security configuration unchanged. Historical diagnostic FAILs remain as run-level evidence, not the current candidate verdict. No all-path or unlimited-duration claim. |
| STORAGE | PASS for the identified redundant bytes and natural reclamation objective | Two unnecessary representation costs removed; final authorization receipt batch and decision batch naturally reach zero after retention and a full maintenance cycle. Real unACKed audit work and reusable physical allocation are explicitly separated. |

The action was not to call every growing file necessary. The unnecessary holder members and redundant unique-index key were removed. Valid replay receipts, live grants and unACKed audit evidence retain their existing purpose. Expired records and ACKed transient evidence have measured natural deletion; retained empty pages are available for reuse, not an undiscovered live-row retention owner.

- AUTH_B30: last receipt retention deadline **06:07:53 UTC**, full natural cycle **06:08:24.506 UTC**, final 23,550 receipts deleted in that cycle. The next full cycle at **06:09:24.668 UTC** deletes none. Final receipts, decisions, eligible families, orphan contracts and pending are zero; 9,920 legitimate active families remain. No manual purge/vacuum was used.
- At roughly equal early populations (92,018 old vs 91,998 new receipts), receipt heap is **34.45 → 27.77 MiB**. This supports the narrower field/layout evidence, not an equal-time whole-database percentage claim. The fixed 300,000-key index experiment was repeated with recorded command/exit 0 and identical byte results.
- CC_B15: actual continuous-load pending grows to **107,246**, oldest age **28.473695 s**, because measured event creation exceeds signed ACK throughput. Capacity is **FAIL**: **3,540.747 successful ops/s**, P95/P99 **361/430 ms**, **413,327 drops**. Pending drains after stop. These events could not safely be removed while unACKed.
- CC_RETEST: same source, original **4,000/s**, **992 VUs**, exporter batch limit **256**, unchanged safety configuration, **600 formal seconds**. **2,400,001** successful and completed operations; **4,000.002 ops/s**, P50/P95/P99 **3/10/26 ms**, **zero drop/error/unfinished**. Every full minute's P99 histogram lies in **20–50 ms**, with no upward progression. Median pending **169**, peak **4,854**, peak age **1.206531 s**, followed by return to the low hundreds during continued load and terminal zero. This run does not exhibit cumulative backlog; it does not erase CC_B15 or prove shared CPU is the sole cause.
- CC_RETEST reconciles **2,460,004** issued events including warmup/preparation with the expected issuance count, database head, receiver and signed checkpoint; zero sequence gaps/duplicates. The authorization points reconcile the complete observed persisted prefix, but their validator marks `token_issued_scope=reported_only_no_clean_denominator`; no extra HTTP-success-to-event-count proof is invented for those points.
- CC_RETEST physical database falls from **183,842,495** bytes at the last active sample to **89,732,799** bytes after natural drain/maintenance. Two timed PostgreSQL checkpoints complete. WAL directory allocation settles at **3,841,982,464** bytes through the final observations; that is recycled/reserved WAL disk, separate from **4,249,386,857** newly generated WAL bytes between formal collector samples. `max_wal_size` is a checkpoint target, not a hard disk cap. No replication slot/archive retention was present in this test configuration.
- Mature CC Valkey memory is approximately **1,802,200 bytes** across all three late windows. It is neither the external multi-GB receiver journal nor PostgreSQL WAL.

Acceptance scope is concrete: the completed current-candidate retests pass; original long-window failures remain historical observations. Only the scoped mechanisms and finite windows above are accepted. The test does not promise unlimited audit storage under indefinitely unavailable export, zero physical reserve after bursts, or all-path infinite-runtime flatness. No already-completed unaffected fault matrix or main benchmark was rerun.

Read-only observer errors after database shutdown are retained in the execution/physical-analysis logs. They occur during owned fixture cleanup after terminal measurements and signed validation; task cleanup reports no remaining test containers. Optional forensic trace truncation is also retained separately from the formal aggregate verdict. Historical evidence is not overwritten.