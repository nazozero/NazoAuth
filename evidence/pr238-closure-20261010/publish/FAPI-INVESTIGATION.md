# Investigation of B1 mixed FAPI P95 failure

B1 source `667060893661dae2c2e31289d5d86ca6474132c3` has a real failure: FAPI full-operation P95=109ms against the unchanged 100ms gate. Its P99=128ms, successful rate=30/s, drop=0, unexpected errors=0 and unfinished=0. Main mixed is 1599.977 success/s with 4/35/71ms and drop=0; refresh is 600/s with 5/12/25ms and drop=0. The failed result is retained in candidate/MIX300/short-result.json.

The repeat protocol was declared before launching more runs in confirmation-plan.json: one full original-window A2 control followed by one B2 candidate, each at the original load, VUs, sidecars, security profile and thresholds. No source change, pool resizing, TTL reduction or manual cleanup is introduced to get a green result. A/B binaries are already frozen images; the checkout is not switched or duplicated.

## Observed timing and code boundaries

`fapi-diagnostic.json` aligns main, FAPI, metadata and refresh histograms to the same UTC window. B1 FAPI P95 is in (100,200]ms in many 30s buckets but returns to (20,50]ms at offset 90s. Metadata returns from (5,10]ms to (1,2]ms in that same bucket, and rises again with FAPI. Neither curve shows a monotonic accumulation-driven rise. Original A has FAPI P95 in (20,50]ms across its window and metadata mostly in (1,2]ms.

The production metadata/JWKS handlers in `crates/http-actix/src/metadata.rs` call `ApplicationMetadataSnapshotSource` in `crates/authorization-server/src/domain/metadata.rs`. That implementation loads key/module snapshots in memory. These files are unchanged between A and B. Their handlers have no database borrow, new health query or per-request wait queue. This is evidence that the shift is not specific to the modified SQL adapter, not proof that database timing can never matter elsewhere.

The FAPI HTTP/token paths are also unchanged by this revision. The mTLS change removes only the unused copied validity boolean after DER validity was checked. The revocation UUID and two control metadata fields are not written by this successful FAPI scenario. Audit health narrows an existing query projection; it adds no call, transaction, artificial delay or new queue. The actual Required worker still starts immediately and awaits commit, as verified by final-source regressions. The pool already uses `RecyclingMethod::Fast`; there is no new checkout ping to remove.

Per-process application sampling shows maximum 10s-average per-thread use of approximately 0.148 cores in A and 0.146 in B1. This does not exclude brief bursts or scheduler delay, but does not show a serial CPU-saturated application thread. Runtime-role PostgreSQL snapshots have maximum sampled oldest transaction age 12.428ms in A and 29.264ms in B1. They distinguish exporter/observer connections and idle ClientRead from active application borrowers. Ten-second snapshots cannot establish every request's connection-hold time or rule out unsampled stalls.

The user-designated CNB UI was read during the following revoke point. Its earlier displayed 5m server load was 61.33/64 and subsequently 50.98/64 at 00:46:34 UTC. These are shared-server load averages, not application CPU percentages or retrospective per-request scheduling proof. The UI's displayed CPU 0% is not treated as zero CPU consumption. Exact timestamped additional observations are in shared-server-panel.csv. The cgroup sampler's common parent values are not attributed separately to each container.

## Interpretation

The cross-endpoint co-movement, unchanged metadata path, absence of measured single-thread saturation and draining security-state cohorts support a common scheduling/transport/resource-delay hypothesis. They do not establish a new code bottleneck or justify adding caches, widening the connection pool, removing commit confirmation or weakening FAPI. The control/candidate confirmation results and final gate status belong in REPORT.md. Any failing observation remains FAIL rather than being waived simply because CNB is shared.


## Predeclared confirmation outcome

A2 completed at the unchanged original gate: mixed 1599.990 success/s, P95/P99 12/24ms and drop=0. FAPI was 30/s, 31/53ms, drop=0. Refresh was 599.437/s, 8/21ms, with 211/225000 drops (0.0938%); it passes the original 0.1% gate but is not described as an across-the-board improvement.

B2 uses the exact same source and binary as B1: mixed 1599.973 success/s, P95/P99 12/19ms, drop=0. FAPI was 30/s, 29/42ms, drop=0. Refresh was 600/s, 8/17ms, drop=0. All four sidecars passed. No code, queue, pool, TTL, workload or threshold was changed between B1 and B2. The predeclared confirmation stopped after this pair; there was no open-ended search for a passing run.

This does not establish that every B1 delay came from the shared host. It demonstrates that the B1 FAPI failure is not a stable behavior of the candidate at the prescribed load, and that the candidate reaches the original gates with all sidecars present. The original B1 failure remains in the report and raw metrics; final confirmation PASS is scoped to B2, not a claim that every repeated window or untested load always passes. No storage-backlog-driven monotonic P99 rise was observed in the final confirmation; the persisted decision cohort expired and was naturally reclaimed while requests continued.
