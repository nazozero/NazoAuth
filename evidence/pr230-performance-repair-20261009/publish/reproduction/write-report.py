from pathlib import Path
import json,shlex
E=Path('/src/evidence/pr230-performance-repair-20261009');P=E/'publish';q=json.loads((E/'verification-summary.json').read_text());src=json.loads((E/'final-source.json').read_text());metrics={x['key']:x for x in json.loads((E/'acceptance-metrics.json').read_text())};ledger=json.loads((E/'ledger-comparison.json').read_text())
def link(path):
 f=P/path
 if not f.exists() and f.with_name(f.name+'.gz').exists():path+='.gz'
 return '['+path+']('+path+')'
def table(keys):
 s='| Point | ops/s | P50/P95/P99 ms | success/planned | errors / expected rejection / unfinished | drop | result |\n|---|---:|---|---|---|---|---|\n'
 for k in keys:
  r=metrics[k];t=r['complete_operation_ms'];w=r['window'];s+=f"| {k} | {r['successful_ops_s']:.3f} | {t['p50']:.2f}/{t['p95']:.2f}/{t['p99']:.2f} | {r['outcomes']['success']}/{w['measure_scheduled_observed']} | 0 / 0 / {r['unfinished']} | {w['measure_dropped_exact']} ({100*w['measure_drop_fraction']:.4f}%) | {r['verdict']} |\n"
 return s
body=f'''# PR #230 — connection ownership repair and targeted acceptance, 2026-10-09

Final source: `{src['source_sha']}`. Direct A: `{src['baseline_sha']}` (report-only head over source `{src['baseline_underlying_source']}`). Source was fetched from the original PR branch. The initial container's unrelated clippy.toml edit remains preserved in a named stash. Only one checkout, target cache and writer were used.

This round fixes a proven resource-lifetime defect: a completed PostgreSQL read kept its borrowed connection until its request task was polled again. The existing pool runtime now owns the hot read through query completion and connection return; the request receives owned data. A real-database deterministic test fails on A and passes on B. All four original failing capacity points now pass their unchanged gates on the clean final binary. **This is not proof that this defect alone caused the earlier seconds-long slowdown:** unchanged A also passed in the later interleaved control. Normal-load B has slightly higher tails/app CPU than A, within the original gates. Neither shared CPU nor this patch is asserted as the sole explanation for historical variability.

| Dimension | Verdict | Evidence boundary |
|---|---|---|
| CODE | PASS | Final format, workspace all-target/all-feature Clippy, static/boundary checks, affected real database tests and full all-feature workspace suite. |
| SECURITY | PASS | Unchanged SQL predicates and safety boundaries plus actual identity/tenant/epoch/replay/Required and commit-boundary regressions. |
| RECOVERY | PASS | Affected cancellation/connection replacement and late commit failure boundaries; full workspace suite. Unchanged complete telemetry/exporter failure-load evidence remains historical. |
| PERFORMANCE | PASS | Four original failure points at unchanged load, VUs, pool32, Disabled application anchor and gates. Finite short tests, not a guarantee against arbitrary shared-host contention. |
| STORAGE | PASS | Short-window observation, exact audit reconciliation and 60,001 target decisions naturally reach zero after the last retention deadline and a complete real maintenance cycle. |
| Long-term target-load storage plateau | INVALID / not measured | This short-test round does not establish long-term plateau or infinite export-outage boundedness for Optional/Disabled. |

CI is considered only after local work and report publication. The full workspace invocation passed3,674 tests with4 ignored and exit0. Its ignored FAPI shared-secret rejection test was then explicitly executed with the real fixtures and passed. The other ignored entries are an isolated S3 TLS child invoked by its parent, a controller-wire external-input helper, and a live official-UI download test; they are not silently counted as passed. This report alone does not certify future shared-host performance, indefinite storage boundedness, or GitHub merge authorization. No merge or deployment was performed.

## Root cause, repair and failure proof

The original caller polled the query while owning the pooled connection. PostgreSQL could already be idle while an unpolled caller still occupied the only pool slot. Under delayed scheduling this unnecessarily couples reusable database capacity to request progress; pool waiting is the symptom, not a reason to increase the pool. The repair adds a private read boundary on the existing pool runtime for four client reads and three user reads. It returns owned rows/scalars, then does domain conversion outside the connection lifetime. There is no added capacity throttle, batching delay, durable queue, cache authority or recovery layer. Existing transaction paths remain unchanged.

`read_connection_ownership` uses a real PostgreSQL table lock and an independent observer. A caller is first polled until its query really waits on the lock; the lock is then released and the caller deliberately left unpolled. The observer confirms the backend is idle before attempting a second checkout of the sole pool slot. A compiles and fails at runtime, exit101: `completed database read still holds the sole pool connection until its caller is polled`. B passes all seven read cases. This is the isolated failing mechanism and repaired behavior, not a compile failure or missing fixture.

The second regression cancels a truly blocked read. Dropping the owner JoinSet cancels its task; the existing DiscardOnDrop retires an unfinished physical connection. The independent observer sees the old backend disappear before testing a different replacement backend. The isolated test PostgreSQL enables `client_connection_check_interval=100ms`; this is fixture failure detection, not a production default timing promise. Cancellation is never asserted to imply rollback of an already-committed write. Real `audit_commit_boundary` and `security_state_commit_boundary` tests exercise late commit error, cancellation and disconnection without confirmed-success fabrication.

Evidence: {link('negative-read-ownership-exit.json')}, {link('negative-read-ownership.log')}, {link('positive-read-ownership.log')}, {link('read-integration.log')}, {link('chain-review.json')}. An earlier candidate compile error, a missing-cargo observer attempt and a transient MinIO source-download failure are retained under their attempt names; none counts as negative behavioral proof or a passed gate.

The final production diff changes only the read ownership boundary and its consumers; SQL projections, tenant predicates, active flags, secret comparison, epoch and subject-binding checks are unchanged. Commit confirmation, ordered safety locks, consumption fence, revocation, Required completion, telemetry retry identity, receipt verification and all security TTLs remain intact. No cleanup schedule was modified.

## Connection ledger and scheduling

The complete authorization operation makes **11 logical borrows**: client reads5, public account2, subject snapshot1, audit preflight1, decision commit1, token issuance1. Full per-phase acquisition, holding, sampled SQL/BEGIN/COMMIT, residual other holding and ready-to-poll/poll-time profiles are in {link('ledger-comparison.json')} and the three point ledgers. Aggregates cover complete one-second buckets; they are not per-request traces.

| Stage | borrows/op | A acquire / hold ms | B acquire / hold ms | A SQL / commit / other sampled ms | B SQL / commit / other sampled ms |
|---|---:|---|---|---|---|
'''
def v(n):return 'n/a' if n is None else f'{n:.6f}'
for a,b in zip(ledger['DREADA2']['stages'],ledger['DREADB']['stages']):
 body+=f"| {a['stage']} | {a['logical_borrows_per_operation']} | {v(a['acquire_ms'])} / {v(a['hold_ms'])} | {v(b['acquire_ms'])} / {v(b['hold_ms'])} | {v(a['sql_ms_sample'])} / {v(a['commit_ms_sample'])} / {v(a['other_hold_ms_sample'])} | {v(b['sql_ms_sample'])} / {v(b['commit_ms_sample'])} / {v(b['other_hold_ms_sample'])} |\n"
body+='''
SQL/BEGIN/COMMIT are client-observed elapsed time, including driver/network/scheduling, not backend CPU. Matched sampled holding minus those values is application/other holding, not an invented CPU decomposition. Wake-to-poll is reported separately and must not be added again to SQL wall time; it misses time before the driver wakes or before first poll. A's public-account future lacked a separate scheduling profile. Domain conversion coverage differs between caller-body and owner-query profiles, so poll CPU is not total request CPU.

In the earlier busy DREAD window, mean acquisition cost was roughly52–54ms per borrow; the observed pool reached944 waiters, with mean420.19. PostgreSQL statement times were much smaller. This exposed avoidable client-side ownership/scheduling coupling. Later DREADA2/B both sustained800ops/s: pool maximum waiting2→0, client-read hold0.126969→0.120873ms, public-account0.110362→0.107494ms and subject0.266306→0.262249ms. Token issuance commit confirmation was retained (sampled1.40015→1.49030ms). These later normal-load measurements do not reproduce the earlier overloaded state, and do not establish a seconds-scale patch-only improvement.

Database activity is separated by `nazoauth_perf_runtime`, `nazoauth_perf_exporter`, observer/admin `postgres`, and background roles. `ClientRead` alone is never equated with application pool occupancy. No credential values or request/user IDs are metric labels. Temporary diagnostic overlays and sampled logging were removed before the final gates and clean formal tests.

## Original-gate clean capacity results

All use pool32, Disabled application anchor, RUST_LOG=warn, original success semantics, P95≤100ms, P99≤250ms, success≥99.5%, drop≤0.1%. Formal windows are60s; original auth/revoke warmups and mixed60s warmup are preserved. Auth16=800ops/s with992VUs; revoke16=960 with992VUs; mixed1=400 with64VUs; mixed16=1600 with992VUs. Preparation, subject distribution, CPU affinity, sidecars and exact invocations are retained in each request JSON, manifest, health and command records. Every point took under10minutes. No build/test ran concurrently with load. Main and the old passing matrix were not rerun.

'''+table(['BREAD','AREAD','BREAD2','BREAD10','BREAD03','BREAD04'])+'''
The auth sequence is B/A/B. A is the unchanged original binary; B is the final clean binary. All started operations completed successfully, all sidecar/affinity/state checks and audit reconciliation checks passed, and there were no expected rejection or unfinished operations. Mixed1's13 drops are real (0.0542%, below0.1%); its64VU exhaustion warning is retained. Do not describe every point as drop-free. Other three points lack a new paired A in this scoped round; their earlier FAIL records remain historical references, not a controlled causal contrast.

The normal-load A P99=29ms versus B30/34ms is a small adverse tail change at equal800ops/s and zero drops; it remains far inside the original250ms gate. It is not presented as a universal latency improvement. The earlier severe reports cannot be erased because later A passes.

Rejected diagnostic configuration: default16 Tokio workers →2 →16 on the same original binary produced664.90→560.50→666.15ops/s, P99 1701→2240→1703ms and drop16.8892%→29.9390%→16.7313%. It worsened performance, was not adopted, and is not original-gate acceptance evidence. The entrypoint already applies affinity before exec, so the hypothesized after-start affinity mismatch was rejected by code inspection.

Separate instrumented diagnostic runs (not clean acceptance):

'''+table(['DREAD','DREADA2','DREADB'])+'''
Exact full-window quantiles/outcomes come from the harness's complete cohort. Ten-second series use complete-stream histograms and provide quantile intervals, not fake exact quantiles from sampled raw points. The interval/throughput/drop series must be read together: finite VUs or drops alone can flatten latency. In BREAD every10s bucket's P99 lies20–50ms, with no drops/unfinished work and no growing tail. BREAD2 had one bucket in50–100ms and returned to20–50ms; revoke16 started in50–100ms then stayed20–50ms; mixed16 ended in10–20ms. Mixed1 had a real last-bucket rise to100–200ms (maximum256ms), together with13drops, so it is not described as perfectly flat. Its whole-window P99 remains24ms and drop0.0542%, within the unchanged gates. Per-point time-analysis JSON, time-series-summary.json and storage CSV retain all windows.

## Storage, audit and natural reclamation

| Point | WAL bytes/success | app/PG mean cores | sampled physical DB first→last bytes | sample span s | Valkey final bytes |
|---|---:|---|---|---:|---:|
'''
for k in ['BREAD','AREAD','BREAD2','BREAD10','BREAD03','BREAD04']:
 r=metrics[k];c=r['cpu_cores'];body+=f"| {k} | {r['wal_bytes_per_success']:.3f} | {c['app']}/{c['postgres']} | {r['db_sample_first_bytes']}→{r['db_sample_last_bytes']} | {r['db_sample_seconds']:.2f} | {r['valkey_last_bytes']} |\n"
body+='''
WAL is normalized by successful formal operations; physical DB endpoints cover their actual stated sampler windows and are neither per-operation nor uniform60s growth. CPU means are occupied cores, not per-op cost. Valkey is total instance memory, not persistent disk bytes. A/B auth WAL is broadly similar (10408 versus10444/10379), with no claimed broad storage reduction from a read-only change.

For final-source BREAD2, the follower was attached after reconstruction to the actual application instance and records the matching instance identity. A frozen60001-decision cohort had its last business retention deadline at2026-10-09 03:24:02.912406UTC. The03:23:46 cycle deleted46560 but was not accepted as the final cycle. The complete natural maintenance cycle at03:24:46.611386UTC deleted the remaining13441 in56batches/493ms with stop_reason=drained. The independent03:24:50.264444UTC sample confirms cohort remaining=eligible=retained=unexported=0. The sum of actual logged decision deletions is60001. Total point duration319.8s.

At terminal observation,9920 live families,60001 issuance receipts and992 referenced contracts were preserved; no eligible family/orphan/spent/pending backlog remained.171075 database audit facts match receiver events and the signed checkpoint chain. No manual delete, shortened TTL, maintenance invocation or manual vacuum was used. Physical database size240252607bytes remains a high-water observation; live logical count, dead tuples, natural autovacuum and retained reusable space are distinguished. Cumulative n_tup_del statistics are asynchronous and never replace actual cohort counts.

During BREAD load the pending maximum was110 and oldest pending0.035712s, then0 after drain. BREAD2 pending peaked860/0.164383s, mixed1 893/1.949402s, mixed16 490/0.565432s and revoke16 109/0.032234s; all drained and reconciled. These transient peaks are retained rather than hidden behind end-state zero. This finite load plus natural post-retention cycle establishes short-run progress and reclamation, not indefinite outage disk bounds or long-term steady state. Optional/Disabled behavior is unchanged. The full prior signed receiver/exporter recovery fault load was not rerun because this patch does not change it; affected real transaction/cancellation tests and the complete workspace suite were rerun.

'''+link('BREAD2/decision-natural-reclamation.json')+'; '+link('BREAD2/storage-series.csv')+'; '+link('BREAD2/time-analysis.json')+'; '+link('acceptance-metrics.json')+'''. The exact retention/eligibility samples and real application maintenance log are in BREAD2; audit reconciliation/checkpoint files exist per point. Raw signed payload journals remain private in the isolated evidence; their hashes and reconciliation are published, not credentials or bearer material.

## Actual verification commands and exits

All commands below ran inside the authorized isolated CNB with real PostgreSQL, Valkey and the exact repository MinIO test fixture. Single target cache; fixture credentials excluded. Full suite uses serial test execution as configured by the repository fixture environment. Final-source identity and checks are in verification-summary.json. Check counts below are invocation counts, not a deduplicated total across overlapping runs.

| Check | Command | exit | passed / ignored | seconds |
|---|---|---:|---|---:|
'''
for r in q['checks']:
 cmd=r.get('command',r.get('cmd',''));cmd=shlex.join(cmd) if isinstance(cmd,list) else str(cmd);c=r['test_result_counts'];body+=f"| {r['name']} | `{cmd}` | {r['exit']} | {c['passed']} / {c['ignored']} | {r.get('seconds',0):.2f} |\n"
body+='''
Negative proof command: `cargo test --locked -p nazo-postgres --test read_connection_ownership -- --nocapture`, exit101 on A after successful compilation and a real failing assertion. Final positive command and full suite are above. All diagnostic/formal point commands, manifests, exact source/binary hashes, wrapper exits and raw logs are published; a wrapper's transport success is never used to replace its nested process exit.

Final source release binary SHA256: `'''+src['candidate_binary_sha256']+'''`; original binary SHA256: `'''+src['baseline_binary_sha256']+'''`. Instrumented builds have distinct hashes and diagnostic_only=true. The report commit will be recorded separately in the PR body/comment; this file cannot self-reference its eventual Git commit.

Reproduction scripts, artifact hashes and raw capacity series are in this directory. Large logs are gzip-compressed without content changes. Filtered k6 raw files retain original cap_* / iteration / drop / VU records; HTTP metrics that could contain request material are omitted. Whole-window exact summaries and full-stream histogram analysis remain authoritative. Published artifacts are checked against known fixture credentials, private-key and token patterns before commit.

## Remaining limits and retained history

- The deterministic completed-read ownership defect is fixed. The exclusive cause of the historical severe capacity swings remains unproven because unchanged A later passes. Shared CPU is a possible limitation, not an automatic waiver or established cause. No host probes were performed.
- This finite four-point PASS is the original scoped capacity gate. It does not guarantee every future shared-machine window or claim all old15scenarios were rerun.
- Long-term target-rate storage plateau remains unmeasured; legitimate security retention and physical high water are not pending backlog. Infinite Optional/Disabled export-outage boundedness is not claimed.
- CI and repository merge policy are checked separately after publication. Final merge belongs to the owner.

Historical reports are retained without overwrite: [previous bottleneck round](https://github.com/nazozero/NazoAuth/blob/5005b39182f42c53537ed45ce21a72db7db92af5/evidence/pr230-bottleneck-20261009/publish/README.md), [earlier connection investigation](https://github.com/nazozero/NazoAuth/blob/7d7ed5fddc5c91201bcac94553a6e72836d471d7/evidence/pr230-performance-20261009/publish/README.md), [recovery acceptance](https://github.com/nazozero/NazoAuth/tree/298cf845c58b2caab0128ac07f5eacd3e50fb355/evidence/pr230-recovery-20261008/publish), [revision acceptance](https://github.com/nazozero/NazoAuth/blob/e13fcfd1292283f135906a31de987b533f002de8/evidence/pr230-revision-20261008/continuation/publish/README.md).
'''
(P/'README.md').write_text(body)
print('report_bytes',len(body.encode()))
