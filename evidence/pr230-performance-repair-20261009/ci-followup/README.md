# PR #230 — PostgreSQL cancellation fixture follow-up

Final source: `7646b82c9e8d5954cd3065846a28f312ed5c9d18`. Measured production source remains `ef89417c9377ea765878b24d7b034a189638dee3`. Previous report: `7ccf7c8eb4cd2e94a0aff526de10a013ab03dee9`.

The first report HEAD's Rust CI failed at the newly added cancellation test. It held its own table lock while demanding that PostgreSQL notice a closed client socket within10s. The CNB fixture had `client_connection_check_interval=100ms`, while CI uses the PostgreSQL default0. The test therefore depended on an undeclared fixture setting. This was a real CI failure; the previous local PASS is not presented as an all-green final acceptance.

With the default0 explicitly supplied to connections in CNB, the unchanged test reproduced the identical timeout after successful compilation: one failed, one passed, exit101. An earlier URL-options encoding mistake failed before the behavior was exercised; it is preserved under options-attempt1 and does not count as the negative proof.

Only `crates/persistence-postgres/tests/read_connection_ownership.rs` changed. The corrected test explicitly sets the tested session to default0, cancels an actually blocked read, and first requires pool size0 while the lock remains held. This proves cancellation discarded the connection before the query could finish normally. It then releases its own fault-injection barrier, independently waits for the old PostgreSQL backend to disappear, and only afterwards checks out a replacement with a different PID and successful SQL. A mere successful replacement is still insufficient. The original10s backend-observation deadline remains unchanged; the new5s wait is for the distinct discard event. No production cancellation, pooling, SQL, transaction or safety behavior changed, and no failed test was deleted or ignored.

Final-source default0 verification passes both tests, including all seven completed-read ownership cases. The real audit/cleanup late-commit, cancellation, disconnect and backend-retirement regressions also pass:7 tests total. Format and full workspace all-target/all-feature Clippy pass.

| Command | exit | seconds |
|---|---:|---:|
| `cargo test --locked --all-features -p nazo-postgres --test read_connection_ownership -- --nocapture` | 101 | 10.49 |
| `cargo test --locked --all-features -p nazo-postgres --test read_connection_ownership -- --nocapture` | 0 | 0.53 |
| `cargo fmt --all -- --check` | 0 | 2.26 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | 35.51 |
| `cargo test --locked --all-features -p nazo-postgres --test read_connection_ownership --test audit_commit_boundary --test security_state_commit_boundary -- --nocapture` | 0 | 20.90 |

The two ownership tests at final source pass in0.53s including command overhead; old backend5263 independently disappeared before replacement5266 executed SQL. See the raw positive log for the exact observation. The production file-tree equivalence is recorded in production-equivalence.json.

## Carried-forward runtime evidence

[Full report, commands/exits, before/after connection ledgers, capacity data and storage time series](https://github.com/nazozero/NazoAuth/blob/7ccf7c8eb4cd2e94a0aff526de10a013ab03dee9/evidence/pr230-performance-repair-20261009/publish/README.md). That report remains unchanged. It records final runtime source `ef89417c9377ea765878b24d7b034a189638dee3`, its binary hash,3,674 passed/0failed/4ignored full workspace tests, explicit FAPI pass, original four-point capacity PASS, and60,001 decisions naturally reclaimed after the last retention deadline and a complete maintenance cycle.171,075 audit facts reconcile with the receiver and signed checkpoint. This follow-up does not rename those measurements to a different binary or repeat unaffected performance/fault workloads.

| Original point | successful ops/s | P50/P95/P99 ms | formal drop | result |
|---|---:|---|---|---|
| auth16,800ops/s,992VUs,pool32 | 800.000 | 10/18/34 | 0 | PASS |
| revoke16,960ops/s,992VUs,pool32 | 960.000 | 12/22/39 | 0 | PASS |
| mixed1,400ops/s,64VUs,pool32 | 399.783 | 2/12/24 | 13/24000 (0.0542%) | PASS |
| mixed16,1600ops/s,992VUs,pool32 | 1600.000 | 3/13/23 | 0 | PASS |

CODE / SECURITY / RECOVERY / PERFORMANCE / STORAGE remain PASS for their documented local scope, with this test portability defect now repaired and verified. The earlier final-HEAD CI was FAIL; a fresh final-HEAD CI result is still required before merge readiness is asserted and will be recorded in the PR body/comment after publication. Long-term storage plateau remains INVALID/not measured. Shared-CPU causation remains unproven; unchanged A also passed later, and no blanket throughput/latency improvement is claimed. Mixed1's final10s tail rise and13drops remain in the report. The owner performs the final merge.

All added reproduction and verification ran in the same authorized CNB checkout/target with one writer. Production code, performance gates, Required evidence, commit confirmation, locks, replay fences and TTLs are unchanged. No merge or deployment was performed.
