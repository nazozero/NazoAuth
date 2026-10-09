# Historical PR description at 67f836f2

This is the superseded historical description, not the current acceptance decision. See README.md in this directory for the continuation results.

This single integration PR contains the complete heads of #222, #223, #224, #225, #226, #227, #228, #231, #232, #233, #234 and #235. Those PRs are closed as superseded; their branches and histories remain available. Final merge into main belongs to the repository owner.

The changes make durable authorization decisions and token receipts authoritative, preserve original deadlines and fresh-authentication evidence, reduce duplicate token/audit work, bound reclamation, and incorporate dependency/build updates. The final storage fix discards consumed authorization-code, consent and PAR preparation only after confirmed durable commit. Version checks protect replaced values, cleanup failure keeps TTL fallback, and durable replay authority remains intact.

## Verification

Final head: `67f836f2b616e811ce9a20bb857a01ea9517b42b`. All eight exact-head workflows succeeded: code quality, CodeQL, dependency review, conformance/security, operator fuzz, specification freshness, release policy and performance images. Rust results: 3,639 passing test executions, zero failures, four ignored. The earlier focused fault/replay/expiry checks covered 212 distinct tests with real PostgreSQL/Valkey.

The measured production source is `b050012a753cb6939251192d63d4a0c0840958ad`, binary SHA-256 `f2f4ae9a6093395867c1ba26af68cd097feb19994d1859843dad8aa57f920006`. The final commit changes only an obsolete test guard to require cleanup after commit; all production source, manifests, lockfile, migrations and build inputs match the measured source.

The owner selected final-only short tests within two hours, without rerunning main. Formal windows are 60 seconds for the corrected Native SSO fixture, 90 seconds otherwise, 300 seconds for multi-core authorization/refresh/revocation, and 480 seconds for multi-core mixed. Each point uses fresh isolated storage, original offered load and thresholds, Required audit and durable PostgreSQL settings. CPU allocation is shared; affinity does not reserve physical cores.

## Final short-test matrix

| Scenario | Formal s | Success/s | P95 / P99 ms | Dropped iterations | Raw capacity | State | DB growth MB / sampled s | WAL bytes/success | Valkey post MB |
|---|---:|---:|---:|---:|---|---|---:|---:|---:|
| Client credentials 1 CPU | 90 | 997.68 | 43.00 / 58.00 | 209 | FAIL | PASS | 35.05 / 140 | 1748.28 | 1.40 |
| Client credentials 16 CPU | 90 | 3939.46 | 255.00 / 290.00 | 5448 | FAIL | PASS | 65.13 / 174 | 1537.39 | 1.82 |
| Mixed 1 CPU | 90 | 400.00 | 100.00 / 134.00 | 0 | FAIL | PASS | 46.78 / 214 | 3163.77 | 5.96 |
| Mixed 16 CPU | 480 | 1572.90 | 838.00 / 1584.00 | 12998 | FAIL | PASS | 414.22 / 633 | 4287.27 | 43.03 |
| Authorization code 1 CPU | 90 | 200.00 | 136.00 / 160.00 | 0 | FAIL | PASS | 79.80 / 132 | 10557.99 | 8.98 |
| Authorization code 16 CPU | 300 | 573.95 | 2121.00 / 2403.00 | 67813 | FAIL | PASS | 671.32 / 377 | 12448.34 | 46.23 |
| Refresh 1 CPU | 90 | 500.00 | 52.00 / 74.00 | 0 | PASS | PASS | 28.84 / 132 | 3380.14 | 1.49 |
| Refresh 16 CPU | 300 | 1998.59 | 25.00 / 304.00 | 430 | FAIL | PASS | 143.45 / 355 | 3481.28 | 1.94 |
| Introspection 16 CPU | 90 | 7973.81 | 39.00 / 121.00 | 2368 | FAIL | PASS | 10.29 / 137 | 1.21 | 2.27 |
| Revocation 16 CPU | 300 | 448.66 | 2497.00 / 2663.00 | 153403 | FAIL | PASS | 458.92 / 366 | 12104.47 | 38.01 |
| mTLS client credentials 16 CPU | 90 | 3390.33 | 354.00 / 391.00 | 54884 | FAIL | PASS | 237.91 / 163 | 1541.87 | 1.82 |
| FAPI logged-in authorization 16 CPU | 90 | 320.00 | 319.00 / 417.00 | 0 | FAIL | PASS | 174.73 / 138 | 12778.10 | 103.96 |
| Cold login + refresh 16 CPU | 90 | 16.00 | 313.05 / 339.22 | 0 | PASS | PASS | 13.73 / 137 | 14890.22 | 3.36 |
| Native SSO fresh credentials 16 CPU | 60 | 400.02 | 77.00 / 104.00 | 0 | PASS | PASS | 43.22 / 105 | 5128.29 | 23.14 |
| Signed PAR 16 CPU (third attempt) | 90 | unverified | unverified | unverified | INVALID: evidence lag | PASS | 3.21 / 146 | unverified | 458.45 |

Native SSO uses its corrected 60-second short window; the initial fresh fixture did not enable the module and is retained separately as a failed preparation run.


DB growth is first-to-last physical allocation over the actual sampler span, not a normalized per-operation cost. WAL uses the interpolated formal-window counter / formal successful main operations; mixed points also contain sidecar work and cannot be treated as the cost of only one endpoint. Valkey is whole-instance post-test memory, including necessary replay state.

## Merge assessment

Acceptable for owner merge under the explicitly selected two-hour final-only short-test scope. The PR is not a certification that all original capacity targets passed or that long-term storage is flat.

- Final-head CI: 8/8 workflows succeeded. The Rust log records 3,639 passing test executions, zero failures and four explicitly ignored executions; these are executions, not a distinct-test count. Earlier focused correctness/failure verification covered 212 distinct tests with real PostgreSQL/Valkey cases.
- All 15 scenarios have passing state checks. Fourteen have valid performance evidence and zero unexpected business errors; signed PAR has three INVALID performance attempts from evidence-consumer lag, despite passing independent health/state checks. Strict original capacity gates: 3 PASS, 11 FAIL, 1 INVALID. All observed generator work in the fourteen valid points completed; this does not imply every internal queue was instrumented.
- Consumed authorization-code, consent and PAR preparation is removed only after confirmed durable commit, with original-version comparison where applicable. Failure preserves TTL fallback and cannot reverse the committed outcome. Authoritative decisions, replay receipts, signed-proof retention and Required audit remain intact.
- Refresh at 2,000/s returned to its earlier latency level after a short spike; there is no observed cumulative tail growth in the five-minute window. Mixed tails improved in later intervals, but collector overhead changed and a causal product-improvement claim is not justified.
- Authorization at 800/s and revocation at 960/s were overloaded. Authorization audit pending and retired families cleared at +20.41s/+31.41s; revocation retired families cleared at +21.25s. Client credentials and mTLS also accumulated audit work, settling at +38.28s/+29.20s. These rates are not shown sustainable with flat storage on this host.
- Single-core mixed, single-core authorization, FAPI and Native SSO retained terminal families at the end of their short observation. The remaining counts and full sampling spans are preserved above. Their full drain and perpetual storage plateau were not established.
- Valkey authorization growth is now accounted for by live replay markers/session state rather than consumed preparation. These records cannot be deleted early without weakening correctness. Physical PG growth and some WAL costs remain real tradeoffs.
- Main was not rerun. Historical main numbers are context, not a concurrent causal comparison. Shared-CPU interference is possible, not proven as the only cause. The second source-chain review found no blocking correctness defect or unjustified new hot-path queue/retry mechanism; accepted under the owner's specified review criterion.
- Three PAR attempts remain INVALID because evidence-consumer lag reached 15.82, 15.28 and 22.10 seconds. Increasing decoder workers from three to six did not resolve it. An attempted forensic-disable change affected the controller checkout but not the immutable runner image: runtime stats confirm the third run still had its original 512 MB diagnostic cap. That attempt is not treated as a forensic-off experiment. PAR performance remains unverified; the second hot-path code review is accepted only under the owner-specified review exception. No INVALID was converted to PASS.
- The initial Native SSO point failed all credential preparations because the fresh-database fixture omitted enabling Native SSO before startup. Its module-enabled requirement existed in the request description but was not executed. The corrected fixture writes authoritative desired state plus an event before first startup and asserts actual enabled state before load; the replacement uses a 60-second formal window at the same 400/s rate. The original failed point is retained and excluded from successful-flow performance conclusions.

The owner retains the final merge into main. Long-term steady-state and universal fixed-rate capacity guarantees are outside this agreed short-test acceptance.

## Review disposition

The second chain review covered durable commits, version-checked preparation cleanup, refresh lock order and fresh-clock validation, cancellation/unknown outcomes, bounded audit export and state reclamation, and signed PAR. No blocking defect was found in those chains. Thirty-two CodeQL alerts were individually triaged: 29 test fixtures, one RFC-defined nonsecret HKDF salt, and two generic cookie helpers whose insecure mode is restricted to loopback HTTP by startup validation. No security query was disabled or alert globally dismissed. The 32 default-branch dependency alerts were checked against the final PyJWT 2.15.1 / urllib3 2.8.0 pins and their reported vulnerable ranges; this is not a claim of zero possible vulnerabilities.

The first mixed and refresh runs completed measurement/state checks but their outer receipt wrapper referenced an obsolete field. Unchanged artifacts were recovered and SHA-256 verified without repeating load. The first mixed point exceeded its original transport wall budget during recovery; its measurement remained within budget. Three PAR attempts remain INVALID from measured evidence-consumer lag; six decoder workers did not help. The attempted forensic-disable did not reach the immutable runner image and is not counted as an effective diagnostic change. Optional forensic captures are capped; interval quantiles are histogram bounds grouped by completion time, while headline metrics use the full formal cohort. Internal best-effort queue/acquisition telemetry was unavailable; no zero-backlog claim is based on missing telemetry.
