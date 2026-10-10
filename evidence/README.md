# Current acceptance and retained evidence

Source candidate: `4ccd02de2767a7dd586f19ccb7cf502197e02aeb`.

Current scoped performance acceptance is **PASS**: authorization-code retest at 800 ops/s for 180 formal seconds; client-credentials retest at 4,000 ops/s for 600 formal seconds. The original workload, success definition, P95/P99 100/250 ms, success fraction 99.5% and drop 0.1% gates are unchanged. This does not claim a repeated 30-minute authorization pass or all-path infinite-runtime stability. Historical diagnostic FAIL/INVALID observations remain unchanged and do not automatically override valid same-source retest acceptance.

## Evidence to read

- [Current acceptance, storage findings and all run outcomes](pr238-physical-growth-20261010/publish/REPORT.md).
- [Earlier chain coverage and anomalies](pr238-longrun-20261010/publish/REPORT.md).
- [Earlier implementation and fault/regression closure](pr238-closure-20261010/publish/REPORT.md).
- [Model responsibility and field review](pr238-closure-20261010/publish/MODEL-REVIEW.md).
- [Exact cleanup ledger](retention-20261010.json).

## Retention rule

Keep commands/exits, source/image provenance, requests and gates, raw latency/throughput and storage time series, natural-maintenance deadlines/cycles, signed receiver/database/checkpoint reconciliation, failure/negative tests, model inventories and reproduction scripts. A failed or invalid outcome is never a reason to delete its evidence. Process CPU counters remain available in the original proc-detail files.

Repeated successful per-thread CPU-affinity identity listings add no further capacity or storage proof. Their `.summary.json` replacements keep every snapshot timestamp, role/container, requested masks, verification flag, collector completeness/errors and exact task counts grouped by observed mask/name. Incomplete/unverified snapshots retain their full task rows. Only repetitive successful PID/TID/PPID/UID/starttime listings are removed. The cleanup ledger records original and replacement hashes and sizes.

Historical reproduction scripts and frozen provenance may name the original detailed files. For replay requiring those exact files, retrieve the recorded path from commit `28fd6a693b06485ea83570f6ae703af013e684e9` using `git show <commit>:<path>`. Current checksum/publication inventories point to retained summaries. This is a working-tree evidence reduction, not Git-history erasure or a claim to reduce existing clone object storage. Untracked private scratch data and test caches are outside this cleanup.

## Verification of this documentation-only revision

On the authorized CNB checkout, the retention check compares compact summaries with every original snapshot, verifies current hashes/publication indexes, confirms retained run aggregates and raw performance/storage evidence are unchanged, and runs `git diff --check`. No application source, tests, benchmark gates or raw run verdicts are modified; no repeat load test is required for this evidence-only change. The earlier 7/7 successful CI result belongs to report commit `28fd6a6`, not to this new documentation commit.

Verified result: 61 original/summary pairs match; 6,092 other existing evidence files are byte-identical; 2,922 integrity/publication entries pass; `git diff --check` exits 0. The CNB command was `python3 /tmp/check-evidence-retention-20261010.py` (exit 0). Two pre-existing stale hashes in the PR230 publication inventory were corrected against unchanged files at the base commit; exact old/new hashes are in the cleanup ledger. The original 38,230,263 bytes of thread listings become 2,477,257 bytes of summaries (35,753,006 bytes net reduction before small index/document additions).
