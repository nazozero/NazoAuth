# Final Soak 6h R1 — Run Manifest (FAILURE)

| Field | Value |
|---|---|
| RUN_ID | `statemin-final-soak-6h-r1` |
| FINAL_CANDIDATE_SHA | `23762421` (tested source; pushed to origin+cnb) |
| REHEARSAL | `final-rehearsal-10m-r1` PASS — all sidecars real, receiver 0/0, anchor==receiver 1,145,692 |
| SOAK window | 2026-09-20T16:44:49Z–22:46:59Z (6h01m) |
| Result | **FORMAL_SOAK = FAIL** |
| Cliff question | answered: no exporter cliff past 5h10m (evidence: steady anchor tracking, outbox≈0 through 6h) |
| Gate breaches | main drops 0.219% (>0.1%); argon2 5×503; 96,389 `dropped_required` required-class audit losses |
| DB final | anchor=head=receiver=43,347,685; outbox/chain/events=0; chain_valid=t |
| WAL | +313.34 GB → ~7.1 KB/op (all ops) |
| RSS | 199–200 MB steady |
| Intervention | `pg_cancel_backend(1626)` at 16:58:07Z — cancelled a 12-min wedged claim (no-stats pathological plan). Fixture-recovery action, not product change; disclosed, and itself the trigger for the 17:12Z drop cluster. |
| Scene | preserved: evidence dir intact on bench host + this repo copy; DB left as-is |

## Status ledger

| State | Status |
|---|---|
| APP_HOT_PATH | FAIL (drops 0.219%) |
| FAPI_PERF | PASS (644,375 flows, 0 err) |
| ARGON2 | FAIL (5×503) |
| AUDIT_CLAIM | PASS steady-state / FAIL cold-start wedge |
| AUDIT_EXPORT_CAPACITY | PASS (cliff absent) |
| AUDIT_RETENTION | FAIL (Required-class loss via best-effort queue) |
| WRITE_AMPLIFICATION | PASS (~7.1 KB/op) |
| STORAGE_LIFECYCLE | PASS (converged to zero) |
