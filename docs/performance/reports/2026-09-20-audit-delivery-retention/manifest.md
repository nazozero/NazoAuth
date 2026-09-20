# Audit Delivery-Scoped Retention — Correction Run Manifest

| Field | Value |
|---|---|
| RUN_ID | `statemin-fix-int30-r1` (integrated) · `fapi10m-r2` (FAPI) · `auditA2-claim-10m` / archive-only / `auditC-both-10m` (diagnostics) |
| BASE_SHA | `b5ee3139` — remote `origin` (GitHub) and `cnb` `main` both read at this SHA before work; no remote drift was overwritten |
| PRIOR_TEST_SOURCE_SHA | `6e3a352c` — the binary the 8h soak actually ran; report commit `b5ee3139` is bookkeeping, not the tested source |
| IMPLEMENTATION_SHA | `19a77140` → `9b9654d0` → `d427343f` → `881df787` → `72572eba` (code chain); REPORT_SHA=`63efa404` (this report+evidence). Local `main`; push pending user authorization |
| Window | diagnostics + drain 2026-09-20 ~12:00–15:24Z; integrated 14:53:33–15:23:57Z |
| Bench host | `cnb-pqg-1k2u7i4nd-001.049d8344…6m8@cnb.space`, docker compose `nazoauth-perf`, PG 18 / 128 MB shared_buffers |
| Fixture | prior soak DB: 11.88M undelivered audit events, receiver checkpoint seeded to anchor `41,586,901`; `oauth_tokens` TRUNCATEd before seeding (fixture cleanup, not a product path) |

## Status ledger

| State | Status | Evidence |
|---|---|---|
| DIAG_A_CLAIM_ONLY | DONE | 100.7 ev/s; health 2,449.9 ms/iter ≈96.8 % wall; claim inner SQL 13–22 ms |
| DIAG_B_ARCHIVE_ONLY | DONE | 6,960 rows/s; ~7.5 KB WAL/event (archive INSERT ~6.5 KB) |
| DIAG_C_CONCURRENT | DONE | 160 ev/s; claim 6.6× slower; `Lock:transactionid` on `chain_state` |
| IMPLEMENTATION | DONE | migration `20260924000100`; delete-at-ack; archive dropped; empty-chain head valid; queue autovacuum bounds |
| LOCAL_GATES | PASS | fmt/clippy clean; 22 PG tests; static contracts + dep graph |
| FAPI_10M | PASS | `fapi10m-r2`: 18,001 iters @30/s, 90,005 reqs, errors 0.0, p95 8.09 ms |
| INTEGRATED_30M | PASS (disclosed `target_miss`) | `statemin-fix-int30-r1`: 3.24M iters @1776.8 ops/s, err 0.0, p99 30 ms; anchor==receiver `56,853,522`; outbox/chain/events = 0; WAL 9.98 KB/op; DB −15.9 GB |
| NEXT_LONG_SOAK | GATED | awaiting authorization; not started |

## Files changed this round

- `migrations/20260924000100_audit_delivery_scoped_retention/{up,down}.sql`
- `crates/persistence-postgres/src/repositories/{security_state,audit_ledger}.rs`, `src/{schema,pool}.rs`, `migration-head.txt`
- `crates/persistence/src/maintenance.rs`, `crates/nazoauth/src/jobs/security_state.rs`, `crates/nazoauth/tests/unit/jobs/security_state.rs`
- `crates/persistence-postgres/tests/{security_state_maintenance,audit_ledger,audit_chain_cutover}.rs`
- `perf/tools/ledger.sql`, `perf/seed.py` (grow-only vector pool)
- `tests/contracts/migrations.sha256`
- `docs/security/audit-anchor.md`, `docs/operations/security-audit-ledger-roles.md`

## Evidence (in `evidence/`)

`statemin-fix-int30-r1/`: ledger-pre/post/diff, audit-health.jsonl, soak-metrics.jsonl, runner-rss.jsonl, vkledger pre/post, main/latest.json + report.md, audit worker + receiver logs, soak.log, manifest.txt. `fapi10m-r2/`: report.md, latest.json, k6 summary.
