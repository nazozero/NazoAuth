# State-Minimization Rectification + Live Regression + 8h Benchmark — Run Manifest

| Field | Value |
|---|---|
| RUN_ID | 20260919-state-min-v2 |
| BASE_SHA | `41b0a197db41b099179f4e1fdb3ed01ba5d69471` (GitHub `main` at task start; = historical audit baseline) |
| TEST_SOURCE_SHA | `6e3a352c33b1abfa3c0a4aa72d0b32fe3f1e8174` (Phase A frozen source; regression evidence above ran against this tree) |
| REPORT_SHA | *(final report commit)* |
| T0 | 2026-09-19T20:55:26Z (RUN_ID=`statemin-v2-soak-8h`, 1800 ops/s cap_mixed, 8 h, audit anchor live) |
| Bench host | `cnb-g6o-1k2t4ter2-001.85006e8b…iq8@cnb.space` — 64 CPU / 128 GiB / 256G+512G disk / kernel 5.4.241 / docker 29.6.2 |
| Old host | *retired — not used* |

## Status ledger (each PASS requires real evidence, not plan text)

| State | Status | Evidence |
|---|---|---|
| AUDIT | PASS (carried from 41b0a197 report) | `docs/performance/reports/2026-09-19-state-minimization/report.md` |
| IMPLEMENTATION | PASS | A1–A6 landed; migrations `20260921000100`, `20260922000100`, `20260923000100`; `state-chains.md` |
| LIVE_REGRESSION | PASS | nazo-postgres full suite ~283 green on live PG18+Valkey8; nazo-oauth-server 296, nazo-valkey 14, nazo-auth 158, nazo-persistence 5, nazoauth lib 1291; audit fault-injection 22/22 |
| FORMAL_BENCHMARK | NOT_RUN | — |
| DEPLOYMENT_WORM_VERIFICATION | NOT_RUN (requires trusted retention infra) | — |
| ONLINE_RETENTION_ACCEPTANCE | NOT_RUN | — |

## Phase A work items

| Item | Status | Evidence |
| --- | --- | --- |
| A1 evidence-chain tooling | DONE | `perf/tools/ledger.sql`, `soak_run.sh`, `vkledger.py` — live-validated against PostgreSQL 18 + Valkey 8 |
| A2 batch exporter protocol + reference receiver | DONE `4a1e1a1a` | PG integration (28 audit/ledger tests) + fault-injection regression 22/22 |
| A3 auth-code issuance-row consumption | DONE | `single_use_redemption` PG fence + Valkey delete-on-commit; auth_repositories + replay suite green |
| A4 sparse family terminal state | DONE | migration `20260922000100`; `security_state_maintenance` sparse/60s-window cases green |
| A5 audit taxonomy + online retention/archive + required admission | DONE | migration `20260923000100` (`security_audit_archive` + `nazo_archive_security_audit_prefix`); taxonomy classes in `AUDIT_EVENT_DEFINITIONS`; required-mode admission unchanged (`ensure_audit_storage` gates admin + issuance) |
| A6 remaining state chains + regression gate | DONE | `state-chains.md` inventory; full `nazo-postgres` integration suite green on live PG18 |
