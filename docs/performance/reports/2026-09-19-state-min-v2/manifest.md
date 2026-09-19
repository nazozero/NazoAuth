# State-Minimization Rectification + Live Regression + 8h Benchmark — Run Manifest

| Field | Value |
|---|---|
| RUN_ID | 20260919-state-min-v2 |
| BASE_SHA | `41b0a197db41b099179f4e1fdb3ed01ba5d69471` (GitHub `main` at task start; = historical audit baseline) |
| TEST_SOURCE_SHA | *(fixed at end of Phase A)* |
| REPORT_SHA | *(final report commit)* |
| T0 | *(Phase B start — sync of frozen source to new bench host)* |
| Bench host | `cnb-g6o-1k2t4ter2-001.85006e8b…iq8@cnb.space` — 64 CPU / 128 GiB / 256G+512G disk / kernel 5.4.241 / docker 29.6.2 |
| Old host | *retired — not used* |

## Status ledger (each PASS requires real evidence, not plan text)

| State | Status | Evidence |
|---|---|---|
| AUDIT | PASS (carried from 41b0a197 report) | `docs/performance/reports/2026-09-19-state-minimization/report.md` |
| IMPLEMENTATION | IN_PROGRESS | this file |
| LIVE_REGRESSION | NOT_RUN | — |
| FORMAL_BENCHMARK | NOT_RUN | — |
| DEPLOYMENT_WORM_VERIFICATION | NOT_RUN (requires trusted retention infra) | — |
| ONLINE_RETENTION_ACCEPTANCE | NOT_RUN | — |

## Phase A work items

A1 evidence-chain tooling · A2 batch exporter protocol + reference receiver ·
A3 auth-code issuance-row consumption · A4 sparse family terminal state ·
A5 audit taxonomy + online retention/archive + required-mode admission ·
A6 remaining state chains + regression gate
