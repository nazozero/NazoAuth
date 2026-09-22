# Final Soak 6h R1 — FAILURE RECORD (not a pass)

- **RUN_ID**: `statemin-final-soak-6h-r1`
- **TEST_SOURCE_SHA**: `23762421` (delivery-scoped retention + grow-only vector pool)
- **Window**: 2026-09-20T16:44:49Z → 22:46:59Z (6h01m), main `cap_mixed` constant-arrival 1800 ops/s + argon2 8/s + meta 200/s + fapi 30/s + real audit receiver/exporter
- **Host**: fresh bench host `cnb-npo-1k2voeraa-001…` (previous host destroyed); fresh PG18/Valkey8, 52,000 pre-seeded flow vectors, 256 users
- **Verdict**: **FORMAL_SOAK = FAIL** on acceptance gates. The headline structural question — *does the exporter cliff survive past ~5h10m* — is answered affirmatively (no cliff), but the run failed the drops gate and exposed two defects.

## What the run proves (kept facts)

| Fact | Evidence |
|---|---|
| Historical ~5h10m exporter cliff did **not** recur | at 5h27m: anchor advancing at arrival rate, outbox ≈0-77 rows, oldest_pending_age = 0; stayed flat through 6h01m |
| Final convergence exact | DB `anchor_sequence = head = 43,347,685` == receiver `last_sequence = 43,347,685`; `security_audit_event_outbox`, `security_audit_chain_entries`, `security_audit_events` all = 0 after drain |
| Receiver integrity | 809,266 batches / 43,347,685 events accepted; **duplicates = 0, rejected = 0** |
| Latency | p50/p95/p99 = 4.0/10.4/55.1 ms; no sustained degradation |
| RSS | ~199–200 MB flat for 5h+ (HWM 262 MB during ramp) — independent of DB growth |
| WAL | +313.34 GB / 6h → **7.1 KB/op** over all logical ops (8.1 KB/op over main only) — under the 12 KB/op target |
| DELETE amplification | audit ins == del exactly per table (42,201,993 each of outbox/chain/events) — delete-at-ack, no re-amplification |
| Autovacuum lifecycle | outbox 350 / chain 345 / events 360 runs; dead tuples bounded ~20–180k between cycles |
| Sidecars | argon2 171,834 flows, meta 4,296,001, fapi 644,375 — all persisted summaries on host disk; fapi never crashed (grow-only pool fix verified over 6h) |

## Why it still FAILED

| Gate | Threshold | Actual | Classification |
|---|---|---|---|
| main dropped_iterations | ≤ 0.1 % | **85,302 / 38,880,040 = 0.219 %** | FAIL — single cluster ~17:12Z (one `Insufficient VUs … 256` warning); see causal chain below |
| unexpected HTTP/business errors | = 0 | argon2 `login` step **5× 503 `temporarily_unavailable`** at 19:42:34Z | FAIL — transient burst during a persist sag |
| required audit evidence loss | = 0 | **96,389 `authorization_approved` events logged `dropped_required`/`queue_full`** | FAIL — see defect B |
| audit no sustained drift | — | PASS — outbox sawtooth ≤64k always reconverged (age ≤35 s) | — |
| claim cliff | — | PASS after recovery — but see defect A (12-min wedge at cold start) | partial |

## Defect A — cold-start claim wedge (fixture-triggered, real robustness gap)

The exporter's first `nazo_claim_security_audit_pending` at 16:46:02Z ran **11m39s** on CPU with no lock wait, holding `backend_xmin`. Root cause: fresh tables had no planner statistics yet (autoanalyze landed 16:56–16:57Z), so the planner picked a catastrophic join order for the claim's `NOT EXISTS` fallback. While wedged it pinned the vacuum horizon; ack-side deletes accumulated an unreclaimable dead-prefix on the outbox order index. After `pg_cancel_backend` (16:58:07Z) the claim retried on fresh stats and drained at ~2.9–4.9k ev/s; outbox converged 913k → ~250 by 17:08Z. The post-recovery dead-prefix + drain burst caused the ~17:09–17:18Z persist sag that produced the k6 drop cluster and the first `dropped_required` burst (29,181 in hour 17).

## Defect B — Required-class audit events on the best-effort queue (pre-existing misroute)

`authorization_approved` is classed `Required` in `AUDIT_EVENT_DEFINITIONS` but `record_decision_audit()` emits it via `SecurityAudit::record()` — the bounded (4,096) in-process `try_send` queue. Each persist sag (~35–40 min cadence, correlated with outbox sawtooth peaks at 20:29/20:44/21:04/22:30Z) filled the queue within ~2 s and dropped required evidence while the business grant succeeded (HTTP-invisible). Hourly distribution: 17h 29,181 / 18h 3,891 / 19h 4,953 / 20h 32,836 / 21h 11,111 / 22h 14,417 = **96,389** + one `misrouted_required` warning. `evidence/statemin-final-soak-6h-r1/app-audit-drops-hourly.txt` is the retained per-hour census; the verbatim 26MB per-event extract was removed during evidence minimization (the census above is the complete derived record).

## Chain of causation for the gate misses

cold-start no-stats → claim wedge 12min holding xmin → unreclaimable dead prefix → cancel → drain burst + persist sag ~17:09–17:18Z → k6 VU saturation (85,302 drops) + first queue_full burst. Later `dropped_required` bursts recur at each outbox sawtooth peak — a steady-state persist-sag exposure independent of the cold start.

## What this run does NOT change

- Delivery-scoped retention itself is validated (zero online audit residue, exact anchor↔receiver convergence, bounded WAL/DML) — the cliff mechanism is gone.
- The failures are: (a) a plan-stability gap at cold start, (b) a Required/Telemetry routing defect, (c) their cascade into the drops/errors gates.
- Compact evidence retained under `evidence/` (sampler streams, ledgers, summaries, censuses); bulky verbatim extracts (`app-audit-drops.log`, `main/run.log`) and the superseded `final-rehearsal-10m-r1/` pre-run were removed during evidence minimization — conclusions are carried by the retained aggregates.

## Disposition

FORMAL_SOAK=FAIL. Targeted short-test remediation only (no further 6h+ run without explicit authorization): rewrite the claim function to index-first identity selection without the hot-path anti-join; add bounded autoanalyze parameters as planner-statistics aid (not as the bounding mechanism); re-route Required-class emissions through `record_required`/transactional append at the correct mutation boundary; add cold-start claim regression at 0/10k/1M/15M pending.
