# NazoAuth Performance Benchmarks — Current Baseline

Date: 2026-09-22. This is the canonical entry point for the current
performance/storage/stability state. Per-scenario capacity matrices live in
[performance-capacity-curve.md](performance-capacity-curve.md) (July 2026
baseline) and the reports it links; this document records the post
refresh-storage-redesign steady state.

## 1. Tested version

- `BASE_SHA` = `ef45b8817b41e5683dc5361c2b5a72916fa19db7` (`origin/main`)
- Implementation under test: refresh-state three-table redesign applied as a
  working diff on top of `BASE_SHA`; content fingerprint
  `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5` (sha256 of
  diff + untracked files — not a git commit).
- PostgreSQL `postgres:18-alpine`, `max_wal_size=8GB`; Valkey `valkey:8-alpine`;
  64C/128G container host; DB pool default; main workload target 1800
  logical ops/s (`cap_mixed`) plus refresh 600/s, argon2 8/s, metadata 200/s,
  FAPI 30/s sidecars, audit exporter + durable receiver, autovacuum on.

Run set (report + evidence:
[reports/2026-09-22-refresh-storage-redesign/](reports/2026-09-22-refresh-storage-redesign/report.md)):

| RUN_ID | Duration | Result |
|---|---|---|
| `20260922-refreshmin-10m-v2` | 10 min | PASS |
| `20260922-integrated-30m-r2` | 30 min | PASS |
| `20260922-storage-3h` | 3 h | storage PASS; raw drop gate `target_miss` (see §9) |
| `20260922-dropsfix-30m` | 30 min | PASS — repair verification |

## 2. Executive summary

- 28.09M logical operations over 3 h; measured main throughput 1,784.65 ops/s
  (99.1% of the 1800/s target).
- Main p50 4.32ms / p95 11.98ms / p99 77.95ms; classified HTTP error rate
  0.0126%, all expected `invalid_grant` (retired-family semantics);
  unexpected business/security errors = 0.
- Database converges: final 509.9MB, last-hour slope −0.09MB/min.
- Refresh durable state: 43.9MB total, bounded by cap 10 families per
  (tenant,user,client) and 64 spent proofs per family.
- WAL 3.62KB/op (gate <12KB/op); audit chain 29,919,738 events, receiver
  anchor == DB anchor, duplicates=0, rejected=0, pending=0.
- App RSS ~107→205MB plateau, uncorrelated with DB/WAL growth; no OOM/restart.

## 3. Current storage steady state

3h soak (`20260922-storage-3h`, 1,079 sampler bins):

| Phase | DB growth | Rate |
|---|---|---|
| 0–30min | +459.6MB | 15.34 MB/min (fixture warmup) |
| 30–60min | +14.7MB | 0.49 MB/min |
| 60–120min | +28.3MB | 0.47 MB/min |
| 120–180min | −5.5MB | −0.09 MB/min (net shrink) |

Final relation sizes (post-autovacuum): `oauth_token_issuances` 295.3MB
(retention-bounded issuance ledger, largest relation),
`security_audit_chain_entries` 35.7MB + `security_audit_event_outbox` 16.6MB +
`security_audit_events` 12.8MB (≈65MB reusable physical high-water, logical
rows drained to 0), `oauth_refresh_families` 23.1MB / 3,080 rows,
`oauth_refresh_spent_tokens` 20.2MB / 13,275 rows,
`oauth_refresh_contracts` 0.55MB / 452 rows.

Conclusion: database size is governed by current valid security state and
bounded retention windows, not by cumulative request history.

## 4. Refresh state

| Metric | Old model (6h formal soak) | New model (3h soak) |
|---|---|---|
| refresh relations | `oauth_tokens` 15.63GB | 43.9MB (3 tables) |
| refresh rows | 12.62M | 3,080 families + 13.3K proofs + 452 contracts |
| families | 6.64M (~25,956/user) | cap 10 per (tenant,user,client); plateau ~3,040 at t+2h11m |
| DB total | 15.97GB | 0.51GB |
| growth shape | ~2.6GB/h linear | converging; negative last hour |

- Rotation reuses the family slot; it does not create a new family.
- Contract dedupe ≈7,332:1 (3.31M family inserts → 452 live contracts).
- Spent proofs: create≈delete≈777/s in the final hour; cap 64/family;
  expired backlog 0.
- 30-day projection at this workload: refresh state ≈45–60MB; DB ≈500–600MB
  steady state, ~4× under the 2GB budget.

Growth model:
`DB(t) = B_active(scopes×10) + B_contract(unique grants) + B_spent(rotation×retention) + B_issuance(window) + B_audit_phys(high-water) + B_transient(TTL)` —
no term scales with cumulative requests.

## 5. PostgreSQL / WAL

- `max_wal_size=8GB` is the validated envelope
  ([A/B report](reports/2026-09-21-poolstarve-ab-30m/report.md)): the 1GB
  default caused requested-checkpoint storms and pool starvation; at 8GB,
  checkpoints are timeout-driven (27 timed / 1 requested in 3h).
- WAL per logical op: 3.62KB/op at the current workload. Historical
  optimization trajectory ~16.8 → ~9.98 → ~7.79 → 3.62KB/op.

## 6. Audit

- 3h run: 29,919,738 exported events; receiver `last_sequence` ==
  DB `anchor_sequence`; duplicates=0, rejected=0, outbox pending=0.
- Historical 6h formal run delivered 42.2M events with the same
  anchor==receiver reconciliation
  ([report](reports/2026-09-21-final-soak-6h-formal-r1/report.md)).
- The historical ~5h10m exporter cliff (per-iteration orphan scan + archive
  contention) was fixed and did not recur in any later run
  ([report](reports/2026-09-19-state-min-v2/report.md)).
- The receiver is a test durable receiver; it is not a deployment-level WORM
  attestation.

## 7. Sidecars (3h soak / repair verify)

| Workload | Rate | 3h iterations | errors | p95 |
|---|---|---|---|---|
| refresh rotation | 600/s | 6,280,970 | 0 | 14.16ms |
| argon2 cold login | 8/s | 85,592 | 1 transient 503 | 131.4ms |
| metadata/JWKS | 200/s | 2,140,000 | 0 | 0.35ms |
| FAPI2 high-security | 30/s | 320,981 | 0 | 13.46ms |

Repair run (`20260922-dropsfix-30m`): all sidecars 0 drops / 0 errors
(argon2 14,241 iters, fapi 53,401, meta 356,001, refresh 1,067,999).

## 8. Stability / resources

- nazoauth RSS: 107MB start → ~190–205MB plateau (max spike 245MB, final
  141MB); stable across 3h and independent of DB/WAL/key-count growth.
- No crash, restart, or OOM.
- Pool: ~14K acquisitions/s; per-bin avg wait ~20–50µs; one 957ms stall at
  t+7,849s coinciding with a checkpoint flush.
- Valkey: 193,507 keys / 82.0MB used, 0 evictions; prefix census —
  `oauth:session` 86,412, `oauth:jar` 51,231, `oauth:dpop` 39,336,
  `oauth:client_assertion` 16,532, `oauth:rate` 1. Transient TTL material
  only; no refresh durable state in Valkey.

## 9. Known caveats

- The 3h main workload recorded 115,560 dropped iterations (0.594%) —
  literally above the 0.1% gate, so the raw gate stands as `target_miss`.
  Root cause proven to be load-generator ceiling (k6 `MAX_VUS=256`, driver
  RSS 453MB→6.5GB): app-side pool wait stayed ~20–50µs/bin and p50 was flat.
  The repair run at identical rates with `MAX_VUS=512` dropped 0.0048% —
  PASS. Storage/lifecycle evidence from the 3h run is unaffected.
- One argon2 `503 temporarily_unavailable` in 85,592 iterations (00:46 UTC);
  zero recurrences in the 14,241-iteration repair run.
- `oauth_token_issuances` (295MB) is the largest relation — a
  retention-window ledger; its window sizing is a separate capacity
  parameter, not refresh state.

## 10. Retained evidence

Current-state reports:

- [Refresh storage redesign — final benchmark set](reports/2026-09-22-refresh-storage-redesign/report.md) (10min/30min/3h/repair evidence)
- [WAL/checkpoint envelope A/B](reports/2026-09-21-poolstarve-ab-30m/report.md) (`max_wal_size` 1GB vs 8GB root cause)
- [Formal 6h soak r1](reports/2026-09-21-final-soak-6h-formal-r1/report.md) — FAIL on drop gate; audit 42.2M complete; historical root-cause record
- [Final 6h soak r1](reports/2026-09-20-final-soak-6h-r1/report.md) — FAIL: required-audit loss root cause (bounded queue) + fix lineage
- [Audit retention fix / state-min v2 8h](reports/2026-09-19-state-min-v2/report.md) — historical 5h10m cliff and its elimination
- [Audit delivery & retention remediation](reports/2026-09-20-audit-delivery-retention/report.md)

Capacity baselines:

- [Capacity curve overview](performance-capacity-curve.md) + `reports/main`,
  `reports/extended`, `reports/special` scenario reports
- [2026-09-17](reports/2026-09-17-capacity-endurance/report.md) /
  [2026-09-18](reports/2026-09-18-capacity-endurance/report.md) capacity
  endurance runs (multi-endpoint ladder + soak baseline)
- [2026-09-19 state lifecycle](reports/2026-09-19-state-lifecycle/report.md)
  and [state minimization](reports/2026-09-19-state-minimization/report.md) —
  remediation rounds superseded by the redesign above, retained as fix lineage
