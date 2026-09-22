# Manifest — Refresh Storage Redesign benchmark set

## Source identity

- `BASE_SHA` = `ef45b8817b41e5683dc5361c2b5a72916fa19db7` (fetched `origin/main` at archive time)
- `IMPLEMENTATION_SHA` = `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5`
  - This is a **content fingerprint**, not a git commit: sha256 over the working-tree diff + untracked files applied on top of `BASE_SHA` (the refresh-state three-table model, spent-proof cap, and perf-toolchain adaptation). The implementation was exercised from the container build, not committed under this id.
- nazoauth image: built in-container from that applied diff; deployment `01a0c608-3576-7fe1-904c-675dbc851f3f` (3h soak), `01a0c5a8-206b-7320-b495-bf890b09a256` (10m/30m runs).

## Runs

| RUN_ID | Role | Verdict |
|---|---|---|
| `20260922-refreshmin-10m-v2` | 10min refresh-heavy gate | PASS (62 sampler bins) |
| `20260922-integrated-30m-r2` | 30min integrated gate | PASS (182 bins) + sidecar re-verify |
| `20260922-storage-3h` | 3h storage/lifecycle soak | storage PASS; `target_miss` on drop gate (load-gen ceiling) |
| `20260922-dropsfix-30m` | drop-gate repair verify (MAX_VUS 256→512) | PASS, drops 0.0048% |
| `20260922-sidecar-verify` | argon2/fapi/meta 420s re-verification for r2 | PASS, 0 errors |

Superseded/invalid siblings (`20260922-refreshmin-10m` v1 — sampler-write bug; `20260922-integrated-30m` r1 — sidecar vector-pool misconfiguration) were not archived: no independent evidence value beyond the corrected reruns.

## Harness tool digests (sha256, repo copies at run time)

From `evidence/20260922-storage-3h/manifest.txt`:

- `ledger.sql` `24b9cb3fe8c249b9e65dacceb0e8e8b1da8ff29512c3e795e7bcea43f1ddabf2`
- `soak_sampler.py` `b377f7b4aa16bee1e35e8b93af5989607ac1e127c28b50159e0f555c80cbf221`
- `vkledger.py` `9367851303b227157c004a7ad4251c9f05388c46d12e0f95116a1fbad913f82b`
- `ledger_check.py` `aacf367b5458c42d83c8c17c187895f53aca54113b7dad5e69c2b7722c64fcd8`
- `soak_run.sh` `b330e1af399a1889fb4987ed66d32f083977656e3bd08130a9890384af91b6e8`

## Environment

- Host: 64C/128G container host (`cnb-9ge-1k328fgjv-001`), Docker compose stack
- PostgreSQL `postgres:18-alpine`, `max_wal_size=8GB` (per poolstarve A/B sizing)
- Valkey `valkey:8-alpine`
- Workload (frozen): main `cap_mixed` @1800 ops/s; refresh `cap_refresh_token` @600/s; argon2 `oidc_cold_login_refresh` @8/s; metadata `metadata_jwks` @200/s; FAPI `fapi2_logged_in_high_security` @30/s; audit exporter + durable receiver; maintenance/autovacuum live.
- Duration: 10,800s (3h soak); 1,079 sampler bins at 10s.

## Evidence layout

- `evidence/<RUN_ID>/soak-metrics.jsonl` — 10s sampler bins (DB size, WAL, refresh model counters, relation bytes, pool, audit)
- `evidence/<RUN_ID>/runner-rss.jsonl` — RSS series (app + driver)
- `evidence/<RUN_ID>/ledger-{pre,post,diff}.txt` — row/table ledger
- `evidence/<RUN_ID>/<workload>/*.summary.json` + `*.errors.json` — k6 aggregates and classified errors
- `evidence/<RUN_ID>/audit-health.jsonl`, `audit-receiver-state.json` — exporter/receiver integrity
- `evidence/<RUN_ID>/vkledger-{pre,post}.json` — Valkey key census
- `evidence/<RUN_ID>/manifest.txt`, `soak.log`, `watchdog.log`
