# Manifest — 2026-09-22 current-capacity benchmark set

## Source identity

| Field | Value |
|---|---|
| `TASK_BASE_SHA` | `2aad6048b33240c7f324ade44da8ecad2bda368e` |
| `FINALIZATION_BASE_SHA` | `822c44c81d9f10691753931c9c532b4b0266b314` (this report's own commit; the 1900 run built from it) |
| `D416_CONTENT_FINGERPRINT` | `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5` |
| `RECOVERED_D416_FINGERPRINT` | `d416a1ee4595b1f9ed0fcc2201bf3c512fe4d73ae3378a7968455665954a30c5` |
| `D416_RECOVERY` | `EXACT` |
| `REFRESH_IMPLEMENTATION_SHA` | `50d896a8…` (production refresh tree; see chain below) |
| `TEST_SOURCE_SHA` | `fd52b556370fa8d72ecfef35947bae8241e722e6` |

### Fingerprint rule (recovered verbatim from session metadata)

```bash
{ git diff HEAD; cat crates/persistence-postgres/tests/refresh_family_capacity.rs \
    migrations/20260926000100_refresh_state_minimal/up.sql \
    migrations/20260926000100_refresh_state_minimal/down.sql; } | sha256sum
```

Evaluated on a clean worktree of `ef45b8817b41e5683dc5361c2b5a72916fa19db7` +
the recovered working tree: reproduced `d416a1ee…` byte-for-byte (three
independent reproductions).

### Commit chain (all on `main`, pushed to `origin` + `cnb`)

| Commit | Role |
|---|---|
| `50d896a8` | `fix(refresh): bound durable refresh state` — recovered production implementation + migration + tests |
| `7f3bdaa4` | `style(refresh): rustfmt the recovered implementation` — mechanical fmt only |
| `249457a4` | `perf: pin reproducible current-capacity environment` |
| `95f4c809` | `perf: add refresh sidecar to sustained workload` |
| `589d826f` | `perf: pin pg_stat_statements and refresh sidecar VU ceiling` |
| `201718b8` | `perf: classify expected refresh invalid_grant and fix capacity gates` |
| `ce76f7e2` | `perf: pass capacity point env via -e flags` |
| `9f4eb068` | `perf: evaluate capacity gate on measured metrics, not runner status` |
| `fd52b556` | `perf: measure capacity rate over the post-warmup window` |

`git diff 7f3bdaa4..fd52b556 -- crates/ migrations/ Cargo.toml Cargo.lock` = **empty**
(every commit after the fmt normalization touched only `perf/`, `docker-compose.perf.yml`).

### d416 → commit equivalence

Per-file byte comparison of the recovered d416 tree vs `REFRESH_IMPLEMENTATION_SHA`:
all production files identical except six files whose only deltas are rustfmt
canonicalization (line joins, trailing commas, closure braces) — verified by
whitespace-stripped and token-level diff. No semantic delta.

## Provenance (per run)

Captured by `perf/tools/soak_run.sh` into each run's `manifest.txt`:
`TEST_SOURCE_SHA`, git-clean flag, app image id + repo digest, running binary
`sha256` (`/proc/1/exe`), `MIGRATION_SET_SHA256`, `APPLIED_MIGRATIONS_SHA256`,
`CANONICAL_PG_SCHEMA_SHA256`, PostgreSQL runtime settings, Valkey
version/policy, harness versions, host profile.

| Field | Value |
|---|---|
| app image | `nazoauth-perf-nazoauth` local build |
| image id (final runs, built @`fd52b556`) | `2bfa9c824d29` |
| `RUNNING_BINARY_SHA256` | `24d8067d395c624c7677e3d8c45d8e18c8be04182177bcb4d32ede17389fa0ae` |
| `MIGRATION_SET_SHA256` | `4b25e9660a74b4f62385336be5921e3636bc5c01ca3ca82ee1b8fead19f9d240` (84 migrations) |
| `APPLIED_MIGRATIONS_SHA256` | `84dbbfd1a001d7a3a90b995531fd44a7fd1cb39ffb6468af8bcf25314d667df9` (84 rows) |
| `CANONICAL_PG_SCHEMA_SHA256` | `c0e96dbad212dd0b132934bf15a86c6841f122a97c7cdbdc5b2fc4d4b90a0f87` (1,772 catalog rows, deterministic across captures) |
| PostgreSQL | `postgres:18-alpine` (`d3e1620b…`), `max_wal_size=8GB`, `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `checkpoint_timeout=5min`, `checkpoint_completion_target=0.9`, `shared_buffers=128MB` |
| Valkey | `valkey:8-alpine` (`e0eb7c48…`), `maxmemory=0`, `noeviction` |
| k6 | `v2.2.0` (perf image) |
| Host | AMD EPYC 9K65, 64 logical CPUs, 128 GB RAM, kernel 5.4.241 |

Binary reproducibility: image rebuilt from a clean `fd52b556` checkout
yields the same `RUNNING_BINARY_SHA256` — the running container and the
committed source are the same binary.

Schema identity is a triple: `MIGRATION_SET_SHA256` (repo migration files),
`APPLIED_MIGRATIONS_SHA256` (live `__diesel_schema_migrations` rows), and
`CANONICAL_PG_SCHEMA_SHA256` (deterministic catalog dump via
`perf/tools/canonical_schema.sql` — sorted logical schema covering tables,
columns, types, nullability, defaults, PK/unique/FK/check constraints,
indexes, sequences, views, functions, triggers; excludes OID, owner, ACL,
storage order, statistics, timestamps). The earlier raw `pg_dump -s` hash
(`19bd89af…`, `0cdee983…`, `974a2558…` observed on the same migration set)
varied with OID ordering and runtime-table materialization order — it is
retained only as `PG_DUMP_SCHEMA_SHA256_DIAG`, never as identity.

## Runs

| RUN_ID | Role | Duration | Verdict |
|---|---|---|---|
| `current-refresh-10m-r1` | refresh storage/regression verification @ `589d826f` binary-identical | 600s | all gates PASS (raw artifacts lost with recycled workspace; values retained in `report.md`) |
| capacity search points | `perf-results/capacity-search/<scenario>/r<rate>/` | 600s each | see `report.md` |
| `current-capacity-final-30m` | sustained `cap_mixed` @2000 on inherited matrix DB (44.9M audit backlog) | 1800s | gate FAIL — see `report.md` §sustained-under-backlog |
| `current-capacity-final-30m-fresh` | sustained `cap_mixed` @2000 on fresh DB, all sidecars | 1800s | measured 1967.4 ops/s; rate gate miss (−1.6%), latencies clean, 0 shed, audit complete |
| `current-capacity-final-1900-30m` | sustained `cap_mixed` @1900 on fresh DB, all sidecars | 1800s | gate FAIL — measured 1889.129 ops/s < 1890.5; all other gates PASS |

## Evidence layout

- `evidence/capacity-search/` — per-scenario `search-ledger.jsonl`, `result.json`, per-point summaries; `cap_mixed/` carries the two full capsearch soak dirs (r2000/r2500) with ledgers
- `evidence/argon2/` — `cold-c8` + `cold-c16` point summaries and error classification
- `evidence/current-capacity-final-30m/` — sustained run on inherited matrix DB (backlog degradation evidence)
- `evidence/current-capacity-final-30m-fresh/` — canonical sustained run on fresh DB @2000 (same soak evidence set)
- `evidence/current-capacity-final-1900-30m/` — final sustained run on fresh DB @1900 (same soak evidence set + canonical schema captures)

`current-refresh-10m-r1` raw artifacts were lost when its benchmark
workspace was recycled; its extracted values are retained in `report.md`,
and the fresh-30m sampler independently re-verifies every refresh bound.
