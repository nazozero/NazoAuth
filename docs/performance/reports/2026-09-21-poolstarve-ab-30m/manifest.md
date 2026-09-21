# Manifest — Pool-Starvation A/B (30m ×2)

Date: 2026-09-21
TESTED_SOURCE_SHA: `dffffa32` (unchanged; diagnostic-only, no business code touched)
PARENT_REPORT: `2026-09-21-final-soak-6h-formal-r1` (FORMAL_SOAK=FAIL, drops 0.4122%)
REPORT_SHA: `d04de825`

## Runs

| Field | Run A | Run B |
|---|---|---|
| RUN_ID | `statemin-poolstarve-30m-a` | `statemin-poolstarve-30m-b` |
| DEPID | `01a0c41f-73af-7a23-897c-e89fc0759de5` | `01a0c442-00d0-7e80-844e-8071e31118d7` |
| Window | 13:21:44Z–13:52:49Z | 13:58:30Z–14:29:30Z |
| Main duration | 1800s @ 1800 ops/s cap_mixed | 1800s @ 1800 ops/s cap_mixed |
| Fixture | fresh volumes + seed | fresh volumes + seed (identical) |
| `max_wal_size` | 1024MB | 8192MB |
| Everything else | identical (see report §4) | identical |
| Result | ledger PASS, drops 938 (0.029%) | ledger PASS, drops 487 (0.015%) |

## Tool digests

| Artifact | sha256 |
|---|---|
| observer `obs1s.py` | `b7366b224671e82bf7c0756b89227df8019fe39ab97515fbbab19c450b621270` |
| `ledger.sql` | `8710ccd62fdcf97e23b21113faf2cc5c0fa75b0e5ae0399bafde32fd2bafc4d4` |
| `soak_sampler.py` | `5f973dcf051178cf58355c68138f2032c4b6761ef4a58bb73d9b22fbb9e9f16f` |
| `vkledger.py` | `9367851303b227157c004a7ad4251c9f05388c46d12e0f95116a1fbad913f82b` |
| `ledger_check.py` | `a91dc5ae2254a860794533a0deb8833162f020841b32026036f9f89a2965711a` |
| `soak_run.sh` | `ca2074a6f9464d5090734775fcba1344b170e29a32730f756d7714ea1153a436` |

## Image / platform

- PostgreSQL `postgres:18-alpine` @ `sha256:d3e1620b…65b2` (same both runs)
- Valkey `valkey:8-alpine` @ `sha256:e0eb7c48…c84` (same both runs)
- nazoauth image built from `dffffa32` (same both runs)
- PG storage: Docker volume on host RAID0 `md0` (members `vdb`–`vdu`)

## Evidence files

- `evidence/statemin-poolstarve-30m-{a,b}/` — k6 summaries (main + 3 sidecars),
  ledger pre/post/diff, audit-receiver-state.json, audit-health.jsonl,
  vkledger pre/post, soak.log, manifest.txt
- `evidence/observer/obs-run{A,B}.jsonl` — 1s observer raw samples
- `evidence/observer/obs1s.py` — observer source (digest above)

## Verdict

`PostgreSQL WAL/checkpoint envelope undersized for this write rate` —
deployment-capacity configuration defect, not application pool/code defect.
Recommendation: `max_wal_size >= peak WAL rate × checkpoint interval × safety factor`.
