# Final Soak 6h Formal R1 — Run Manifest (FAILURE)

| Field | Value |
|---|---|
| RUN_ID | `statemin-formal-6h-r1` |
| FINAL_CANDIDATE_SHA | `dffffa322072daaecfdfb715fabf837d640be8a7` (sole tested version; pushed to origin+cnb) |
| DEPLOYMENT_ID | `01a0c284-eabc-7321-9712-be6c2a2bd1d9` |
| SOAK window | 2026-09-21T05:53:44Z → 2026-09-21T11:55:28Z (main load 21,600s; total 21,641s incl. drain+post-ledger) |
| Environment | fresh container + fresh volumes; no historical backlog, stats, or receiver state; seed (256 users / 52,000 vectors) completed before start |
| Intervention | **none** — no reseed/vacuum/restart/tuning during the window |
| Result | **FORMAL_SOAK = FAIL** — main drop fraction 0.4122% > 0.1% gate |
| Gate breaches | `main dropped_iterations = 160,275 (0.4122%)` — single ~15 min throughput sag at elapsed 2h05m–2h20m (≈08:04–08:14Z) |
| All other gates | PASS — see report §Verdict matrix |
| Cliff question | answered: historical ~5h10m exporter cliff **not reproduced** (buckets 48–66 steady ~588k arrivals/5min, claim max ≤29.6ms, pending ≤160, xmin spikes transient) |
| Audit integrity | receiver 1,240,790 batches / 42,213,228 events accepted, **0 dup, 0 reject, fault=none**; DB anchor == receiver durable head = 42,213,228; events/outbox/chain = 0/0/0 after drain |
| Required reconciliation | `authorization_decision_intent` receiver-accepted = **6,644,524**; equals post-seed token-family growth (6,644,780 − 256 seed) 1:1 — no admitted decision escaped durable intent |
| DB final | 15.97 GB total (+15.96 GB); `oauth_tokens` 15.63 GB (98% of growth); all three audit relations heap=0 live |
| WAL | +301.24 GB → **7.79 KB/op** (gate <12) |
| RSS | nazoauth 132.5–204.3 MB sawtooth, ends 134 MB — bounded, no monotonic growth |
| Scene | preserved: evidence dir intact on bench host + this repo copy; receiver volume `nazoauth-perf_audit_receiver_data` retained (journal 38 GB) |

## Frozen identities

| Item | Value |
|---|---|
| Source | `dffffa322072daaecfdfb715fabf837d640be8a7` (0 tracked modifications at run time; untracked scratch artifacts excluded) |
| nazoauth image | `nazoauth-perf-nazoauth` `7a245ebd6620` (local image ID, freshly built from SHA) |
| audit-worker image | `nazoauth-perf-audit-worker` `bce49f6d395c` |
| migrate image | `nazoauth-perf-migrate` `b6a9327ff18b` |
| audit-receiver image | `nazoauth-perf-audit-receiver` `960533b24cd0` |
| perf image | `nazoauth-perf-perf` `6cc7e69c0910` |
| keyset image | `nazoauth-perf-keyset` `754c6c5b6755` |
| Migration head | `20260925000100` — claim fn `proconfig = search_path=pg_catalog,pg_temp; enable_seqscan=off; enable_bitmapscan=off` verified in-DB |
| PostgreSQL | 18.6 — `postgres:18-alpine` @ `sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2` |
| Valkey | 8.1.9 — `valkey:8-alpine` @ `sha256:e0eb7c480958d32bdc4357a74bdd70653ae15f2f9b4c93c4a5a9fad1dc471c84` (INFO `redis_version:7.2.4` is Valkey's client-compat field) |
| `soak_run.sh` | `ca2074a6f9464d5090734775fcba1344b170e29a32730f756d7714ea1153a436` |
| `soak_sampler.py` | `5f973dcf051178cf58355c68138f2032c4b6761ef4a58bb73d9b22fbb9e9f16f` |
| `ledger.sql` | `8710ccd62fdcf97e23b21113faf2cc5c0fa75b0e5ae0399bafde32fd2bafc4d4` |
| `ledger_check.py` | `a91dc5ae2254a8607945330a0deb8833162f020841b32026036f9f89a2965711a` |
| `vkledger.py` | `9367851303b227157c004a7ad4251c9f05388c46d12e0f95116a1fbad913f82b` |
| `seed.py` | `e8bd6149722bfa93a38a923191df65881c51c78e58a864bfac1f5c177a024b92` |
| `runner.py` | `db66fa425a61c09a8e3d8b5518e0a45a17eceea42cfdad8c885d62fc4da51c95` |
| `docker-compose.perf.yml` | `6b7d56b3d4775b2d653462974e548b97cc42a393b4ff069db9eb76a5b39499be` |
| `k6/oauth.js` | `1db9c6e7bbc02a757f1d77d5ad52b5cc5fbcd3b9a663d1afefdcf64acc667989` |

All runtime files verified byte-identical to `dffffa32` content before start (sha256 comparison, local repo vs container copies). No production code, migration, harness, collector, or seed change occurred during the run.

## Status ledger

| State | Status |
|---|---|
| APP_HOT_PATH | **FAIL** — drops 0.4122% (>0.1%); errors 0; p95 9.55 ms |
| ARGON2 | PASS — 171,028 logins, 1,026,168 reqs, 0 err, 0×503 (173 drops = load-driver side, not a gate) |
| FAPI | PASS — 641,689 flows, 3,208,445 reqs, 0 err |
| META/JWKS | PASS — 4,280,000 iters, 8,560,000 reqs, 0 err, 0 drops |
| AUDIT_CLAIM | PASS — 1,231,964 claims, mean 0.72 ms, max 29.6 ms, no minute-scale cliff |
| AUDIT_EXPORT_CAPACITY | PASS — 42.21M events exported+ACKed, pending≤160 transient, drain→0 |
| AUDIT_REQUIRED_INTEGRITY | PASS — 0 misrouted, 0 dropped_required, 0 receiver dup/reject, intent↔family 1:1 |
| AUDIT_TELEMETRY | PASS — 0 telemetry drops (all 42.21M events of 4 types delivered) |
| STORAGE_LIFECYCLE | PASS — audit relations converged to 0 live rows; issuances retention receding |
| WRITE_AMPLIFICATION | PASS — WAL 7.79 KB/op |
| MVCC_HORIZON | PASS — transient xmin spikes only; 0 sustained >60s/>300s transactions |
| VALKEY | PASS — 0 evictions; 11.71M natural expirations; all high-cardinality prefixes TTL-bounded |
| RSS_STABILITY | PASS — app sawtooth 132–204 MB, terminal 134 MB |
| **FORMAL_SOAK** | **FAIL** (single gate: main drops) |

## REPORT_SHA

`b27dd323cccfd8473352850bd29971bdce043b4e` (report+evidence commit; tested source unchanged at `dffffa32`)
