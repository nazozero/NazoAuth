# Current Capacity Baseline — 2026-09-22

This is the canonical capacity record for the current release. Every number
below was measured against `TEST_SOURCE_SHA` on a clean checkout; see
`manifest.md` for the full provenance chain (git → image → binary → schema).

- `TEST_SOURCE_SHA`: `fd52b556370fa8d72ecfef35947bae8241e722e6`
- `REFRESH_IMPLEMENTATION_SHA`: `50d896a8` (+ `7f3bdaa4` rustfmt normalization)
- Topology: 1× nazoauth, 1× PostgreSQL 18 (`max_wal_size=8GB`), 1× Valkey 8
- Host: AMD EPYC 9K65, 64C/128G container host
- Method: adaptive 10-minute capacity points (`perf/tools/capacity_search.py`),
  `PASS` = drops ≤0.1%, measured rate ≥99.5% of target, zero unexpected
  errors, p95 ≤100ms, p99 ≤250ms; final headline = 30-minute sustained
  `cap_mixed` with all sidecars + audit exporter + receiver.
- **No test longer than 30 minutes was run.** The 3h storage-plateau evidence
  lives in `../2026-09-22-refresh-storage-redesign/` and applies to this
  implementation because its content fingerprint (`d416a1ee…`) was recovered
  exactly and committed (see manifest).

## Current capacity matrix

| Scenario | MAX_10M_PASS | FIRST_FAIL_ABOVE | ops/s @pass | HTTP rps @pass | p95 ms | p99 ms | drops | unexpected errors |
|---|---|---|---|---|---|---|---|---|---|
| cap_mixed (full sidecars) | 2000 | 2500 | 1998.3 | 2862 | 10.3 | 16.2 | 0.011% | 0 |
| cap_client_credentials | 3200 | 3400 | 3198.4 | 3198 | 7.3 | 15.2 | 0.05% | 0 |
| cap_authorization_code | 1125 | 1250 | 1125 | 4499 | 12.2 | 17.4 | 0.012% | 0 |
| cap_refresh_token | 1440 | 1600 | 1441.7 | 1442 | 9.7 | 14.0 | 0% | 0 |
| fapi2_logged_in_high_security | 731 | 913 | 731 | 3655 | 11.0 | 17.3 | 0.007% | 0 |
| cap_introspect | 7812 | 8788 | 7815.1 | 7815 | 1.0 | 1.3 | 0.028% | 0 |
| cap_revoke | 787 | 875 | 787 | 3935 | 8.5 | 12.4 | 0% | 0 |
| mtls_client_credentials | 3515 | 3906 | 3515.0 | 3515 | 7.4 | 14.4 | 0% | 0 |
| par_signed_request_object | 6102 | — (ladder cap) | 6102 | 6102 | 1.2 | 8.5 | 0% | 0 |

`cap_mixed` additionally carries sidecars on every point: refresh 600/s,
argon2 8/s, metadata 200/s, FAPI 30/s, audit exporter + receiver. Its 2500
point attained 2486.7 ops/s (99.47% of target) — a borderline miss against
the 99.5% gate, so `first_fail_above=2500`.

`par_signed_request_object` reached the 6-point ladder cap still passing;
`first_fail_above` was not established within the point budget.

## Argon2 (separate class)

`oidc_cold_login_refresh`, 10-minute constant-VU points. Argon2 concurrency
stays at 8 (not raised for a better number).

| VU | attempted login/s | successful login/s | rejected | login 503 | login p50/p95/p99 ms | HTTP req/s |
|---|---|---|---|---|---|---|
| 8 | 55.1 | 55.1 | 0% | 0 | 121.0 / 127.6 / 138.0 | ~330 |
| 16 | 93.3 | 56.6 | 39.3% at login step | 22,016 (`temporarily_unavailable`) | 156.1 / 255.8 / 269.8 | ~413 |

At 16 VU the concurrency-8 Argon2 slot limit is the active backpressure:
39.3% of login attempts return `503 temporarily_unavailable`, all other
steps clean. Reported as measured — protection semantics unchanged.

## Headline

### `current-capacity-final-1900-30m` — fresh `oauth` database, all sidecars, `cap_mixed` @1900 it/s

```
TARGET=1900 ops/s   MEASURED_OPS_S=1889.129 (cap_measure_ops 3,372,095 / 1785s)
ATTAINMENT=99.43%   HTTP_RPS=2718.0
P50=4.2ms  P95=11.2ms  P99=19.2ms
DROPS=3,119  DROP_RATE=0.091%   UNEXPECTED_ERRORS=0
WAL=+17.58 GB / 3.42M ops ≈ 5.1 KB/op   DB_FINAL=490 MB (ledger-post)
APP_RSS=91→218 MB (flat ~201 MB plateau t+5–25 min)   restarts=0
AUDIT=receiver 5,218,207 events / 85,890 batches; dup=0; reject=0;
      anchor 5,218,207 == DB anchor 5,218,207; pending=0 after drain;
      queue_full shed=0; dropped_required=0
REFRESH=families 5,894 live / 24.9 MB; spent 41,824 / 25.3 MB;
      contracts 1,160 / 1.17 MB; max 10 families/scope; max 64 spent/family;
      expired spent backlog=0 on every sample
```

**Verdict: FAIL** — measured 1889.129 ops/s < 1890.5 required (99.5% ×
1900), a miss of 0.07%. Every other gate passed (drops 0.091% ≤0.1%, zero
unexpected errors, latencies far inside bounds, audit fully reconciled).

Mechanism: the same timed-checkpoint arrival dips as the 2000 run — the
worst window t≈1640–1695 s briefly fell to ~840 it/s for ~2 s with VU
scaling to 500 (MAX_VUS 1024, never hit); steady-state between dips is the
full 1900 it/s. Runner averaged 1.7 CPU cores and peaked 4.0 GB RSS on a
64C/128G host — not load-generator-bound. Latency, pool wait, and backend
counts stayed healthy throughout: the strict gate measures
arrival-schedule fidelity under periodic checkpoint flush, not a server
saturation ceiling.

Provenance note: this run's checkout was `822c44c8` (this report commit —
docs-only delta over `fd52b556`; `git diff fd52b556..822c44c8 -- crates/
migrations/ Cargo.toml Cargo.lock` is empty) and the running binary is
byte-identical (`RUNNING_BINARY_SHA256=24d8067d…`, image `2bfa9c824d29`).

Consequence: `STRICT_30M_CAPACITY_NOT_ESTABLISHED`. Validated sustained
statement is therefore: **10-minute mixed target 2000 ops/s; 30-minute
observed delivery 1967.4 ops/s @2000 target and 1889.1 ops/s @1900
target** — the 1900–2000 boundary was not searched and no exact maximum is
claimed. Sidecar terminal metrics were not persisted for this run (sidecar
stdout is lost on container removal — a harness gap already present in the
2000 run); app logs show zero `queue_full`/`dropped_required` over the run
window.

### `current-capacity-final-30m-fresh` — @2000 it/s

Fresh `oauth` database, all sidecars, audit exporter + receiver,
`cap_mixed` at the matrix's 10-minute pass rate:

```
MAX_SUSTAINED_MIXED_30M=2000 (target)
MEASURED_OPS_S=1967.4   (98.4% of target — rate gate miss)
HTTP_RPS=2858.3
P50=4.2ms  P95=11.9ms  P99=37.9ms
DROP_RATE=0.158% (5,669 iterations)
UNEXPECTED_ERRORS=0   QUEUE_FULL_SHED=0
WAL_PER_OP=+18.63 GB / 3.54M ops ≈ 5.26 KB/op
DB_FINAL=815 MB (fresh schema + one soak's accumulation)
APP_RSS=91→224 MB
AUDIT=receiver 5,417,360 events; duplicates 0; rejects 0; pending ≈107
```

Verdict: **rate gate missed by 1.6%** (required ≥99.5% = 1990 ops/s;
measured 1967.4). Drops 0.158% vs the 0.1% gate. Latencies far inside
bounds — this is a throughput deficit, not a latency failure.

Mechanism (measured, not inferred): five timed checkpoints fired during
the window (`checkpoint_timeout=5min`). Each checkpoint produces a
10–60 s throughput dip — the worst at t≈1637–1695 s drove completion to
~430 it/s for ~2 s and pinned 594 VUs; steady-state between dips is the
full 2000 it/s. The deficit ≈ dropped iterations inside dip windows, so
it is roughly proportional to arrival rate rather than a hard server
ceiling. `pg` activity stayed ≤26 backends, pool wait averaged 0.395 ms,
statement mean 0.048 ms — the server was never saturated.

### Sustained-under-backlog (second 30 m run, `current-capacity-final-30m`)

The same 2000 it/s target was also run on the database carrying the
entire capacity matrix's state — **44.9 M pending audit events, 39 GB
audit+outbox+chain**. It is kept as degradation evidence:

```
measured_ops_s=1950.5  drops=0.72%  p95=144ms  p99=495ms
WAL=+26.4 GB / 3.51M ops ≈ 7.9 KB/op   DB=40.6 GB
audit pending 44.9M→43.3M (net drain ~965/s while serving)
queue_full shed=16,806 events (00:41:22–00:50:10Z)
app RSS 166→310 MB peak, end 197 MB
```

- At t≈15 min a timed checkpoint on 39 GB of audit churn stalled the
  writer; request VUs spiked 13→951 (max 1024) for ~30 s.
- The in-memory audit queue (capacity 4096, single draining worker)
  overflowed for ~9 min: **16,806 events were rejected `queue_full` and
  never reached the durable sink**. Taxonomy per the run log: all 16,806
  were Telemetry-class (`persistence_status="not_queued"` —
  `authorization_approved` 16,474, `login_success` 332); zero
  `dropped_required` — Required-class events persist via the fail-closed
  transactional path and were not lost. Requests were unaffected; the run
  measured the shedding cost of a pathological inherited backlog and is
  not a capacity result.
- Even so the system delivered 1950 ops/s sustained *and* net-drained
  the 43 M outbox backlog (~965/s) — recovery behavior is real, bounded
  only by export throughput.

Interpretation: the audit outbox is the dominant durability cost
(~2960 events/s at 2000 ops/s ≈ 1.5 events/op... plus chain entries).
With a bounded in-memory queue of 4096, any export stall >~1.4 s sheds
events. On a fresh DB the export pipeline keeps pace (pending ≈100–400,
worst observed burst 54.8k, all drained; zero shed).

## Refresh storage verification

Two independent measurements — a dedicated 10 m refresh point
(`current-refresh-10m-r1`) and the sampler stream inside the canonical
30 m fresh run (refresh sidecar 600/s under full mixed load):

| Gate | `current-refresh-10m-r1` | `current-capacity-final-30m-fresh` |
|---|---|---|
| max active families / scope | 10 (bound held) | 10 (bound held all run) |
| max spent proofs / family | 64 (bound held) | 64 (bound held) |
| expired spent backlog | 0 | 0 (every sample) |
| `oauth_tokens` runtime authority | table dropped; zero DML | table absent |
| refresh durable bytes | ~44 MB (vs 15.63 GB old model) | ~60 MB total: families 29.0 + spent 30.1 + contracts 1.3 |
| families live / spent live / contracts | 3,648 / 14,598 / 1,056 | 7,038 / ~47.5k / 1,160 |
| contract dedupe | 384k rotations → 4.5k contract inserts | 608,732 family inserts → 1,160 contracts (~525:1) |
| churn convergence | — | families ins−del == live (608,732−601,694=7,038); spent ins 1,481,126 / del 1,433,641, backlog 0 |
| WAL | +4.89 GB / 10min ≈ 4.6 KB/op | +18.63 GB / 30min ≈ 5.26 KB/op (all steps) |
| audit | head == anchor == receiver (1,542,761); dup=0; reject=0 | receiver 5,417,360; dup=0; reject=0; pending ≈107 |
| expected errors | `invalid_grant` (bounded-family eviction class) | same class only; 0 unexpected |
| app RSS | 90→221 MB peak, ended 131 MB | 91→224 MB, ended 224 MB |

The r1 run's raw artifacts were on a recycled benchmark workspace; its
extracted values are kept here for comparison — the fresh-30m column is
the canonical, fully preserved evidence (`evidence/current-capacity-final-30m-fresh/`).

## Historical 3h mapping

`20260922-storage-3h` ran the identical refresh implementation as a
working-tree diff (fingerprint `d416a1ee…`). That exact content is now commit
`REFRESH_IMPLEMENTATION_SHA`; production-path byte equivalence verified
(rustfmt-only deltas). The 3h plateau, WAL/op and audit evidence therefore
applies to this commit without re-running a long soak.
