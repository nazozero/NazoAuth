# Formal 6h Soak — `dffffa32` — `statemin-formal-6h-r1`

**FORMAL_SOAK = FAIL.**

One gate breached: main `cap_mixed` dropped **160,275 iterations = 0.4122%** (gate ≤0.1%), produced by a single ~15-minute throughput sag at elapsed ≈2h05m–2h20m (wall ≈08:04–08:14Z). Every other mandatory gate passed, including all audit-integrity gates at their strongest measured level in this program (0 misroute, 0 required drop, 0 telemetry drop, 0 receiver dup/reject, exact four-way reconciliation, anchor==receiver==42,213,228).

The historical ~5h10m cliff was **not reproduced**. The dip that failed the run occurred earlier (≈2h15m elapsed) and recovered by itself; no restart, OOM, or intervention occurred anywhere in the window.

---

## 1. Identity and provenance

See `manifest.md` for the frozen-identity table. Headlines:

- `FINAL_CANDIDATE_SHA = dffffa322072daaecfdfb715fabf837d640be8a7` — sole tested version; runtime files verified byte-identical (sha256) before start.
- Fresh container, fresh volumes, zero inherited backlog/stats/receiver state. Seed (256 users, 52,000 flow vectors) completed pre-run.
- Migration head `20260925000100`; claim function carries `proconfig` pins `enable_seqscan=off`, `enable_bitmapscan=off`.
- PostgreSQL 18.6 (`postgres:18-alpine` pinned), Valkey 8.1.9 (`valkey:8-alpine` pinned; its INFO `redis_version:7.2.4` is the client-compat field, not the server version).
- No reseed, bulk UPDATE, manual VACUUM/REINDEX, restart, pool/batch/worker change, key rotation, or load-ratio change during the run. `RestartCount=0`, `OOMKilled=false` on nazoauth, postgres, valkey.
- `DEPLOYMENT_WORM_VERIFICATION`: **not claimed** — the receiver is a test double with fsync'd journal+checkpoint, not external trusted WORM infrastructure.

## 2. Main load accounting (`cap_mixed`, constant-arrival 1800/s target)

| Metric | Value |
|---|---|
| Configured target | 1800 logical iterations/s × 21600s |
| Scheduled | 38,880,039 (= 38,719,764 completed + 160,275 dropped; runner's emitted `scheduled_estimate` field read 38,800,039 — runner-side estimate defect, corrected here) |
| Completed iterations | 38,719,764 |
| Dropped iterations | **160,275 (0.4122%)** |
| Measured successful logical ops | 38,669,819 |
| Measured successful ops/s | **1,790.269** |
| HTTP requests | 56,237,902 (2,603.6 req/s) |
| HTTP error rate | 0.0 (zero unexpected, zero business errors) |
| Iteration latency | p95 = 9.551 ms |
| k6 DB statement calls | 972,713,407 |
| VU warnings | none ("Insufficient VUs" absent; maxVUs 256 saturated) |
| k6 exit / status | 0 / `target_miss` |

Nominal 1800/s is configuration, not measured throughput; measured sustained success = **1,790.27 ops/s**.

`started` vs `completed`: the runner reports completed iterations and `0 interrupted` in progress output; a separate `started` counter is not emitted by this harness (gap noted in §14).

## 3. The drop event — what is established

Per-5-minute completion rates from the k6 progress stream:

```
… steady 1799.4–1800.1/s through 1h45m …
1h50m  1795.4/s     1h55m  1796.4/s
2h00m  1750.9/s     2h05m  1774.5/s
2h10m  1504.2/s  <== 2h15m  1672.7/s  <==
2h20m+ 1800.0/s — steady to 6h00m
```

Deficit arithmetic: (1800−1504.2)×300 + (1800−1672.7)×300 + (1800−1750.9)×300 + (1800−1774.5)×300 + minor sub-target bins ≈ 88.7k+38.2k+14.7k+7.6k+~10k ≈ **159k ≈ 160,275 observed drops**. The drops are fully accounted by this one window.

**Direct mechanism (established):** the app's DB pool acquisition wait (`pool.wait_ns` counter, 10s samples) burst to +500–6,600 s of aggregate wait per 30 s during ≈08:04–08:13Z, versus ~2 s/30s baseline immediately after 08:14Z. Requests queued on connections; per-acquire max stayed ≤0.55 s (many moderate waits, not one hard block).

**What it was not (evidence):**

- Not an audit/exporter stall — claim max stayed ≤9.1 ms through the dip buckets, pending ≤99, receiver ACK unaffected.
- Not PG IO saturation — physical reads rose only ~25% (4,121 vs 3,298 blk/s), buffer hit stayed 98.6%, commits fell 11% *with* the load (the DB did less work, not more).
- Not OOM/crash/restart — `OOMKilled=false`, `RestartCount=0` on all core containers; app RSS sawtooth continued.
- Not a k6 accounting artifact — DB-side audit arrival fell independently in the same wall-clock window (bucket deltas 516,964 and 530,656 vs the steady ~588–590k/5min, buckets 21–22 @ 08:07/08:12Z).
- Not VU exhaustion — no warning emitted, and the deficit is a rate sag not a queue asymptote.

**Correlated, unproven:** transient `backend_xmin`-holding transactions (lag 20k–80k xids, tens of seconds each) recurred densely inside the window, and recurred sparsely elsewhere (e.g. buckets 52/58) without throughput impact. Checkpoint duty cycle was already ~90% (549 checkpoints/6h, mean write ~35s each); a large checkpoint overlapping the window is a plausible contributor but not observable post-hoc (`log_checkpoints` off). The narrowest established statement: **a ~15 min interval of elevated DB statement latency starved the app's connection pool; the trigger (checkpoint write burst vs. transient snapshot-holding transactions vs. host IO contention) is not separable with the collected sampling.**

### Required targeted short test (not run — no second soak)

Reproduce at the same frozen configuration for ~60–90 min with **1s-granularity** sampling of `pg_stat_activity` (`wait_event_type`, `wait_event`, `query_id`, `backend_xmin`), `pg_locks` contention, pool wait deltas, and `pg_stat_io`/checkpointer timing, plus `log_checkpoints=on`. Decision the test answers: whether pool starvation is driven by lock/snapshot waits (→ query-class fix) or write IO bursts (→ checkpoint spread / storage class). No tuning or re-run of 6h.

## 4. Audit ledger (Required vs Telemetry)

Continuous 5-minute collection over the whole window; final state after drain:

| Gate | Observed |
|---|---|
| `misrouted_required` | **0** (bucket-sampled + zero `audit.persistence` log lines in the entire run) |
| `dropped_required` | **0** |
| Telemetry drops | **0** (all emitted events delivered this run) |
| Receiver duplicates / rejects / fault | **0 / 0 / none** |
| Chain discontinuity | **0** |
| Receiver batches / events accepted | 1,240,790 / 42,213,228 |
| DB anchor == receiver durable head | **42,213,228 == 42,213,228** ✓ |
| Post-stop `events/outbox/chain` live | **0 / 0 / 0** |
| Pending max / oldest pending max | 160 rows / 6 s — transient, no positive drift |
| Claim latency | 1,231,964 calls, mean 0.72 ms, **max 29.6 ms** (no minute-scale cliff) |

### Required three-way reconciliation

| Leg | Count | Basis |
|---|---|---|
| Admitted authorization decisions | 6,644,524 | post-seed token-family growth: `count(distinct token_family_id)` = 6,644,780 − 256 seed families. Each admitted decision creates exactly one family; a decision that skipped its intent would still create a family → counts would diverge. |
| Durable `authorization_decision_intent` | 6,644,524 | journal receiver-accepted count (durable==exported: chain continuous, pending=0, anchor==receiver) |
| Receiver-accepted Required intents | 6,644,524 | `journal.jsonl` exact `event_type` count |

Difference: **0**, explained structurally (intent is written atomically inside the decision transaction, fail-closed) and empirically (family 1:1).

Journal exact event census (38 GB `journal.jsonl`):

| `event_type` | receiver-accepted | Cross-check | Match |
|---|---|---|---|
| `token_issued` | 28,753,152 | `oauth_token_issuances` n_tup_ins | exact |
| `authorization_decision_intent` | 6,644,524 | new token families | exact |
| `authorization_approved` (Telemetry) | 6,644,524 | intents 1:1 | exact |
| `login_success` | 171,028 | argon2 completed iterations | exact |
| **total** | **42,213,228** | DB anchor / receiver seq | exact |

Telemetry emitted = queued = persisted = 6,644,524; dropped = 0 — reported independently, not merged into Required completeness.

## 5. PostgreSQL byte ledger (same collector pre/post; deltas)

| Item | Pre | Post | Delta |
|---|---|---|---|
| DB total | 13.3 MB | **15.97 GB** | **+15.96 GB** |
| `oauth_tokens` heap | 0.18 MB | **10.37 GB** | +10.37 GB |
| `oauth_tokens` indexes | 0.25 MB | **5.26 GB** | +5.26 GB |
| `oauth_tokens` total | 0.47 MB | **15.63 GB** | **98% of all growth** |
| `oauth_token_issuances` total | 0.05 MB | 263.5 MB | live 406,414 rows (`retain_until` window) |
| `security_audit_events` heap | — | **0 B** (residual idx 5.9 MB) | ins=del=42,213,228 |
| `security_audit_event_outbox` heap | — | **0 B** (residual idx 12.9 MB) | ins=del=42,213,228 |
| `security_audit_chain_entries` heap | — | **0 B** (residual idx 40.3 MB) | ins=del=42,213,228 |
| `user_client_grants` | 0.21 MB | 5.05 MB | 320 live rows, **6.64M updates** (last_authorized hot rows) |
| `security_audit_chain_state` | 0.03 MB | 0.21 MB | 3.72M HOT-updates |

Audit delivered state receded continuously — delivered rows do not persist with cumulative sequence.

### `oauth_tokens` focus

| Metric | Value |
|---|---|
| Rows | 12,623,963 (+583 rows/s; +722 KB/s total relation) |
| Active (not revoked, not sparsified) | 6,644,780 |
| Revoked | 5,979,183 (47.4%) |
| Sparsified / reuse-detected | 0 / 0 |
| Distinct families | 6,644,780 → **1.90 members/family** |
| Bytes per active family | 2,353 B (15.63 GB / 6.64M) |
| Dead tuples / autovacuum count | 79,123 / 101 runs |

Interpretable model only (no 30-day extrapolation): under this workload each admitted decision leaves one active family; refresh rotation appends ~0.9 revoked member per family; growth is linear in decisions at ~2.35 KB/family and is bounded by retention/sparsification policy rather than uncontrolled — the observed leak-free audit side and stable revocations support boundedness at this scale.

## 6. WAL / DML ledger

| Metric | Delta | Per op (38.67M) |
|---|---|---|
| WAL bytes | +301.24 GB | **7.79 KB/op** (gate <12 ✓; short-test baseline 6.0) |
| WAL records | +1,383.14 M | 35.8/op |
| WAL FPI | +27.11 M | 0.70/op |
| `tup_inserted` | +168.02 M | 4.34/op |
| `tup_updated` | +16.36 M | 0.42/op |
| `tup_deleted` | +154.99 M | 4.01/op |
| `xact_commit` | +330.19 M | 8.54/op |
| `xact_rollback` | +3 | ≈0 |

WAL above the 6.0 KB/op short-test figure but well under the 12 KB/op ceiling; the +1.8 KB/op delta is attributable to index growth churn on `oauth_tokens` (5.26 GB new index) + audit triple-insert/delete throughput — consistent with relation-level evidence, no anomalous relation found.

## 7. Valkey census (exact SCAN pre/post)

| Metric | Pre | Post |
|---|---|---|
| Total keys | 258 | 240,327 |
| `used_memory` | 1.39 MB | 108.63 MB |
| `used_memory_rss` | 10.39 MB | 158.70 MB |
| `evicted_keys` | 0 | **0** |
| `expired_keys` | 0 | **11,711,762** |
| hits / misses | 396 / 278 | 137.77M / 388k |

Post prefixes: `oauth:session` 171,542 (TTL spread ~2–8h, matching login times), `oauth:jar` 41,510 (≤2m), `oauth:dpop` 21,469 (≤2m), `oauth:client_assertion` 5,805 (≤1m), `tenant-directory:snapshot` 1 (no_ttl — singleton snapshot, explainable non-cardinality). Consumed authorization-code markers did **not** reappear (no marker prefix in census); no new high-cardinality prefix without TTL. 11.7M natural expirations show transient markers churned through correctly.

## 8. MVCC / horizon

| Metric | Max observed | Final |
|---|---|---|
| `pending` audit rows | 160 | 0 |
| oldest pending age | 6 s | — |
| oldest active xact age | **67 s** (transient) | — |
| xacts >60s / >300s | 1 transient / **0** | 0 / 0 |
| idle-in-transaction | 4 | 0 |
| `xmin_lag_xids` | 158,487 (bucket 52), 156,829 (bucket 58) — recovered to single/double digits next bucket | −1 |
| audit-health chain gap | 56,478 transient (10:23–10:31 window), p50 = 47 | 0 |

No seed/bulk maintenance ran during load; autovacuum continued normally (oauth_tokens 101 runs, issuances 251, audit relations 359 each). Transient xmin holders are preserved as evidence, not masked.

## 9. RSS / process stability

| Container | Range (MB) | Note |
|---|---|---|
| nazoauth (SUT) | **132.5 – 204.3**, ends 134.2 | sawtooth — allocator returns memory; no monotonic growth; independent of DB growth (PG +15.9 GB while app RSS flat) |
| postgres | 4,424 – 4,903 | shared_buffers-dominated, stable |
| valkey | 73.9 – 152.4 | tracks key census growth |
| audit worker / receiver | 19.0–20.5 / 7.9–19.8 | flat |
| k6 drivers (not SUT) | main→12.0 GB, meta→2.13 GB, fapi→0.91 GB, argon2→0.47 GB | load-generator memory growth; recorded for completeness |

## 10. Historical cliff window (≈5h10m elapsed)

| Elapsed | Bucket | anchor Δ/5min | pending | claim max | xmin lag | verdict |
|---|---|---|---|---|---|---|
| ~4h30m | 48–49 | 587k–590k | 21–52 | 29.6 ms | 1,813→12 | clean |
| ~5h00m | 54 | 589k | 160 | 29.6 ms | 15 | clean |
| ~5h10m | 55–56 | 588k–590k | 29–54 | 29.6 ms | 15,427→19 | **crossed, no degradation** |
| ~5h20m | 57–58 | 587k–590k | 68–70 | 29.6 ms | 156,829 transient | clean (xmin spike recovered) |
| ~5h40m | 62–63 | 589k | 50–60 | 29.6 ms | 13→8 | clean |
| ~6h00m | 66–67 | 589k→drain | 56→0 | 29.6 ms | 9,895→−1 | clean + drained |

**The historical ~5h10m exporter cliff did not reproduce.** The two transient xmin spikes (buckets 52, 58) coincided with a widened in-flight chain gap (≤56k) and single >60s transactions, all self-recovered — unlike the historical cliff which was a sustained stall.

## 11. Continuous 5-minute bucket evidence

78 samples (7 early-bucket part1 file 05:55–06:25Z without RSS + 71 main-file buckets 06:27–12:07Z; cadence continuous, one ~2 min phase shift at the collector restart, zero missing buckets in the load window). Columns: bucket / UTC / pending / oldest-pending-age s / cumulative claim calls / claim max ms / anchor / arrival Δ / xmin lag / xacts>60s / app MB / pg MB / valkey MB.

```
pt1 05:55–06:25 (7 buckets, no RSS column): pending 26–91, claim max ≤5.96ms, xmin ≤31, all-zero drops
bk  ts        pend age  claim_c   claimmax  anchor      arrΔ     xmin    o60 appMB  pgMB   vkMB
  1 06:27:04    29   0   122815     5.96   3,891,379        —      11   0 197.7 4424.2  73.9
  2 06:32:04    48   0   142187     5.96   4,480,326  588,947       6   0 197.7 4445.1  75.0
  3 06:37:04    39   0   161954     5.96   5,070,375  590,049       6   0 197.8 4462.1  76.1
  4 06:42:04    72   0   181750     5.96   5,659,119  588,744       4   0 197.7 4480.8  77.2
  5 06:47:04   107   0   200538     8.40   6,248,259  589,140      18   0 198.0 4497.0  78.3
  6 06:52:04    58   0   219810     8.40   6,836,444  588,185       4   0 198.0 4510.0  79.5
  7 06:57:04    29   0   239098     8.40   7,424,330  587,886       5   0 198.0 4522.1  80.6
  8 07:02:04    62   0   258158     8.40   8,013,892  589,562       7   0 197.9 4532.5  82.0
  9 07:07:04    58   0   276162     8.40   8,602,796  588,904       8   0 198.0 4541.5  83.1
 10 07:12:04    85   0   294626     8.40   9,191,900  589,104      13   0 198.0 4550.4  84.2
 11 07:17:04    34   0   312878     8.40   9,780,771  588,871       6   0 134.0 4557.0  85.3
 12 07:22:04    24   0   332247     8.40  10,369,746  588,975      12   0 198.0 4567.5  86.6
 13 07:27:04    66   0   351989     9.08  10,959,224  589,478      12   0 198.0 4574.6  87.8
 14 07:32:04    28   0   370392     9.08  11,547,850  588,626       4   0 198.2 4580.9  89.2
 15 07:37:04    21   0   388850     9.08  12,137,116  589,266       7   0 198.2 4585.3  90.2
 16 07:42:04    36   0   407389     9.08  12,726,261  589,145      10   0 147.2 4593.1  91.6
 17 07:47:04    36   0   426165     9.08  13,315,414  589,153      10   0 198.3 4597.7  92.6
 18 07:52:04    20   0   443978     9.08  13,901,288  585,874       7   0 134.3 4602.4  93.7
 19 07:57:04    75   0   460784     9.08  14,479,942  578,654      12   0 198.1 4606.0  99.1
 20 08:02:04    20   0   478283     9.08  15,062,831  582,889      21   0 197.0 4608.5  99.9
 21 08:07:04    99   0   490963     9.08  15,579,795  516,964      11   0 196.9 4613.2 100.3  << dip
 22 08:12:04    71   0   504102     9.08  16,110,451  530,656       8   0 196.5 4617.6 101.1  << dip
 23 08:17:04    50   0   520733     9.08  16,694,913  584,462   22,596   0 132.5 4647.9 102.2
 24 08:22:04    38   0   539626     9.08  17,284,171  589,258      10   0 196.4 4615.8 103.3
 25 08:27:04   111   0   557596     9.08  17,874,137  589,966   22,361   0 132.6 4654.4 104.5
 26 08:32:04    51   0   576087     9.08  18,461,850  587,713       8   0 196.5 4623.7 105.7
 27 08:37:04    32   0   594406     9.08  19,049,235  587,385      −1   0 196.5 4625.1 106.8
 28 08:42:04    53   0   613314     9.08  19,638,184  588,949      20   0 196.5 4626.3 107.9
 29 08:47:04    55   0   631517     9.08  20,227,784  589,600   21,193   0 152.5 4656.5 109.0
 30 08:52:04    42   0   649230     9.08  20,816,881  589,097   21,355   0 196.5 4661.6 110.1
 31 08:57:04   157   6   664552    14.59  21,400,483  583,602   19,800   0 204.3 4664.5 111.5
 32 09:02:04    24   0   680543    14.59  21,990,880  590,397      11   0 198.1 4630.0 112.5
 33 09:07:04    99   0   695079    14.59  22,581,372  590,492      11   0 198.1 4631.5 113.9
 34 09:12:04    83   0   710275    14.59  23,170,835  589,463      10   0 198.1 4632.8 115.0
 35 09:17:04    37   0   726776    14.59  23,760,318  589,483       2   0 198.2 4633.7 116.1
 36 09:22:04    29   0   743540    14.59  24,349,386  589,068       9   0 198.1 4634.2 117.1
 37 09:27:04    44   0   759666    14.59  24,937,590  588,204       8   0 198.2 4634.8 118.2
 38 09:32:04    71   0   775927    14.59  25,525,905  588,315      16   0 155.8 4635.2 119.7
 39 09:37:04    73   0   789619    14.59  26,114,549  588,644      10   0 198.1 4635.7 120.7
 40 09:42:04    34   0   802652    14.59  26,703,400  588,851       5   0 160.4 4640.3 121.7
 41 09:47:04    37   0   815751    14.59  27,292,182  588,782       4   0 198.1 4640.8 123.0
 42 09:52:04    27   0   832809    24.78  27,882,105  589,923      10   0 198.1 4641.8 124.2
 43 09:57:04    61   0   850066    24.78  28,470,526  588,421   18,884   0 198.1 4676.3 125.4
 44 10:02:04    29   0   864014    29.64  29,058,775  588,249       9   0 198.2 4642.6 126.5
 45 10:07:04    54   0   880659    29.64  29,647,872  589,097      10   0 198.1 4644.2 127.5
 46 10:12:04    63   0   895247    29.64  30,236,835  588,963      12   0 198.1 4644.8 129.0
 47 10:17:04    23   0   911851    29.64  30,826,987  590,152      12   0 134.2 4644.8 130.2
 48 10:22:04    52   0   928679    29.64  31,414,228  587,241   1,813   0 198.1 4645.0 131.1  cliff−40m
 49 10:27:04    21   0   942616    29.64  32,004,228  590,000      12   0 134.2 4645.6 132.6
 50 10:32:04    59   0   957567    29.64  32,592,896  588,668      22   0 172.3 4645.3 133.7
 51 10:37:04    56   0   973561    29.64  33,181,997  589,101      12   0 198.2 4645.7 134.8
 52 10:42:04    58   0   987557    29.64  33,770,749  588,752 158,487   1 163.3 4902.6 135.9  xmin spike
 53 10:47:04    52   0 1,003,727   29.64  34,358,633  587,884       9   0 134.2 4646.0 137.1
 54 10:52:04   160   0 1,019,433   29.64  34,947,743  589,110      15   0 198.2 4646.4 138.6
 55 10:57:04    29   0 1,035,762   29.64  35,536,157  588,414   15,427   0 134.3 4671.2 139.8
 56 11:02:04    54   0 1,049,936   29.64  36,126,321  590,164      19   0 198.1 4646.8 140.9  ≈cliff
 57 11:07:04    68   0 1,065,973   29.64  36,716,236  589,915       7   0 198.1 4646.9 141.9
 58 11:12:04    70   0 1,082,284   29.64  37,302,754  586,518 156,829   1 134.2 4885.8 143.0  xmin spike
 59 11:17:04    37   0 1,098,337   29.64  37,892,313  589,559      14   0 198.1 4647.7 144.2
 60 11:22:04    29   0 1,115,445   29.64  38,479,840  587,527      10   0 198.2 4648.1 145.2
 61 11:27:04    36   0 1,133,883   29.64  39,069,800  589,960       4   0 198.1 4652.1 146.7
 62 11:32:04    60   0 1,152,758   29.64  39,659,137  589,337      13   0 160.4 4652.5 147.8
 63 11:37:04    50   0 1,171,159   29.64  40,248,367  589,230       8   0 198.2 4652.2 148.9
 64 11:42:04    56   0 1,190,191   29.64  40,836,212  587,845   13,705   0 198.1 4683.3 150.1
 65 11:47:04    32   0 1,208,438   29.64  41,425,688  589,476       6   0 198.2 4652.8 151.2
 66 11:52:04    56   0 1,225,199   29.64  42,014,979  589,291   9,895   0 150.2 4774.8 152.4
 67 11:57:04     0  −1 1,231,964   29.64  42,213,228  198,249      −1   0 134.2 4499.1 152.3  drained
 68 12:02:04     0  −1 1,231,964   29.64  42,213,228        0      −1   0 134.3 4499.7 121.1  post
 69 12:07:04     0  −1 1,231,964   29.64  42,213,228        0      −1   0 134.2 4500.4 100.2  post
```

Bucket-sampled drop counters (misrouted / required / telemetry): **0 / 0 / 0 in every bucket**. Worker warn/err: 0 in every bucket.

## 12. Sidecars

| Sidecar | Iterations | HTTP reqs | errors | drops | note |
|---|---|---|---|---|---|
| Argon2 `oidc_cold_login_refresh` (8/s) | 171,028 | 1,026,168 | **0 (incl. 0×503)** | 173 | login p50 115.6ms (crypto-bound); status `target_miss` 47.95rps |
| FAPI `fapi2_logged_in_high_security` (30/s) | 641,689 | 3,208,445 | **0** | 312 | p95 10.36ms |
| Metadata/JWKS (200/s×2 steps) | 4,280,000 | 8,560,000 | **0** | 0 | `passed` |

All summaries persisted under `evidence/statemin-formal-6h-r1/{main,argon2,fapi,meta}/`.

## 13. Verdict matrix

| Gate | Result | Evidence |
|---|---|---|
| main unexpected HTTP errors = 0 | ✓ | error_rate 0.0, 56.2M reqs |
| business errors = 0 | ✓ | empty error_breakdown, all steps |
| **main drops ≤0.1%** | **✗ 0.4122%** | §3 — one ~15min sag, deficit≈drops exact |
| no sustained latency deterioration | ✓ | p95 9.55ms overall; post-dip rate = pre-dip rate |
| no OOM/crash/restart | ✓ | OOMKilled=false, RestartCount=0 all |
| RSS no sustained one-way growth | ✓ | sawtooth 132–204MB, terminal 134MB |
| misrouted_required / dropped_required | ✓ 0 / 0 | buckets + log census |
| receiver dup / reject | ✓ 0 / 0 | receiver state |
| chain discontinuity | ✓ 0 | health sampler 361 samples, end gap 0 |
| pending / oldest-pending drift | ✓ none | max 160 / 6s transient, ends 0 |
| no minute-scale claim cliff | ✓ | max 29.6ms / 1.23M calls |
| post-stop events/outbox/chain = 0/0/0 | ✓ | drained by 11:57Z |
| DB anchor == receiver head | ✓ | 42,213,228 both |
| Required reconciliation | ✓ | 6,644,524 intents = families 1:1 = receiver |
| 5h10m cliff not reproduced | ✓ | §10 |
| WAL <12 KB/op | ✓ | 7.79 KB/op |
| FAPI/Argon2/meta real evidence | ✓ | §12, all error-free with real flow counts |
| **FORMAL_SOAK** | **FAIL** | drops gate |

## 14. Remaining evidence gaps

1. **Dip trigger unresolved to statement class** — needs 1s wait_event/lock/checkpoint sampling (targeted test §3); the collector samples at 10s and does not capture wait events.
2. `started` iterations not separately emitted by the runner (completed + interrupted=0 are).
3. Claim p50/p95/p99 unavailable — `pg_stat_statements` exposes mean/max only.
4. Host CPU/steal and per-checkpoint timing not captured (docker stats returned empty cpu on this host; `log_checkpoints` off) — prevents ruling CPU contention or a specific checkpoint in/out for the dip.
5. `DEPLOYMENT_WORM_VERIFICATION` not exercised — receiver is a test double; no external WORM claim made.
6. `oauth:session` residual 171,542 keys expire on their own TTLs (~≤8h) — observed TTL distribution, no manual cleanup performed.

## 15. Failure characterization vs. the previous failed soak

The prior failed run (`2026-09-20-final-soak-6h-r1`, TEST_SOURCE_SHA `23762421`) failed on three gates: drops 0.219% (cancel-intervention recovery window), argon2 5×503, and 96,389 Required-class events lost via best-effort queue. This run fixed all three: drops now stem from an organic (non-intervention) throughput sag; argon2 had zero 503s; Required loss is zero with exact 1:1 reconciliation, and telemetry loss is also zero. The remaining defect class is **transient DB-side latency bursts starve the connection pool at near-capacity arrival** — the next targeted test in §3 is scoped to attribute it precisely before any further full soak.
