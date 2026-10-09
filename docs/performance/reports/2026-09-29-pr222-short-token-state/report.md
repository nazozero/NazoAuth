# PR #222 current-source one-hour short acceptance

Measurement completion: **COMPLETE**. Required-point acceptance: **FAIL**.
Original task start: `2026-09-29T08:32:42Z`; load cutoff: `09:28:42Z`; delivery deadline: `09:32:42Z`.
Source `3b6d8d3cfe35f79a3ab896d53a3aa76c443e7599`; harness `3b6d8d3cfe35f79a3ab896d53a3aa76c443e7599`. Report commit is recorded separately in the PR comment.

Logical success rates and complete-operation latency use the formal measurement cohort. HTTP req/s is the native whole-scenario rate, including warmup; it is not logical ops/s. E/D/R/U = unexpected operations / dropped arrivals / expected rejection / unfinished operations. Local no-request exits and preparation failures remain separate in summary.json. N/A means unavailable, never zero.

| Mode | App CPUs | Scenario | Offered ops/s | Success ops/s | HTTP req/s | Complete P50/P95/P99 ms | E/D/R/U | Valid measured window s | Verdict |
|---|---:|---|---:|---:|---:|---|---|---:|---|
| single | 1 | cap_client_credentials | 1000 | 1000 | 997.907 | 5/12/21 | 0/0/0/0 | 60 | PASS |
| multi | 16 | cap_client_credentials | 4000 | 4000 | 3999.728 | 6/14/28 | 0/0/0/0 | 60 | PASS |
| single | 1 | cap_mixed | 400 | 400 | 575.81 | 6/37/77 | 0/0/0/0 | 60 | FAIL |
| multi | 16 | cap_mixed | 1600 | 1599.967 | 2339.255 | 6/30/63 | 0/0/2/0 | 60 | FAIL |
| single | 1 | cap_authorization_code | 200 | 200 | 799.889 | 17/29/40 | 0/0/0/0 | 60 | PASS |
| multi | 16 | cap_authorization_code | 800 | 714.05 | 2924.432 | 143/1802/2060 | 0/5157/0/0 | 60 | FAIL |
| single | 1 | cap_refresh_token | 500 | 500 | 501.894 | 7/13/20 | 0/0/0/0 | 60 | PASS |
| multi | 16 | cap_refresh_token | 2000 | 2000.017 | 2045.873 | 9/18/33 | 0/0/0/0 | 60 | PASS |
| multi | 16 | cap_mixed mature | 800 | 799.902 | 1166.708 | 6/29/52 | 0/0/56/0 | 570 | FAIL |

| Mixed point | Sidecar | Success ops/s | Complete P50/P95/P99 ms | Unexpected / drops / unfinished | Sidecar formal s | Verdict |
|---|---|---:|---|---|---:|---|
| s2-single-1790671460 | argon2 | 1 | 290/354.1/417.18 | 0/0/0 | 135 | PASS |
| s2-single-1790671460 | meta | 13 | 1/3.3/12 | 0/0/0 | 135 | PASS |
| s2-single-1790671460 | fapi | 2 | 35/140.1/224.55 | 0/0/0 | 135 | FAIL |
| s2-single-1790671460 | refresh | 38 | 9/40/73.71 | 0/0/0 | 135 | PASS |
| s3-multi-1790671697 | argon2 | 8 | 178/206.05/253.84 | 0/0/0 | 135 | PASS |
| s3-multi-1790671697 | meta | 200 | 1/1/1 | 0/0/0 | 135 | PASS |
| s3-multi-1790671697 | fapi | 30 | 41/63/105 | 0/0/0 | 135 | PASS |
| s3-multi-1790671697 | refresh | 598.993 | 8/16/35 | 0/137/0 | 135 | FAIL |
| s8-multi-1790672562 | argon2 | 7.997 | 171/195/301.31 | 0/2/0 | 645 | PASS |
| s8-multi-1790672562 | meta | 200 | 1/1/1 | 0/0/0 | 645 | PASS |
| s8-multi-1790672562 | fapi | 30 | 39/59/156 | 0/0/0 | 645 | PASS |
| s8-multi-1790672562 | refresh | 597.682 | 8/14/38.96 | 0/1495/0 | 645 | FAIL |

| Point | Fresh / legacy rows | Issuance rows / cumulative inserts | Subject bindings | WAL generated MiB | WAL written MiB | Generated B/success | Pool wait ms/acquire | Audit |
|---|---|---|---:|---:|---:|---:|---:|---|
| s0-single-1790671160 | 0/0 | 0/0 | 0 | 97.538 | 557.994 | 1704.594 | 0.001 | PASS |
| s1-multi-1790671303 | 0/0 | 0/0 | 0 | 400.926 | 1261.487 | 1751.673 | 0.197 | PASS |
| s2-single-1790671460 | 0/0 | 7568/7568 | 0 | 66.107 | 343.943 | 2888.251 | 0.001 | PASS |
| s3-multi-1790671697 | 0/0 | 35096/35096 | 0 | 367.551 | 1181.295 | 4014.722 | 0.285 | PASS |
| s4-single-1790671935 | 0/0 | 15000/15000 | 0 | 104.762 | 566.741 | 9154.282 | 0.001 | PASS |
| s5-multi-1790672093 | 0/0 | 54844/54844 | 0 | 379.979 | 1089.482 | 9299.937 | 45.145 | PASS |
| s6-single-1790672249 | 0/0 | 64/64 | 0 | 96.493 | 452.699 | 3372.689 | 0.001 | PASS |
| s7-multi-1790672403 | 0/0 | 992/992 | 0 | 395.691 | 1192.738 | 3457.569 | 0.075 | PASS |
| s8-multi-1790672562 | 0/0 | 56692/101872 | 0 | 2500.931 | 8489.015 | 5751.619 | 0.174 | PASS |

WAL generation (`pg_stat_wal`) and WAL write bytes (`pg_stat_io`, WAL object) are separate counters. Costs use the existing interpolated sampler window and include sidecars and background work per main success. Neither physical-media bytes nor SQL-level attribution is claimed. Legitimate SingleUse receipts in non-client-credentials paths are retained.

| Point | Component | Mean CPU cores | Mean / peak summed process RSS MiB | Samples |
|---|---|---:|---|---:|
| s0-single-1790671160 | app | 0.654 | 35.72/35.78 | 12 |
| s0-single-1790671160 | postgres | 1.981 | 1347.67/1511.35 | 12 |
| s0-single-1790671160 | sis-load-s0-single-1790671160 | 0.486 | 433.72/447.3 | 12 |
| s0-single-1790671160 | valkey | 0.03 | 10.9/11.06 | 12 |
| s1-multi-1790671303 | app | 3.943 | 81.03/81.07 | 11 |
| s1-multi-1790671303 | postgres | 7.398 | 2908.75/3730.34 | 11 |
| s1-multi-1790671303 | sis-load-s1-multi-1790671303 | 1.991 | 4983.89/5145.35 | 11 |
| s1-multi-1790671303 | valkey | 0.072 | 11.5/11.57 | 11 |
| s2-single-1790671460 | app | 0.621 | 59.62/100.3 | 11 |
| s2-single-1790671460 | postgres | 1.312 | 2033.34/2201.85 | 11 |
| s2-single-1790671460 | sis-load-s2-single-1790671460 | 0.403 | 464.13/475.2 | 11 |
| s2-single-1790671460 | sis-side-argon2-s2-single-1790671460 | 0.012 | 467.18/480.66 | 11 |
| s2-single-1790671460 | sis-side-fapi-s2-single-1790671460 | 0.027 | 403.74/412.73 | 11 |
| s2-single-1790671460 | sis-side-meta-s2-single-1790671460 | 0.024 | 381.55/391.87 | 11 |
| s2-single-1790671460 | sis-side-refresh-s2-single-1790671460 | 0.047 | 443.71/451.37 | 11 |
| s2-single-1790671460 | valkey | 0.04 | 13.82/14.56 | 11 |
| s3-multi-1790671697 | app | 5.07 | 169.38/231.51 | 11 |
| s3-multi-1790671697 | postgres | 6.737 | 5108.06/5270.48 | 11 |
| s3-multi-1790671697 | sis-load-s3-multi-1790671697 | 1.482 | 5062.59/5099.17 | 11 |
| s3-multi-1790671697 | sis-side-argon2-s3-multi-1790671697 | 0.047 | 409.66/417.52 | 11 |
| s3-multi-1790671697 | sis-side-fapi-s3-multi-1790671697 | 0.286 | 515.63/524.63 | 11 |
| s3-multi-1790671697 | sis-side-meta-s3-multi-1790671697 | 0.174 | 460.68/473.67 | 11 |
| s3-multi-1790671697 | sis-side-refresh-s3-multi-1790671697 | 0.406 | 678.36/691.59 | 11 |
| s3-multi-1790671697 | valkey | 0.115 | 28.27/33.33 | 11 |
| s4-single-1790671935 | app | 0.555 | 32.3/32.37 | 12 |
| s4-single-1790671935 | postgres | 1.479 | 1735.5/2055.9 | 12 |
| s4-single-1790671935 | sis-load-s4-single-1790671935 | 0.613 | 430.8/445.7 | 12 |
| s4-single-1790671935 | valkey | 0.074 | 14.39/16.65 | 12 |
| s5-multi-1790672093 | app | 2.96 | 98.75/108.51 | 12 |
| s5-multi-1790672093 | postgres | 12.267 | 4229.6/5062.27 | 12 |
| s5-multi-1790672093 | sis-load-s5-multi-1790672093 | 2.179 | 4890.33/5097.98 | 12 |
| s5-multi-1790672093 | valkey | 0.217 | 24.15/30.37 | 12 |
| s6-single-1790672249 | app | 0.632 | 34.83/34.87 | 12 |
| s6-single-1790672249 | postgres | 1.847 | 1587.04/1863.85 | 12 |
| s6-single-1790672249 | sis-load-s6-single-1790672249 | 0.328 | 432.81/442.95 | 12 |
| s6-single-1790672249 | valkey | 0.021 | 11.1/11.2 | 12 |
| s7-multi-1790672403 | app | 3.838 | 106.87/106.93 | 11 |
| s7-multi-1790672403 | postgres | 7.536 | 4118.12/5155.7 | 11 |
| s7-multi-1790672403 | sis-load-s7-multi-1790672403 | 1.134 | 4741.93/5097.3 | 11 |
| s7-multi-1790672403 | valkey | 0.049 | 11.95/11.98 | 11 |
| s8-multi-1790672562 | app | 3.753 | 147.15/218.83 | 103 |
| s8-multi-1790672562 | postgres | 4.633 | 5074.84/5489.99 | 103 |
| s8-multi-1790672562 | sis-load-s8-multi-1790672562 | 0.802 | 5227.14/5373.82 | 103 |
| s8-multi-1790672562 | sis-side-argon2-s8-multi-1790672562 | 0.045 | 412.48/425.67 | 103 |
| s8-multi-1790672562 | sis-side-fapi-s8-multi-1790672562 | 0.273 | 527.45/551.82 | 103 |
| s8-multi-1790672562 | sis-side-meta-s8-multi-1790672562 | 0.17 | 484.18/518.56 | 103 |
| s8-multi-1790672562 | sis-side-refresh-s8-multi-1790672562 | 0.393 | 729.64/786.4 | 103 |
| s8-multi-1790672562 | valkey | 0.087 | 48.38/57.71 | 103 |
| s8-multi-1790672562 | audit-receiver | 0.054 | 9.2/9.48 | 108 |
| s8-multi-1790672562 | audit-worker | 0.092 | 20.65/20.74 | 108 |

Process CPU jiffy deltas and summed process RSS. Nested cgroup counters were not independently scoped; no component physical-memory claim. PostgreSQL RSS counts shared pages repeatedly.

**Resource evidence coverage: PARTIAL.** Earlier short-point audit receiver/worker process CPU/RSS is unavailable (INVALID for that resource claim). Mature-point audit resource evidence supplements the original sampler by reusing its existing sample() function, with collector hashes retained. Independently scoped physical-memory cost is not established. Available process CPU/RSS observations and WAL/pool costs remain evidence for their recorded scope; missing values are not zero.

Confirmation and limitations:

- Mature mixed point: **FAIL**. Maintenance **PASS** over 210 mature seconds and 101 samples. Oldest expired receipt age peaked at 58.203 seconds against the retained 120-second SLO; retention remains 360 seconds. This establishes the sampled maintenance-age result, not indefinite stability.
- Confirmation journal: 1099770 reconciled events, 1017578121 bytes; archived file SHA-256 `d11b64fd16c9f6f422f77f81cbc98d863f8cdcb6b8af6bea26cc396f2d3a2359`, source hash match `True`. Drain, checkpoint/hash alignment and contiguous sequence checks are in summary.json.
- s2-single-1790671460: **FAIL**; main path **PASS**; success 400/400 offered ops/s, complete P95/P99 37/77 ms, formal drops 0/24000. Non-Argon2 gates retain 99.5% successful arrivals, at most 0.1% drops, P95 <=100 ms and P99 <=250 ms. Detailed health and sidecar verdicts remain in summary.json.
- s2-single-1790671460 sidecar fapi: **FAIL**; success 2 ops/s; complete P95/P99 140.1/224.55 ms; formal drops 0/270. Generator-local resource-failure evidence, when evaluated, is `not triggered`; the precise bottleneck is not established.
- s3-multi-1790671697: **FAIL**; main path **PASS**; success 1599.967/1600 offered ops/s, complete P95/P99 30/63 ms, formal drops 0/96000. Non-Argon2 gates retain 99.5% successful arrivals, at most 0.1% drops, P95 <=100 ms and P99 <=250 ms. Detailed health and sidecar verdicts remain in summary.json.
- s3-multi-1790671697 sidecar refresh: **FAIL**; success 598.993 ops/s; complete P95/P99 16/35 ms; formal drops 137/81001. Generator-local resource-failure evidence, when evaluated, is `absent`; the precise bottleneck is not established.
- s5-multi-1790672093: **FAIL**; main path **FAIL**; success 714.05/800 offered ops/s, complete P95/P99 1802/2060 ms, formal drops 5157/48000. Non-Argon2 gates retain 99.5% successful arrivals, at most 0.1% drops, P95 <=100 ms and P99 <=250 ms. Detailed health and sidecar verdicts remain in summary.json.
- s8-multi-1790672562: **FAIL**; main path **PASS**; success 799.902/800 offered ops/s, complete P95/P99 29/52 ms, formal drops 0/456000. Non-Argon2 gates retain 99.5% successful arrivals, at most 0.1% drops, P95 <=100 ms and P99 <=250 ms. Detailed health and sidecar verdicts remain in summary.json.
- s8-multi-1790672562 sidecar refresh: **FAIL**; success 597.682 ops/s; complete P95/P99 14/38.96 ms; formal drops 1495/387000. Generator-local resource-failure evidence, when evaluated, is `absent`; the precise bottleneck is not established.

PASS applies only to the recorded point. These short tests do not establish maximum capacity or indefinite stability. No improvement percentage is computed against historical results. The accepted historical capacity matrix is unchanged.

Identity, frozen requests, runtime CPU sets, script hashes, durability settings, OOM/restart observations, generator/sidecar gates and audit reconciliation are retained in manifest.json and summary.json. Private native evidence is retained outside test containers with SHA-256 inventory and archive identity in evidence-sha256.json.

Executed on CNB from an ordinary checkout:

```sh
git checkout 3b6d8d3cfe35f79a3ab896d53a3aa76c443e7599
docker compose -f docker-compose.perf.yml -p nazoauth-perf build --build-arg SOURCE_SHA=3b6d8d3cfe35f79a3ab896d53a3aa76c443e7599 nazoauth perf keyset audit-receiver
TASK_STARTED_AT=2026-09-29T08:32:42Z
python3 perf/tools/short_baseline.py --started-at "$TASK_STARTED_AT" --cpu-budget 64 \
  --output "$PWD/perf-results/short-token-state-20260929T083918Z"
```

A fresh reproduction uses its own original UTC start and a new output directory. The recorded start above is never reset for retries. CI of the measured source and CI of the report commit are separate; report-commit CI status is recorded at publication in the PR comment.
