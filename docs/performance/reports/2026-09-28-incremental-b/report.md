# Current-B incremental performance acceptance — 2026-09-28

Status: **INCOMPLETE**. 10/20 mode/scenario rows have reviewed service upper endpoints. All twenty retain real passing observations. Missing uppers remain lower bounds; short candidates still need 180-second verification and wide brackets still need refinement. The results below replace the current baseline, but do not claim completion of the requested full acceptance.

The six-hour execution started at 09:58:28 UTC, with a hard stop at 15:58:28 UTC (23:58:28 Beijing). The remaining fixed verification was bounded to preserve final publication and CI time. The earlier exploration reserve was overrun while repairing invalid measurement and obtaining a new complete mixed journal. This is an execution limitation, not evidence of capacity. [Checkpoint history](checkpoint-history.md) records the independent commits and intermediate results; [original observations](../2026-09-28-current-b/report.md) are historical and superseded.

## Identity, configuration and measurement

Application source is `ac266e7a93749694022efd1aeea6ed4d316fbbcc`, image `5f62a3a2247e609d72ee03de1bc0d330873d5742b1f94cd5ec144baa69f2f71d`, binary `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b`. Production code is unchanged, so the restored application image was reused. Required ancestor `04146234c578e61797aacee7ef7c4687b75653a1` is included. The offline evaluator was reviewed at `efe3189b1dd746c8075ecc5923329c93e8e31421`; its exact source file hashes are retained in the separate reassessment.

Both deployments expose 64 logical CPUs and a 128 GiB container memory limit. The original deployment allocated app single 128 or multi 128–143, PG 144–159, Valkey 160 and generators 161–191. The replacement deployment dynamically allocated app single 24 or multi 24–39, PG 40–55, Valkey 56 and generators 57–79,184–191. Actual per-point affinity is verified and retained. Only deployment-visible resources were investigated. Component allocations are disjoint; all auxiliary roles share the stated generator set. Each interval uses one deployment and one exact frozen recipe; no original/new result or altered VU/pool/user configuration is joined into a boundary.

PostgreSQL 18.6 keeps fsync, synchronous_commit and full_page_writes enabled, normal autovacuum, max WAL 8 GB and five-minute checkpoints. Pool size is 32 in single mode and 64 in the new multi profiles; per-row configurations override any earlier defaults. The stored login fixture retains Argon2 m=65536 KiB/t=3/p=4, with the unchanged eight-permit/100 ms admission policy. Audit, migration, protocol and source-IP limits remain enabled. VUs, users and stream workers are listed per recipe; sidecar users remain independent of sidecar VU overrides.

The existing controller, scenarios and gates were used. Main and sidecar logical operations use exact native measurement cohorts and complete-operation histograms; HTTP rate and HTTP diagnostic quantiles are separate populations. P99 values are never averaged. Standard non-cold gates retain >=99.5% successful offered operations, <=0.1% drops, zero unexpected outcomes, P95/P99 <=100/250 ms, runtime health and durable audit. Cold login and metadata keep their existing distinct gates. A failed/invalid observer, missing acceptance evidence or generator-only failure cannot become a service upper. Short windows do not establish production long-term capacity.

Runner identities are frozen per row: legacy `64b27274...`, native cohort `c3ce0ca4...`, filtered `e5a7c22b...`, sparse-dispatch overlay `ba139190...`, and periodic-native-flush overlay `779d48cb...`; full IDs and component hashes are in the structured recipes. The last overlay contains controller files from `ec638ce7`, k6 v2.2.0 upstream `00a9a1b7f552d6bb4337278b10ae25aac0f4e666`, the `dfed760e` patch and native binary `dff9988f2f4e2dea89c140467632b652574fc31a03323aab4e687f5d1ad98384`. It is a composite image, not a pristine application rebuild.

## Single logical CPU

| Scenario | Deployment | App CPUs | PASS L | Service FAIL U | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window L/U s | Conclusion |
|---|---|---:|---:|---:|---:|---:|---|---|---|---|
| `cap_mixed` | original-container | 1 | 600 | 650 | 600 | 869.944 | 4/45/103 | 0/0/0/0 | 660/180 | [600, 650) observed |
| `cap_client_credentials` | original-container | 1 | 1375 | 1500 | 1375.006 | 1375.011 | 5/24/46 | 0/0/0/0 | 180/180 | [1375, 1500) observed |
| `cap_authorization_code` | original-container | 1 | 325 | 350 | 325 | 1299.989 | 19/50/158 | 0/0/0/0 | 180/180 | [325, 350) observed |
| `cap_refresh_token` | original-container | 1 | 750 | 812 | 749.994 | 750 | 7/34/74 | 0/0/0/0 | 180/180 | [750, 812) observed |
| `fapi2_logged_in_high_security` | original-container | 1 | 20 | not established | 20 | 100 | 22/31/43.01 | 0/0/0/0 | 180/N/A | at least 20/s |
| `cap_introspect` | original-container | 1 | 500 | not established | 500 | 500 | 1/3/11 | 0/0/0/0 | 180/N/A | at least 500/s |
| `cap_revoke` | original-container | 1 | 60 | not established | 60 | 300 | 16/24/38 | 0/0/0/0 | 180/N/A | at least 60/s |
| `mtls_client_credentials` | original-container | 1 | 250 | not established | 250 | 250 | 4/6/12 | 0/0/0/0 | 180/N/A | at least 250/s |
| `par_signed_request_object` | original-container | 1 | 150 | not established | 150 | 150 | 3/5/11 | 0/0/0/0 | 180/N/A | at least 150/s |
| `oidc_cold_login_refresh` | original-container | 1 | 1 | not established | 1 | 6 | 132/142/153.21 | 0/0/0/0 | 180/N/A | at least 1/s |

## Sixteen logical CPUs

| Scenario | Deployment | App CPUs | PASS L | Service FAIL U | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window L/U s | Conclusion |
|---|---|---:|---:|---:|---:|---:|---|---|---|---|
| `cap_mixed` | new-container | 16 | 2349 | 2900 | 2349 | 3404.917 | 4/20/29 | 0/0/0/0 | 660/660 | [2349, 2900) observed |
| `cap_client_credentials` | new-container | 16 | 6000 | 6500 | 6000.022 | 6000.067 | 4/11/29 | 0/0/0/0 | 180/180 | [6000, 6500) observed |
| `cap_authorization_code` | new-container | 16 | 900 | 1000 | 900 | 3599.553 | 63/92/109 | 0/0/0/0 | 180/180 | [900, 1000) observed |
| `cap_refresh_token` | new-container | 16 | 2624 | 2916 | 2624.006 | 2623.994 | 7/13/26 | 0/0/0/0 | 180/180 | [2624, 2916) observed |
| `fapi2_logged_in_high_security` | original-container | 16 | 320 | not established | 320 | 1600.017 | 24/32/42 | 0/0/0/0 | 180/N/A | at least 320/s |
| `cap_introspect` | original-container | 16 | 16000 | 17000 | 15997.911 | 15997.838 | 1/3/15 | 0/376/0/0 | 180/180 | [16000, 17000) observed |
| `cap_revoke` | original-container | 16 | 480 | not established | 480 | 2400.034 | 18/33/42 | 0/0/0/0 | 180/N/A | at least 480/s |
| `mtls_client_credentials` | original-container | 16 | 4000 | not established | 3998.417 | 3998.553 | 4/9/20 | 0/285/0/0 | 180/N/A | at least 4000/s |
| `par_signed_request_object` | original-container | 16 | 2400 | not established | 2400 | 2399.989 | 3/4/5 | 0/0/0/0 | 180/N/A | at least 2400/s |
| `oidc_cold_login_refresh` | original-container | 16 | 52 | 56 | 52 | 312 | 159/179/187 | 0/0/0/0 | 180/180 | [52, 56) observed |

## Upper endpoints

| Scenario / mode | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window s | Failure evidence |
|---|---:|---:|---|---|---:|---|
| `cap_mixed` / single | 644.15 | 938.397 | 10/130/233 | 0/1053/0/0 | 180 | main complete-operation P95 130ms exceeds 100ms; FAPI complete-operation P95/P99 181.2/273.82ms exceeds 100/250ms; refresh complete-operation P95 131ms exceeds 100ms; main dropped fraction 0.9% exceeds 0.1% |
| `cap_client_credentials` / single | 1491.167 | 1491.268 | 11/339/395 | 0/1590/0/0 | 180 | complete-operation P95/P99 339/395ms exceeds 100/250ms; measurement dropped fraction 0.5889% exceeds 0.1% |
| `cap_authorization_code` / single | 342.806 | 1370.978 | 584/809/881 | 0/1295/0/0 | 180 | complete-operation P95/P99 809/881 ms exceeds 100/250 ms; 1295 measurement drops (2.0556%) exceeds 0.1% |
| `cap_refresh_token` / single | 808.95 | 808.447 | 54/311/341 | 0/549/0/0 | 180 | complete-operation P95/P99 311/341 ms exceeds 100/250 ms; 549 measurement drops (0.3756%) exceeds 0.1% |
| `cap_mixed` / multi | 2900.006 | 4208.812 | 7/44/78 | 0/0/0/0 | 660 | FAPI sidecar full-operation P95 108 ms exceeds 100 ms; its 22050 offered operations all finish successfully with no drops. |
| `cap_client_credentials` / multi | 6497.539 | 6497.615 | 5/39/331.44 | 0/444/0/0 | 180 | Full-operation P99 331.44 ms exceeds 250 ms; delivery/drop/error/unfinished gates pass. |
| `cap_authorization_code` / multi | 1000 | 4002.492 | 57/156/311 | 0/0/0/0 | 180 | Complete-operation P95/P99 156/311 ms exceed 100/250 ms |
| `cap_refresh_token` / multi | 1728.389 | 1728.274 | 1196/1356/1517 | 0/213769/0/0 | 180 | Full-operation P95/P99 1356/1517 ms exceeds 100/250 ms; 40.7273% offered arrivals drop after VUs become occupied by slow responses. |
| `cap_introspect` / multi | 16707.406 | 16989.581 | 1/4/24 | 50802/1892/0/0 | 180 | 50802 unexpected logical outcomes; retained HTTP429 temporarily_unavailable responses demonstrate the unchanged source-IP management admission limit |
| `oidc_cold_login_refresh` / multi | 55.933 | 335.849 | 172/239/263 | 12/0/0/0 | 180 | 12 unexpected complete-operation outcomes; retained failed HTTP points are POST /auth/login 503 |


## Why the upper endpoints are service failures

- `single/cap_mixed`: All FAPI and refresh sidecar arrivals complete with zero drops and miss their unchanged latency gates. A separate one-factor main-VU 64-to-128 control at the same 650/s reduces main drops to 0.066% and delivers 99.934% of offered operations, yet main P95 remains 130ms and FAPI/refresh P95 remain 309/135ms. This rules out insufficient main VUs as the cause of the latency failure; that control is not mixed into the frozen 64-VU interval. The original 600/s, 660-second confirmation has verified effective recipe equivalence and is retained without modifying its raw evidence.
- `single/cap_client_credentials`: A one-factor VU 512-to-1024 control at the same 1500/s does not restore latency: complete-operation P95/P99 become 701/760 ms. Native whole-point HTTP waiting P95 is 335.189 ms at 512 VU and 697.629 ms at 1024 VU, while sending, receiving and blocked P95 are below 0.05 ms. These HTTP diagnostics do not replace full-operation cohort gates. Generator CPU is 0.797/31, analyzer lag 0.257 s and mean pool wait 16.985 ms at U (60.062 ms in the 1024 control), identifying server response/queue latency rather than injector compute or transport time. Under the 250-ms P99 SLO, 1500/s needs 375 busy VUs; the frozen 512-VU profile has headroom. The separate 1024 profile also fails at 1375/s and is not mixed into this 512-VU interval. No particular SQL or intrinsic hardware ceiling is claimed.
- `single/cap_authorization_code`: A one-factor 256-to-512 VU control at the same 350/s, users 64 and pool 32 delivers and completes all 63000 offered operations with no drops or warnings but still fails full-operation P95/P99 at 394/497 ms. This excludes insufficient VUs as the independent latency failure. Its generator CPU is 1.139/31, observer lag 0.284 s and mean pool wait 2.617 ms; no audit/health evidence fails. At the frozen 256-VU upper, app CPU is 0.978/1, generator 1.251/31, pool wait 28.991 ms and lag 0.266 s. The separate 512-VU control is not used as an interval bound; no specific SQL or continuously saturated component is claimed.
- `single/cap_refresh_token`: A one-factor 256-to-512 VU control holds users 64, pool 32 and images constant and does not restore the SLO: full-operation P95/P99 771/813 ms. The control still has a VU warning and 9.6654% drops, so it does not establish full target delivery. Independent response/queue evidence supports the service latency failure: native whole-point HTTP waiting P95 is 320.549 ms at the original upper and 769.863 ms in the control; send/receive/blocked P95 remain below 0.062 ms. Pool acquisition wait rises from 15.396 to 128.371 ms while generator CPU stays 0.485/31 and 0.490/31 and observer lag 0.259/0.262 s. App averages 0.958/1 and 0.927/1 CPU. At the unchanged 250-ms P99 SLO, 812/s requires 203 busy VUs, below 256. Warning/drop counts alone are not the attribution. The separate control is not an interval bound; no particular SQL is claimed.
- `multi/cap_mixed`: Independent full-business SLO failure with complete FAPI offered-load delivery, no VU warnings and observer lag 0.327s. The main flow also delivers all 1914004 operations. CPU/pool evidence and whole-point native HTTP waiting support service response costs; no SQL or physical device cause is proved. The bracket remains wider than 12.5% and needs narrowing. A closer 2610/s candidate fails only delivery/drop gates and is not used as a service upper.
- `multi/cap_client_credentials`: A one-factor 2048-to-4096 VU control holds users256/pool64/8 workers/native image fixed at6000/s: all1080004 offered operations finish with zero drops, P95/P99 11/29ms, disproving the old drop-only service upper. The frozen4096-VU upper at6500/s completes all1169557 started operations, has0unexpected and0unfinished, and444/1170001 drops (0.03795%, below0.1%). Its independent complete-operation P99 fails. Generator4.482/31CPUs, lag0.763s, pool wait2.221ms. A VU warning remains, but it is not the upper evidence; no particular SQL/CPU ceiling is claimed.
- `multi/cap_authorization_code`: All 180000 scheduled operations start and finish successfully with no errors, dropped or unfinished operations; no VU warning. Generator uses 3.476 of 31 cores, observer lag 0.999s. Full-operation latency fails with complete offered load delivery.
- `multi/cap_refresh_token`: The same 2048-VU/users256/pool64/4-worker recipe delivers all472321 operations at2624/s, full P95/P99 13/26ms, zero errors/drops/unfinished and no VU warning. At2916/s, complete-operation latency fails independently of the drop count. Mean measured server pool acquisition wait is229.24ms; generator uses1.527/31CPUs, app3.731/16 and PG5.713/16, observer lag0.334s, with no reader/parse failure and intact health/audit. Under the250ms SLO,2916/s requires729busyVUs, below2048. The warning reflects2048 VUs occupied by roughly1.2s responses; it does not by itself define U. This establishes a configured service response/queue boundary, not a specific SQL or intrinsic CPU ceiling. The3240/s control independently fails full P95/P99 1275/1364ms with mean pool wait57.213ms and generator2.081/31CPUs.
- `multi/cap_introspect`: Both points have valid 180-second windows and full cohorts. At 17000/s, 99.938% of offered arrivals start, every started operation completes, and 0.0618% drops satisfy the 0.1% delivery gate; complete-operation P95/P99 are 4/24 ms. Failure persists independently as 50802 unexpected outcomes and a successful-operation deficit. Bounded whole-point logs retain 40960 HTTP 429 samples, not an exact measurement status count. The unchanged policy is 1000000 management requests per source IP per 60 seconds. Generator CPU 8.120/31, app 4.579/16, PG 8.233/16, pool wait 0.090 ms and analyzer lag 3.345 s with zero parse/reader failures exclude generator delivery and measurement failures. This is the configured one-source-IP service admission boundary, not an intrinsic CPU maximum.
- `multi/oidc_cold_login_refresh`: All 10080 offered operations started and completed, no drops, preparation failure or VU warning; load CPU 0.273 and app CPU 8.053 of 16, pool wait 0.001ms and analyzer lag 0.270s. These are server 503 responses. Hash admission pressure is consistent with the eight-permit/100ms policy but the exact 503 response body was not retained, so no narrower root cause is claimed.

## Mixed maintenance, audit and WAL

| Mode / deployment | Load / window s | Mature span / samples | Max expired age s | Due first / last / max | Mature inserted / deleted | Audit queued / persisted / lost / pending after drain | Durable / journal sequence |
|---|---|---|---:|---|---|---|---|
| single / original-container | 600 / 660 | 300 / 148 | 58.435 | 8413 / 8339 / 8413 | 138877 / 141626 | 67827 / 67827 / 0 / 0 | 536367 / 536367 |
| multi / new-container | 2349 / 660 | 300 / 144 | 60.115 | 9354 / 108785 / 134937 | 689993 / 615712 | 288660 / 288660 / 0 / 0 | 2535673 / 2535673 |

| Mode | WAL generation bytes | WAL write bytes | Writes / fsyncs | Generated / written bytes per main success | Pool acquisition wait ms | Maintenance / audit / continuity |
|---|---:|---:|---|---|---:|---|
| single | 1371739627.976 | 5721142050.762 | 406231.228 / 405983.228 | 3463.989 / 14447.328 | 0.027 | PASS / PASS / PASS |
| multi | 6894754743.598 | 18997814010.568 | 860099.164 / 858844.664 | 4447.253 / 12253.966 | 0.024 | PASS / PASS / PASS |

| Mode / sidecar | Offered / successful ops/s | Own window s | Full P50/P95/P99 ms | HTTP guard quantiles when full cohort unavailable | Errors / drops / rejects / unfinished | Gate |
|---|---|---:|---|---|---|---|
| single / argon2 | 1 / 1 | 735 | 258/295.3/318.66 | N/A | 0/0/0/0 | PASS |
| single / meta | 13 / 13 | 735 | 1/7/13 | N/A | 0/0/0/0 | PASS |
| single / fapi | 2 / 2 | 735 | 26/36/51.31 | N/A | 0/0/0/0 | PASS |
| single / refresh | 38 / 38 | 735 | 7/58/88 | N/A | 0/0/0/0 | PASS |
| multi / argon2 | 8 / 8 | 735 | 157/174/194 | N/A | 0/0/0/0 | PASS |
| multi / meta | 200 / 200 | 735 | 1/1/2 | N/A | 0/0/0/0 | PASS |
| multi / fapi | 30 / 30 | 735 | 29/44/65 | N/A | 0/0/0/0 | PASS |
| multi / refresh | 600 / 600 | 735 | 7/12/24 | N/A | 0/0/0/0 | PASS |

WAL generation is pg_stat_wal; write bytes, writes and fsyncs are pg_stat_io. Sparse counter deltas are interpolated at the window boundaries. WAL per main success includes sidecars, audit and background work. WAL timing remains N/A; these are not physical-device write amplification measurements.


The replacement mixed 2349/s confirmation completes every main operation and passes all four sidecars, mature cleanup, audit persistence/loss and journal continuity. Its complete journal is 2282794823 bytes with SHA256 `9266688c73d6ce1c888cdbbcf771f916783cd7591aa7061176a977fc5ce14b6d`; all 63 critical archive members and the full journal were verified locally. The retained single-CPU 600/s journal is also fully hash-verified. The later original-container 3750/s journal was lost during shutdown and is excluded from the current authority.

At mixed 2900/s every FAPI arrival completes with zero drops and no VU warning, while FAPI full P95 is 108 ms. The closer 2610/s attempt fails only delivery gates and is not used as U. Its warning-time samples show pool waiting 20→1134→1268, idle connections zero and 63–64 PostgreSQL LWLock waiters, followed by recovery. These prove a server queue burst, but the captured samples do not identify a specific SQL or physical-device bottleneck. A later bounded wait-name observation on the passing 2349/s point is a separate population and cannot be retroactively attributed to that burst. The [burst evidence](../../../../perf/results/diagnostics/2026-09-28-incremental-mixed-queue-burst.json) records this boundary.

## Endpoint resource evidence

| Mode / scene / endpoint | App cores used / allocated | PG cores / 16 | Generator cores / 31 | Pool wait ms | Native max lag s |
|---|---|---|---|---:|---:|
| single / `cap_mixed` / L | 0.65 / 1 | 1.318 | 0.695 | 0.027 | 0.257 |
| single / `cap_mixed` / U | 0.821 / 1 | 1.382 | 0.798 | 1.371 | 0.254 |
| single / `cap_client_credentials` / L | 0.805 / 1 | 1.627 | 0.681 | 0.201 | 0.255 |
| single / `cap_client_credentials` / U | 0.912 / 1 | 1.935 | 0.797 | 16.985 | 0.257 |
| single / `cap_authorization_code` / L | 0.807 / 1 | 1.64 | 0.981 | 0.121 | 0.258 |
| single / `cap_authorization_code` / U | 0.978 / 1 | 2.502 | 1.251 | 28.991 | 0.266 |
| single / `cap_refresh_token` / L | 0.876 / 1 | 1.589 | 0.443 | 0.148 | 0.26 |
| single / `cap_refresh_token` / U | 0.958 / 1 | 1.821 | 0.485 | 15.396 | 0.259 |
| single / `fapi2_logged_in_high_security` / L | 0.087 / 1 | 0.157 | 0.196 | 0.001 | 0.251 |
| single / `cap_introspect` / L | 0.093 / 1 | 0.397 | 0.356 | 0 | 0.251 |
| single / `cap_revoke` / L | 0.172 / 1 | 0.491 | 0.249 | 0 | 0.25 |
| single / `mtls_client_credentials` / L | 0.177 / 1 | 0.606 | 0.202 | 0.001 | 0.251 |
| single / `par_signed_request_object` / L | 0.048 / 1 | 0.125 | 0.35 | 0.001 | 0.251 |
| single / `oidc_cold_login_refresh` / L | 0.116 / 1 | 0.015 | 0.011 | 0.001 | 0.251 |
| multi / `cap_mixed` / L | 5.387 / 16 | 6.533 | 2.767 | 0.024 | 0.71 |
| multi / `cap_mixed` / U | 6.148 / 16 | 7.678 | 3.307 | 0.097 | 2.402 |
| multi / `cap_client_credentials` / L | 4.834 / 16 | 6.699 | 3.779 | 0.184 | 0.506 |
| multi / `cap_client_credentials` / U | 5.49 / 16 | 7.867 | 4.482 | 2.221 | 0.763 |
| multi / `cap_authorization_code` / L | 3.105 / 16 | 5.516 | 3.038 | 0.019 | 1.998 |
| multi / `cap_authorization_code` / U | 3.336 / 16 | 7.155 | 3.476 | 0.662 | 0.999 |
| multi / `cap_refresh_token` / L | 4.297 / 16 | 7.323 | 1.966 | 0.032 | 0.311 |
| multi / `cap_refresh_token` / U | 3.731 / 16 | 5.713 | 1.527 | 229.24 | 0.334 |
| multi / `fapi2_logged_in_high_security` / L | 1.626 / 16 | 2.26 | 3.232 | 0.001 | 0.256 |
| multi / `cap_introspect` / L | 4.235 / 16 | 7.556 | 7.696 | 0.048 | 3.078 |
| multi / `cap_introspect` / U | 4.579 / 16 | 8.233 | 8.12 | 0.09 | 3.345 |
| multi / `cap_revoke` / L | 1.766 / 16 | 3.704 | 2.056 | 0.001 | 0.254 |
| multi / `mtls_client_credentials` / L | 3.55 / 16 | 5.284 | 3.086 | 0.122 | 0.261 |
| multi / `par_signed_request_object` / L | 0.971 / 16 | 1.244 | 5.462 | 0.001 | 0.262 |
| multi / `oidc_cold_login_refresh` / L | 7.48 / 16 | 0.401 | 0.244 | 0.001 | 0.267 |
| multi / `oidc_cold_login_refresh` / U | 8.053 / 16 | 0.444 | 0.273 | 0.001 | 0.27 |


## Measurement and CI repairs

Mixed now evaluates all four sidecars using the existing shared gates. Invalid measurement takes precedence over health/maintenance service failures. Offline reevaluation and targeted mode/scenario/rate execution preserve separate recipes. Complete sidecar operation quantiles are exposed; absent full-cohort quantiles remain N/A. Python stream dispatch no longer waits for another 64 KiB after complete sparse blocks. Native k6 periodic output now flushes its existing stdout buffer instead of waiting for 4 KiB or shutdown. Both transport regressions fail on the old code and pass after the minimal repairs. Native JSON/metrics tests and 262 Python regressions ran (260 passed, two platform-conditional skips); live repaired observer lag is below the unchanged five-second gate. No acceptance assertion or durability setting was relaxed.

The original compatibility failure was documentation/layout contract drift, not a Rust test failure. CI now budgets build concurrency from runner CPU/memory (four jobs in observed runners), reuses matching all-feature build artifacts and retains serial shared-database tests. Audit fixture cleanup adds deterministic isolation before the expensive vacuum case; all thirteen audit regression behaviors and assertions remain covered. No necessary job or security/concurrency test was deleted.

| Representative quality job | Queue s | Total s | Workspace step s | Cargo compile s | Audit suite s | Evidence |
|---|---:|---:|---:|---:|---:|---|
| Before repair | 2 | 1829 / 1859 | 1567 / 1601 | 460 / 464 | 429.57 / 449.34 | [Original CI report](../2026-09-28-current-b/report.md#ci-repair-and-observed-cost) |
| Earlier repaired run | 2 | 1115 | N/A | 166 | 375.54 | [Recorded timings](../../../../perf/results/diagnostics/2026-09-28-ci-cost-60d.json) |
| `ec638ce7` | N/A | 1110 | 951 | 176 | 374.16 | [Job](https://github.com/nazozero/NazoAuth/actions/runs/36409414900/job/108885814020) |
| `01f3c67c` | 2 | 1390 | 1205 | N/A | N/A | [Job](https://github.com/nazozero/NazoAuth/actions/runs/36430863648/job/108956375295) |

The latest representative job spends 26 s restoring cache, 16 s installing native dependencies, 12 s preparing avatar fixtures, 36 s verifying schema and 47 s in Clippy. Queue, initialization, compilation and tests remain separate costs. Cache/runner variation prevents attributing a speedup percentage to one change. The serial audit suite remains a major cost. Eleven applicable checks must succeed on the delivered final commit. The two existing skips are event conditions: official-source freshness and Rust advisory audit are non-PR checks; their PR counterparts still run. Final SHA and exact-head check links are recorded in the [PR delivery comment](https://github.com/nazozero/NazoAuth/pull/222), rather than claiming an earlier commit's green checks cover this publication.

## Evidence retention and reproduction

[Current structured authority](../../../../perf/results/data/capacity/current-capacity.json), [selected compact evidence](../../../../perf/results/diagnostics/2026-09-28-incremental-b-selected.json), [offline reassessment](../../../../perf/results/diagnostics/2026-09-28-incremental-final-reassessment.json) and [archive identities](../../../../perf/results/diagnostics/2026-09-28-incremental-evidence-archives.json) are in Git. Large archives remain outside Git in the task artifact storage, with file hashes and explicit scopes. The original 812407286-byte archive has 925 verified members; retained incremental evidence has 463 verified members and explicitly lacks 17 legacy auxiliary stdout logs. Native acceptance inputs are retained. Some bounded auxiliary forensic streams overflowed; these are not represented as complete raw streams and do not replace the independent exact native counters/histograms.

| Archive | Bytes | SHA256 | Scope |
|---|---:|---|---|
| `20260928-new-mixed-critical.tar.gz` | 434443156 | `0d13006b33a9e402d8dfb640b668fd194c10223682f7db27bbfe041251bcd5be` | Complete critical mixed confirmation native gate inputs, maintenance/CPU samplers and full journal; forensic gzip streams remain in final selected archive. |


Reassess the preserved point directories with the current controller before requesting more load:

```sh
python perf/tools/current_capacity.py --reevaluate <selected-point.json-files> --output reassessment.json
```

For a new deployment, obtain its process-visible CPU/memory first and freeze its own registered recipe. Use [the existing incremental entry point](../../../../perf/README.md#incremental-current-b-acceptance), set the exact runner image and isolated result root, and specify only the required mode, scene, rate, effective window, VUs, users, pool and stream workers. Mixed also requires its exact sidecar VUs/users/rates and `--confirm --window 660`. Metadata/keys/fixture private inputs are kept outside Git. Do not use an unqualified full-matrix search or mix a newly configured upper with these retained lowers.

## Outstanding acceptance

Service uppers not established: `single/fapi2_logged_in_high_security`, `single/cap_introspect`, `single/cap_revoke`, `single/mtls_client_credentials`, `single/par_signed_request_object`, `single/oidc_cold_login_refresh`, `multi/fapi2_logged_in_high_security`, `multi/cap_revoke`, `multi/mtls_client_credentials`, `multi/par_signed_request_object`.

Candidates needing 180-second confirmation: none.

Intervals needing refinement: `multi/cap_mixed`.

These gaps prevent completed acceptance. Passing observations and independent service failures above are verified within their stated windows and configurations; unestablished maxima, production long-term capacity, per-SQL WAL cause and hidden-host resource limits are not claimed.
