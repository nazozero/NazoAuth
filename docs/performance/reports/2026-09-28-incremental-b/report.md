# Current-B incremental performance acceptance — 2026-09-28

Capacity acceptance status: **COMPLETE**. 20/20 mode/scenario rows have reviewed service upper endpoints. All twenty mode/scenario rows have reviewed service upper endpoints, narrowed frozen-recipe intervals and at least 180-second endpoint verification. Both mixed passing candidates have 660-second maintenance and audit confirmations.

Execution began at 09:58:28 UTC. The user subsequently extended and corrected the final deadline to 2026-09-29 03:30 Beijing (2026-09-28 19:30 UTC), with immediate container destruction at 04:00 Beijing. Final targeted verification uses an explicit 19:40 UTC stop guard; the last formal point finished before 19:27 UTC; publication and exact-head CI are advanced alongside the retained-evidence work. The original 90-minute final reserve was not maintained after continued boundary refinement; the actual final timings are recorded in the delivery comment. [Checkpoint history](checkpoint-history.md) records the independent commits and intermediate results; [original observations](../2026-09-28-current-b/report.md) are historical and superseded.

## Identity, configuration and measurement

Application source is `ac266e7a93749694022efd1aeea6ed4d316fbbcc`, image `5f62a3a2247e609d72ee03de1bc0d330873d5742b1f94cd5ec144baa69f2f71d`, binary `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b`. Production code is unchanged, so the restored application image was reused. Required ancestor `04146234c578e61797aacee7ef7c4687b75653a1` is included. The offline evaluator was reviewed at `d1e2e8ea0f89e479e6dae6e6921a9611f2769fba`; its exact source file hashes are retained in the separate reassessment.

Both deployments expose 64 logical CPUs and a 128 GiB container memory limit. The original deployment allocated app single 24 or multi 24–27,132–143 (16), PG 144–159, Valkey 160 and generators 161–191. The replacement deployment dynamically allocated app single 24 or multi 24–39, PG 40–55, Valkey 56 and generators 57–79,184–191. The PAR allocation override is calibrated from observed client signing cost; its actual application, database and generator CPU sets are separately retained in the registered recipe and its endpoints are remeasured. Actual per-point affinity is verified and retained. Only deployment-visible resources were investigated. Component allocations are disjoint; all auxiliary roles share the stated generator set. Each interval uses one deployment and one exact frozen recipe; no original/new result or altered VU/pool/user configuration is joined into a boundary. The original `current-b` and `incremental-b` result roots belong to the same deployment; `incremental-b-v2` belongs to the replacement.

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
| `fapi2_logged_in_high_security` | new-container | 1 | 180 | 200 | 180 | 899.989 | 28/43/58 | 0/0/0/0 | 180/180 | [180, 200) observed |
| `cap_introspect` | new-container | 1 | 5000 | 5625 | 5000 | 5000.006 | 1/2/11 | 0/0/0/0 | 180/180 | [5000, 5625) observed |
| `cap_revoke` | new-container | 1 | 378 | 425 | 378 | 1890.006 | 22/48/118 | 0/0/0/0 | 180/180 | [378, 425) observed |
| `mtls_client_credentials` | new-container | 1 | 1500 | 1687 | 1500 | 1499.994 | 4/14/69 | 0/0/0/0 | 180/180 | [1500, 1687) observed |
| `par_signed_request_object` | new-container | 1 | 4200 | 4725 | 4197.894 | 4197.883 | 3/9/24 | 0/379/0/0 | 180/180 | [4200, 4725) observed |
| `oidc_cold_login_refresh` | new-container | 1 | 7 | 8 | 7 | 42 | 131/143/517.68 | 0/0/0/0 | 180/180 | [7, 8) observed |

## Multiple logical CPUs (count per row)

| Scenario | Deployment | App CPUs | PASS L | Service FAIL U | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window L/U s | Conclusion |
|---|---|---:|---:|---:|---:|---:|---|---|---|---|
| `cap_mixed` | new-container | 16 | 2600 | 2900 | 2600.003 | 3769.056 | 4/18/25 | 0/0/0/0 | 660/660 | [2600, 2900) observed |
| `cap_client_credentials` | new-container | 16 | 6000 | 6500 | 6000.022 | 6000.067 | 4/11/29 | 0/0/0/0 | 180/180 | [6000, 6500) observed |
| `cap_authorization_code` | new-container | 16 | 900 | 1000 | 900 | 3599.553 | 63/92/109 | 0/0/0/0 | 180/180 | [900, 1000) observed |
| `cap_refresh_token` | new-container | 16 | 2624 | 2916 | 2624.006 | 2623.994 | 7/13/26 | 0/0/0/0 | 180/180 | [2624, 2916) observed |
| `fapi2_logged_in_high_security` | new-container | 8 | 1186 | 1334 | 1186 | 5930.017 | 36/63/81 | 0/0/0/0 | 180/180 | [1186, 1334) observed |
| `cap_introspect` | original-container | 16 | 16000 | 17000 | 15997.911 | 15997.838 | 1/3/15 | 0/376/0/0 | 180/180 | [16000, 17000) observed |
| `cap_revoke` | new-container | 16 | 2000 | 2250 | 2000 | 10000.246 | 27/57/124 | 0/0/0/0 | 180/180 | [2000, 2250) observed |
| `mtls_client_credentials` | new-container | 16 | 6223 | 7000 | 6223.017 | 6223.034 | 5/13/27 | 0/0/0/0 | 180/180 | [6223, 7000) observed |
| `par_signed_request_object` | new-container | 4 | 11853 | 13334 | 11848.939 | 11848.961 | 4/57/93 | 0/729/0/0 | 180/180 | [11853, 13334) observed |
| `oidc_cold_login_refresh` | original-container | 16 | 52 | 56 | 52 | 312 | 159/179/187 | 0/0/0/0 | 180/180 | [52, 56) observed |

## Upper endpoints

| Scenario / mode | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window s | Failure evidence |
|---|---:|---:|---|---|---:|---|
| `cap_mixed` / single | 644.15 | 938.397 | 10/130/233 | 0/1053/0/0 | 180 | main complete-operation P95 130ms exceeds 100ms; FAPI complete-operation P95/P99 181.2/273.82ms exceeds 100/250ms; refresh complete-operation P95 131ms exceeds 100ms; main dropped fraction 0.9% exceeds 0.1% |
| `cap_client_credentials` / single | 1491.167 | 1491.268 | 11/339/395 | 0/1590/0/0 | 180 | complete-operation P95/P99 339/395ms exceeds 100/250ms; measurement dropped fraction 0.5889% exceeds 0.1% |
| `cap_authorization_code` / single | 342.806 | 1370.978 | 584/809/881 | 0/1295/0/0 | 180 | complete-operation P95/P99 809/881 ms exceeds 100/250 ms; 1295 measurement drops (2.0556%) exceeds 0.1% |
| `cap_refresh_token` / single | 808.95 | 808.447 | 54/311/341 | 0/549/0/0 | 180 | complete-operation P95/P99 311/341 ms exceeds 100/250 ms; 549 measurement drops (0.3756%) exceeds 0.1% |
| `fapi2_logged_in_high_security` / single | 200 | 999.972 | 70/114/130 | 0/0/0/0 | 180 | Complete-operation P95 114 ms exceeds the unchanged 100 ms gate. |
| `cap_introspect` / single | 5610.472 | 5610.486 | 1/173/191 | 0/2617/0/0 | 180 | Complete-operation P95 173ms exceeds 100ms; 2617 dropped arrivals (0.25847%) exceed the delivery gate. |
| `cap_revoke` / single | 412.511 | 2060.855 | 601/650/674 | 0/2248/0/0 | 180 | Complete-operation P95/P99 650/674ms exceeds 100/250ms; 2248 dropped arrivals (2.9386%) exceed the delivery gate. |
| `mtls_client_credentials` / single | 1610.528 | 1610.793 | 620/659/803 | 0/13764/0/0 | 180 | Complete-operation P95/P99 659/803ms exceeds 100/250ms; 13764 dropped arrivals (4.5327%) exceed the delivery gate. |
| `par_signed_request_object` / single | 4681.561 | 4681.218 | 40/103/119 | 0/7819/0/0 | 180 | Complete-operation P95 103ms exceeds 100ms; 7819 dropped arrivals (0.91934%) exceed the delivery gate. |
| `oidc_cold_login_refresh` / single | 7.456 | 45.62 | 1123/1227/1247 | 98/0/0/0 | 180 | 98 unexpected logical outcomes at8/s; complete-operation P95/P99 1227/1247ms. The unchanged distinct cold-login gate fails. |
| `cap_mixed` / multi | 2900.006 | 4208.812 | 7/44/78 | 0/0/0/0 | 660 | FAPI sidecar full-operation P95 108 ms exceeds 100 ms; its 22050 offered operations all finish successfully with no drops. |
| `cap_client_credentials` / multi | 6497.539 | 6497.615 | 5/39/331.44 | 0/444/0/0 | 180 | Full-operation P99 331.44 ms exceeds 250 ms; delivery/drop/error/unfinished gates pass. |
| `cap_authorization_code` / multi | 1000 | 4002.492 | 57/156/311 | 0/0/0/0 | 180 | Complete-operation P95/P99 156/311 ms exceed 100/250 ms |
| `cap_refresh_token` / multi | 1728.389 | 1728.274 | 1196/1356/1517 | 0/213769/0/0 | 180 | Full-operation P95/P99 1356/1517 ms exceeds 100/250 ms; 40.7273% offered arrivals drop after VUs become occupied by slow responses. |
| `fapi2_logged_in_high_security` / multi | 1312.878 | 6564.028 | 45/832/848 | 0/3802/0/0 | 180 | Full-operation P95/P99 832/848 ms exceeds unchanged 100/250 ms gates; 3802 dropped operations (1.5834%); runtime audit queue-full gate also fails. |
| `cap_introspect` / multi | 16707.406 | 16989.581 | 1/4/24 | 50802/1892/0/0 | 180 | 50802 unexpected logical outcomes; retained HTTP429 temporarily_unavailable responses demonstrate the unchanged source-IP management admission limit |
| `cap_revoke` / multi | 2214.517 | 11077.95 | 210/487/504 | 0/6387/0/0 | 180 | Full-operation P95/P99 487/504ms exceeds unchanged100/250ms gates;6387drops(1.577%);runtime queue-full gate fails. |
| `mtls_client_credentials` / multi | 6851.75 | 6851 | 5/33/369 | 0/26688/0/0 | 180 | Full-operation P99369ms exceeds unchanged250ms gate;26688droppedoperations(2.118%); successful6851.75/s is not gated capacity. |
| `par_signed_request_object` / multi | 13118.883 | 13112.961 | 73/115/127 | 0/38728/0/0 | 180 | Full-operation P95115ms exceeds unchanged100ms gate;38728droppedoperations(1.6136%);13118.883/s completion is not gated capacity. |
| `oidc_cold_login_refresh` / multi | 55.933 | 335.849 | 172/239/263 | 12/0/0/0 | 180 | 12 unexpected complete-operation outcomes; retained failed HTTP points are POST /auth/login 503 |


## Why the upper endpoints are service failures

- `single/cap_mixed`: All FAPI and refresh sidecar arrivals complete with zero drops and miss their unchanged latency gates. A separate one-factor main-VU 64-to-128 control at the same 650/s reduces main drops to 0.066% and delivers 99.934% of offered operations, yet main P95 remains 130ms and FAPI/refresh P95 remain 309/135ms. This rules out insufficient main VUs as the cause of the latency failure; that control is not mixed into the frozen 64-VU interval. The original 600/s, 660-second confirmation has verified effective recipe equivalence and is retained without modifying its raw evidence.
- `single/cap_client_credentials`: A one-factor VU 512-to-1024 control at the same 1500/s does not restore latency: complete-operation P95/P99 become 701/760 ms. Native whole-point HTTP waiting P95 is 335.189 ms at 512 VU and 697.629 ms at 1024 VU, while sending, receiving and blocked P95 are below 0.05 ms. These HTTP diagnostics do not replace full-operation cohort gates. Generator CPU is 0.797/31, analyzer lag 0.257 s and mean pool wait 16.985 ms at U (60.062 ms in the 1024 control), identifying server response/queue latency rather than injector compute or transport time. Under the 250-ms P99 SLO, 1500/s needs 375 busy VUs; the frozen 512-VU profile has headroom. The separate 1024 profile also fails at 1375/s and is not mixed into this 512-VU interval. No particular SQL or intrinsic hardware ceiling is claimed.
- `single/cap_authorization_code`: A one-factor 256-to-512 VU control at the same 350/s, users 64 and pool 32 delivers and completes all 63000 offered operations with no drops or warnings but still fails full-operation P95/P99 at 394/497 ms. This excludes insufficient VUs as the independent latency failure. Its generator CPU is 1.139/31, observer lag 0.284 s and mean pool wait 2.617 ms; no audit/health evidence fails. At the frozen 256-VU upper, app CPU is 0.978/1, generator 1.251/31, pool wait 28.991 ms and lag 0.266 s. The separate 512-VU control is not used as an interval bound; no specific SQL or continuously saturated component is claimed.
- `single/cap_refresh_token`: A one-factor 256-to-512 VU control holds users 64, pool 32 and images constant and does not restore the SLO: full-operation P95/P99 771/813 ms. The control still has a VU warning and 9.6654% drops, so it does not establish full target delivery. Independent response/queue evidence supports the service latency failure: native whole-point HTTP waiting P95 is 320.549 ms at the original upper and 769.863 ms in the control; send/receive/blocked P95 remain below 0.062 ms. Pool acquisition wait rises from 15.396 to 128.371 ms while generator CPU stays 0.485/31 and 0.490/31 and observer lag 0.259/0.262 s. App averages 0.958/1 and 0.927/1 CPU. At the unchanged 250-ms P99 SLO, 812/s requires 203 busy VUs, below 256. Warning/drop counts alone are not the attribution. The separate control is not an interval bound; no particular SQL is claimed.
- `single/fapi2_logged_in_high_security`: All36000 offered operations complete successfully at200/s with zero errors/drops/unfinished and no VU warning; full P95/P99 114/130ms. The180/s lower completes all32400 operations with full43/58ms. Both effective windows are180s on the same C3 runner/VU256/users64/pool32 recipe. Generator1.826/31CPUs and observer lag0.268s exclude injector compute or observer delay. Health and durable audit pass. This establishes the configured complete-business latency boundary; no particular SQL or CPU ceiling is inferred.
- `single/cap_introspect`: Both endpoints use the frozen 1024-VU/users128/pool32/four-observer recipe and 180-second windows. At 5000/s all 900000 operations succeed without drops/errors/unfinished; full P95/P99 are 2/11ms. At 5625/s all 1009885 started operations succeed, but full P95/P99 are 173/191ms and 2617 offered arrivals drop. Independent native whole-point HTTP response waiting P95 is 173.398ms, while blocked/sending/receiving P95 are below 0.031ms; these are diagnostics, not replacements for complete-operation cohorts. Pool acquisition wait is 10.739ms, app mean CPU 0.894/1, generator 2.809/31 and observer lag 0.334s. The service response latency failure therefore persists independently of VU warning/delivery. Earlier 60-second passes remain controls and do not override the failed 180-second verification at 5625/s. No particular SQL or sustained CPU saturation is inferred.
- `single/cap_revoke`: Both endpoints use 256 VUs/users64/pool32 and 180-second windows. At 378/s every offered operation succeeds with full P95/P99 48/118ms. At 425/s every started operation finishes successfully (74252), but full P95/P99 reach 650/674ms and 2248 arrivals drop. Independent native HTTP response waiting P95 is 201.351ms per request, while blocked/sending/receiving P95 are below 0.038ms; the full revoke business operation contains multiple requests and its own 650ms cohort gate remains authoritative. Application CPU 0.988/1 and pool acquisition wait 29.449ms identify service work/queue pressure, with generator CPU 1.385/31 and observer lag 0.265s. The VU warning is preserved and is not the sole upper evidence. No narrower SQL cause is claimed.
- `single/mtls_client_credentials`: The separate frozen 1024-VU/users64/pool32 single-core recipe passes1500/s for180seconds, with all270000operations succeeding and no drops/errors/unfinished, full P95/P99 14/69ms. At1687/s every289895started operation completes successfully, but full P95/P99 reach659/803ms and13764offered arrivals drop. Independent native whole-point HTTP response waiting P95/P99 is663.883/795.670ms, while blocked/sending/receiving P95 are below0.039ms and TLS handshake P95 is zero; these diagnostics do not replace the full-operation cohort gate. Pool acquisition wait203.054ms and app CPU0.980of1 identify service queue/work pressure. Generator0.817of31CPUs and observer lag0.264s exclude injector compute/measurement delay. The warmup VU warning is retained, but response latency fails independently. Earlier512-VU results remain separate controls; no particular SQL is inferred.
- `single/par_signed_request_object`: Both endpoints use the frozen 512-VU/users64/pool32 single-core recipe and 180-second windows. At 4200/s, all 755621 started operations succeed, full P95/P99 are 9/24ms, and 379 drops (0.05013%) satisfy the unchanged delivery gate. At 4725/s, all 842681 started operations finish successfully, but full P95/P99 are 103/119ms and 7819 offered arrivals drop. Independent whole-point native HTTP response waiting P95 is 100.440ms, with blocked/sending/receiving P95 below 0.034ms. These diagnostics identify response waiting and do not replace the complete-operation cohort gate. App CPU is 0.984/1 and mean pool wait 16.680ms; generator CPU 10.366/31 and observer lag 0.267s provide compute and measurement headroom. Warmup VU warnings remain explicit and are not the sole upper evidence. The separate multi-mode client-signing limits are not spliced into this interval; no per-SQL bottleneck is inferred.
- `single/oidc_cold_login_refresh`: Both endpoints use180s and the same256-VU/users64/pool32/C3 recipe. At8/s all1440 offered operations start and complete, with zero drops/preparation failures/unfinished and no VU warning;1342succeed and98are unexpected. ApplicationCPU0.995of1, generator0.068of31 and observer lag0.371s support service work rather than an injector bottleneck. At7/s every offered operation succeeds, full P95/P99 143/517.68ms, under the existing cold-login class. The stored Argon2 m65536/t3/p4 and eight-permit admission policy are unchanged; no narrower admission/error-body cause or ordinary100/250ms comparison is claimed.
- `multi/cap_mixed`: The same 1024-VU/users256/pool64/four-observer recipe passes2600/s for660seconds:1716002main operations all succeed, complete-operation P95/P99 18/25ms, and all four sidecars, health, mature maintenance and durable audit pass. At2900/s for660seconds all1914004main operations and all22050FAPI operations complete with zero drops/errors/unfinished and no FAPI VU warning, but FAPI complete-operation P95/P99 108/138.51ms violates its100msP95 gate. Main generator3.307of31CPUs and FAPI observer lag0.327s exclude clientcompute/measurement delay for that independent service-latency upper. The earlier2610/s delivery-failed point remains a valid apparatus-constrained control with documented server queue bursts; it is not silently discarded or promoted to a backend upper. The2600/2900 bracket is an observed short-window interval, not proof that every interior load or indefinite operation passes.
- `multi/cap_client_credentials`: A one-factor 2048-to-4096 VU control holds users256/pool64/8 workers/native image fixed at6000/s: all1080004 offered operations finish with zero drops, P95/P99 11/29ms, disproving the old drop-only service upper. The frozen4096-VU upper at6500/s completes all1169557 started operations, has0unexpected and0unfinished, and444/1170001 drops (0.03795%, below0.1%). Its independent complete-operation P99 fails. Generator4.482/31CPUs, lag0.763s, pool wait2.221ms. A VU warning remains, but it is not the upper evidence; no particular SQL/CPU ceiling is claimed.
- `multi/cap_authorization_code`: All 180000 scheduled operations start and finish successfully with no errors, dropped or unfinished operations; no VU warning. Generator uses 3.476 of 31 cores, observer lag 0.999s. Full-operation latency fails with complete offered load delivery.
- `multi/cap_refresh_token`: The same 2048-VU/users256/pool64/4-worker recipe delivers all472321 operations at2624/s, full P95/P99 13/26ms, zero errors/drops/unfinished and no VU warning. At2916/s, complete-operation latency fails independently of the drop count. Mean measured server pool acquisition wait is229.24ms; generator uses1.527/31CPUs, app3.731/16 and PG5.713/16, observer lag0.334s, with no reader/parse failure and intact health/audit. Under the250ms SLO,2916/s requires729busyVUs, below2048. The warning reflects2048 VUs occupied by roughly1.2s responses; it does not by itself define U. This establishes a configured service response/queue boundary, not a specific SQL or intrinsic CPU ceiling. The3240/s control independently fails full P95/P99 1275/1364ms with mean pool wait57.213ms and generator2.081/31CPUs.
- `multi/fapi2_logged_in_high_security`: At 1334/s the exact complete-operation cohort fails latency and delivery. Whole-point HTTP waiting P95/P99 219.096/237.202 ms while blocked/sending/receiving P95 are below 0.041 ms establishes independent response wait; generator12.474/39CPUs and observer lag0.261s exclude CPU-saturated observation. Increasing concurrency is not needed to turn the already-failed server-response gate into a FAIL. App6.037/8CPU, PG9.496/16CPU and pool wait12.385ms are sampled associations, not a proved SQL root cause. The queue-full health failure remains FAIL; all1269341 accepted events reconcile to a complete contiguous journal with zero required audit loss and pending after drain. The 1500/s point separately remains a valid FAIL, not an additional passing result.
- `multi/cap_introspect`: Both points have valid 180-second windows and full cohorts. At 17000/s, 99.938% of offered arrivals start, every started operation completes, and 0.0618% drops satisfy the 0.1% delivery gate; complete-operation P95/P99 are 4/24 ms. Failure persists independently as 50802 unexpected outcomes and a successful-operation deficit. Bounded whole-point logs retain 40960 HTTP 429 samples, not an exact measurement status count. The unchanged policy is 1000000 management requests per source IP per 60 seconds. Generator CPU 8.120/31, app 4.579/16, PG 8.233/16, pool wait 0.090 ms and analyzer lag 3.345 s with zero parse/reader failures exclude generator delivery and measurement failures. This is the configured one-source-IP service admission boundary, not an intrinsic CPU maximum.
- `multi/cap_revoke`: Both180-second endpoints use the same16-app/16-PG/31-generator-CPU,1024-VU,256-user,64-pool profile. At2250/s whole-point HTTP waiting P95/P99 is134.972/154.051ms, while blocked/sending/receiving P95 stay below0.037ms. Generator7.759/31CPUs and native lag0.263s provide headroom; the server response wait independently fails the latency requirement despite the VU warning. PG13.671/16CPU, app8.770/16CPU and pool wait11.818ms are corroborating resource/queue evidence, without attribution to one SQL. All398613 started logical operations finish without unexpected outcomes; the queue-full health failure remains FAIL while durable audit and complete journal reconciliation pass.
- `multi/mtls_client_credentials`: The180-second7000/s point has exact1260003offered,1233315started/completed/successful,zerounexpected/preparation/unfinished outcomes. Whole-point HTTP waiting P99323.899ms independently exceeds250ms, while blocked/sending/receiving P99 are below0.087ms and TLS-handshake quantiles are zero on reused connections. The2048-VU warning accompanies a service-response tail, not the only evidence of failure. Generator3.831/31CPUs and observer lag0.280s provide headroom; app6.480/16CPU, PG10.833/16CPU and pool wait4.190ms corroborate response/queue pressure without identifying a SQL or device cause. Runtime health and durable audit pass; mTLS and all protocol checks remain enabled.
- `multi/par_signed_request_object`: Both180-second endpoints use the exact4-app/8-PG/51-generator-CPU,1536-VU,256-user,64-pool,8-observer-worker profile. At13334/s whole-point HTTP waiting P95/P99 is109.752/119.936ms while blocked/sending/receiving P95 is below0.037ms, independently exceeding the server-response budget. Generator35.780/51CPU and native lag0.445s provide headroom; app3.735/4CPU and pool wait25.944ms corroborate response/concurrency pressure without proving a particular SQL/device cause. Raising VUs blindly did not resolve delivery: on the unchanged11853/s workload the1792-VU profile failed twice with2945and3417drops, while1536VUs pass with729drops(0.03417%) and full57/93ms. The separate1280-VU controls are retained. Lower and upper are exclusively1536VUs; no bound mixes those profiles. All started operations finish, unexpected/preparation outcomes are zero, and runtime/durable-audit gates pass. GC-specific causality and production long-term capacity remain unproved.
- `multi/oidc_cold_login_refresh`: All 10080 offered operations started and completed, no drops, preparation failure or VU warning; load CPU 0.273 and app CPU 8.053 of 16, pool wait 0.001ms and analyzer lag 0.270s. These are server 503 responses. Hash admission pressure is consistent with the eight-permit/100ms policy but the exact 503 response body was not retained, so no narrower root cause is claimed.

## Mixed maintenance, audit and WAL

| Mode / deployment | Load / window s | Mature span / samples | Max expired age s | Due first / last / max | Mature inserted / deleted | In-process queue enqueued / persisted / dropped / pending after drain | Durable / journal sequence |
|---|---|---|---:|---|---|---|---|
| single / original-container | 600 / 660 | 300 / 148 | 58.435 | 8413 / 8339 / 8413 | 138877 / 141626 | 67827 / 67827 / 0 / 0 | 536367 / 536367 |
| multi / new-container | 2600 / 660 | 300 / 145 | 59.764 | 44896 / 10003 / 44896 | 742644 / 653549 | 316281 / 316281 / 0 / 0 | 2745251 / 2745251 |

| Mode | WAL generation bytes | WAL write bytes | Writes / fsyncs | Generated / written bytes per main success | Pool acquisition wait ms | Maintenance / audit / continuity |
|---|---:|---:|---|---|---:|---|
| single | 1371739627.976 | 5721142050.762 | 406231.228 / 405983.228 | 3463.989 / 14447.328 | 0.027 | PASS / PASS / PASS |
| multi | 7422892065.854 | 20403939125.416 | 912514.198 / 911167.309 | 4325.69 / 11890.394 | 0.01 | PASS / PASS / PASS |

| Mode / sidecar | Offered / successful ops/s | Own window s | Full P50/P95/P99 ms | HTTP guard quantiles when full cohort unavailable | Errors / drops / rejects / unfinished | Gate |
|---|---|---:|---|---|---|---|
| single / argon2 | 1 / 1 | 735 | 258/295.3/318.66 | N/A | 0/0/0/0 | PASS |
| single / meta | 13 / 13 | 735 | 1/7/13 | N/A | 0/0/0/0 | PASS |
| single / fapi | 2 / 2 | 735 | 26/36/51.31 | N/A | 0/0/0/0 | PASS |
| single / refresh | 38 / 38 | 735 | 7/58/88 | N/A | 0/0/0/0 | PASS |
| multi / argon2 | 8 / 8 | 735 | 147/161/177 | N/A | 0/0/0/0 | PASS |
| multi / meta | 200 / 200 | 735 | 1/1/1 | N/A | 0/0/0/0 | PASS |
| multi / fapi | 30 / 30 | 735 | 26/38/52 | N/A | 0/0/0/0 | PASS |
| multi / refresh | 600 / 600 | 735 | 6/10/20 | N/A | 0/0/0/0 | PASS |

Queue counters cover the in-process audit adapter; complete durable audit is independently reconciled over the database and journal sequence range, including transactional outbox events. These are different counter populations and must not be equated. WAL generation is pg_stat_wal; write bytes, writes and fsyncs are pg_stat_io. Sparse counter deltas are interpolated at the window boundaries. WAL per main success includes sidecars, audit and background work. WAL timing remains N/A; these are not physical-device write amplification measurements.


The replacement mixed 2600/s confirmation completes the measured workload and passes all four sidecars, mature cleanup, audit persistence/loss and journal continuity. Its complete journal is 2470528071 bytes with SHA256 `dc090b0ee645543be36eb50dc0273b2075ddf95526d6a5d53d232dcb7a76ea22`. The critical archive and complete journal are locally hash-verified. The retained single-CPU 600/s journal is fully hash-verified locally. The later original-container 3750/s journal was lost during shutdown and is excluded from the current authority.

The current new mixed mature span observes due issuance rows 44896→10003 (maximum 44896), with 742644 inserted and 653549 deleted. Maximum expired age is 59.764 seconds against the existing 120-second gate; the maximum sample gap is 2.085 seconds. The earlier2349/s control grows from9354to108785 due rows and remains separately retained. These are sampled cleanup-age passes over300seconds, not proof of bounded all-state backlog or indefinite cleanup equilibrium. Audit pending after drain is zero, which is a separate queue and cannot establish issuance equilibrium.

At mixed 2900/s every FAPI arrival completes with zero drops and no VU warning, while FAPI full P95 is 108 ms. The closer 2610/s attempt fails only delivery gates and is not used as U. Its warning-time samples show pool waiting 20→1134→1268, idle connections zero and 63–64 PostgreSQL LWLock waiters, followed by recovery. These prove a server queue burst, but the captured samples do not identify a specific SQL or physical-device bottleneck. A later bounded wait-name observation on the passing 2349/s point is a separate population and cannot be retroactively attributed to that burst. The [burst evidence](../../../../perf/results/diagnostics/2026-09-28-incremental-mixed-queue-burst.json) records this boundary.

## Endpoint resource evidence

| Mode / scene / endpoint | App cores used / allocated | PG cores used / allocated | Sampled load/auxiliary cores / allocated | App / PG peak process RSS MiB | Pool wait ms | Native max lag s |
|---|---|---|---|---|---:|---:|
| single / `cap_mixed` / L | 0.65 / 1 | 1.318 / 16 | 0.864 / 31 | 100.926/5286.152 | 0.027 | 0.257 |
| single / `cap_mixed` / U | 0.821 / 1 | 1.382 / 16 | 0.975 / 31 | 100.652/4041.93 | 1.371 | 0.254 |
| single / `cap_client_credentials` / L | 0.805 / 1 | 1.627 / 16 | 0.813 / 31 | 54.609/4524.605 | 0.201 | 0.255 |
| single / `cap_client_credentials` / U | 0.912 / 1 | 1.935 / 16 | 0.963 / 31 | 58.062/4839.207 | 16.985 | 0.257 |
| single / `cap_authorization_code` / L | 0.807 / 1 | 1.64 / 16 | 1.115 / 31 | 41.18/3912.156 | 0.121 | 0.258 |
| single / `cap_authorization_code` / U | 0.978 / 1 | 2.502 / 16 | 1.413 / 31 | 46.242/4388.098 | 28.991 | 0.266 |
| single / `cap_refresh_token` / L | 0.876 / 1 | 1.589 / 16 | 0.572 / 31 | 46.23/4510.926 | 0.148 | 0.26 |
| single / `cap_refresh_token` / U | 0.958 / 1 | 1.821 / 16 | 0.617 / 31 | 46.168/4768.301 | 15.396 | 0.259 |
| single / `fapi2_logged_in_high_security` / L | 0.653 / 1 | 1.706 / 16 | 2.045 / 31 | 39.648/3046.758 | 0 | 0.259 |
| single / `fapi2_logged_in_high_security` / U | 0.666 / 1 | 1.587 / 16 | 1.959 / 31 | 39.391/3366.293 | 0.006 | 0.268 |
| single / `cap_introspect` / L | 0.766 / 1 | 2.001 / 16 | 2.595 / 31 | 97.68/1271.953 | 0.126 | 0.271 |
| single / `cap_introspect` / U | 0.894 / 1 | 2.338 / 16 | 2.809 / 31 | 98.34/1270.465 | 10.739 | 0.334 |
| single / `cap_revoke` / L | 0.889 / 1 | 2.946 / 16 | 1.328 / 31 | 42.68/5169.508 | 0.054 | 0.257 |
| single / `cap_revoke` / U | 0.988 / 1 | 3.411 / 16 | 1.491 / 31 | 45.246/5228.047 | 29.449 | 0.265 |
| single / `mtls_client_credentials` / L | 0.887 / 1 | 1.896 / 16 | 0.901 / 31 | 69.492/4640.133 | 0.375 | 0.256 |
| single / `mtls_client_credentials` / U | 0.98 / 1 | 2.312 / 16 | 0.944 / 31 | 93.117/4981.309 | 203.054 | 0.264 |
| single / `par_signed_request_object` / L | 0.883 / 1 | 1.414 / 16 | 9.143 / 31 | 56.547/782.379 | 0.304 | 0.255 |
| single / `par_signed_request_object` / U | 0.984 / 1 | 1.646 / 16 | 10.366 / 31 | 57.785/778.031 | 16.68 | 0.267 |
| single / `oidc_cold_login_refresh` / L | 0.832 / 1 | 0.058 / 16 | 0.043 / 31 | 93.391/235.281 | 0.001 | 0.368 |
| single / `oidc_cold_login_refresh` / U | 0.995 / 1 | 0.08 / 16 | 0.072 / 31 | 541.363/275.699 | 0.001 | 0.371 |
| multi / `cap_mixed` / L | 5.461 / 16 | 6.126 / 16 | 3.755 / 31 | 167.977/10707.949 | 0.01 | 0.439 |
| multi / `cap_mixed` / U | 6.148 / 16 | 7.678 / 16 | 4.517 / 31 | 248.355/10862.031 | 0.097 | 2.402 |
| multi / `cap_client_credentials` / L | 4.834 / 16 | 6.699 / 16 | 3.938 / 31 | 163.574/10388.746 | 0.184 | 0.506 |
| multi / `cap_client_credentials` / U | 5.49 / 16 | 7.867 / 16 | 4.639 / 31 | 243.832/10397.895 | 2.221 | 0.763 |
| multi / `cap_authorization_code` / L | 3.105 / 16 | 5.516 / 16 | 3.188 / 31 | 89.109/10261.816 | 0.019 | 1.998 |
| multi / `cap_authorization_code` / U | 3.336 / 16 | 7.155 / 16 | 3.597 / 31 | 96.07/10392.855 | 0.662 | 0.999 |
| multi / `cap_refresh_token` / L | 4.297 / 16 | 7.323 / 16 | 2.159 / 31 | 163.484/10426.242 | 0.032 | 0.311 |
| multi / `cap_refresh_token` / U | 3.731 / 16 | 5.713 / 16 | 1.747 / 31 | 184.223/10271.129 | 229.24 | 0.334 |
| multi / `fapi2_logged_in_high_security` / L | 5.445 / 8 | 8.159 / 16 | 11.326 / 39 | 81.02/10577.574 | 0.025 | 0.263 |
| multi / `fapi2_logged_in_high_security` / U | 6.037 / 8 | 9.496 / 16 | 12.612 / 39 | 114.008/10750.516 | 12.385 | 0.261 |
| multi / `cap_introspect` / L | 4.235 / 16 | 7.556 / 16 | 7.696 / 31 | 105.434/2387.484 | 0.048 | 3.078 |
| multi / `cap_introspect` / U | 4.579 / 16 | 8.233 / 16 | 8.12 / 31 | 107.984/2396.367 | 0.09 | 3.345 |
| multi / `cap_revoke` / L | 7.731 / 16 | 12.573 / 16 | 7.03 / 31 | 101.703/11032.902 | 0.235 | 0.26 |
| multi / `cap_revoke` / U | 8.77 / 16 | 13.671 / 16 | 7.893 / 31 | 124.434/10965.684 | 11.818 | 0.263 |
| multi / `mtls_client_credentials` / L | 5.832 / 16 | 9.594 / 16 | 3.548 / 31 | 140.305/10359.953 | 0.192 | 0.269 |
| multi / `mtls_client_credentials` / U | 6.48 / 16 | 10.833 / 16 | 3.957 / 31 | 172.934/10444.512 | 4.19 | 0.28 |
| multi / `par_signed_request_object` / L | 3.364 / 4 | 4.811 / 8 | 30.671 / 51 | 117.191/1411.676 | 1.325 | 0.45 |
| multi / `par_signed_request_object` / U | 3.735 / 4 | 5.45 / 8 | 35.78 / 51 | 120.035/1406.527 | 25.944 | 0.445 |
| multi / `oidc_cold_login_refresh` / L | 7.48 / 16 | 0.401 / 16 | 0.257 / 31 | 532.23/688.273 | 0.001 | 0.267 |
| multi / `oidc_cold_login_refresh` / U | 8.053 / 16 | 0.444 / 16 | 0.287 / 31 | 563.602/879.559 | 0.001 | 0.27 |


RSS is sampled process RSS. PostgreSQL values sum backend processes and count shared pages repeatedly; they are not unique physical memory consumption. Valkey and auxiliary component CPU/RSS observations remain in the selected point snapshots. Sampled resource headroom alone cannot establish maximum service capacity.

## Measurement and CI repairs

Mixed now evaluates all four sidecars using the existing shared gates. Invalid measurement takes precedence over health/maintenance service failures. Offline reevaluation and targeted mode/scenario/rate execution preserve separate recipes. Complete sidecar operation quantiles are exposed; absent full-cohort quantiles remain N/A. Python stream dispatch no longer waits for another 64 KiB after complete sparse blocks. Native k6 periodic output now flushes its existing stdout buffer instead of waiting for 4 KiB or shutdown. Both transport regressions fail on the old code and pass after the minimal repairs. Native JSON/metrics tests and 262 Python regressions ran (260 passed, two platform-conditional skips); live repaired observer lag is below the unchanged five-second gate. No acceptance assertion or durability setting was relaxed. A valid upper endpoint may fail a runtime capacity-health gate: that failure remains FAIL and is explicitly reported; its complete measurement, audit reconciliation and journal continuity still require independent evidence.

The original compatibility failure was documentation/layout contract drift, not a Rust test failure. CI now budgets build concurrency from runner CPU/memory (four jobs in observed runners), reuses matching all-feature build artifacts and retains serial shared-database tests. Audit fixture cleanup adds deterministic isolation before the expensive vacuum case; all thirteen audit regression behaviors and assertions remain covered. No necessary job or security/concurrency test was deleted.

| Representative quality job | Queue s | Total s | Workspace step s | Cargo compile s | Audit suite s | Evidence |
|---|---:|---:|---:|---:|---:|---|
| Before repair | 2 | 1829 / 1859 | 1567 / 1601 | 460 / 464 | 429.57 / 449.34 | [Original CI report](../2026-09-28-current-b/report.md#ci-repair-and-observed-cost) |
| Earlier repaired run | 2 | 1115 | N/A | 166 | 375.54 | [Recorded timings](../../../../perf/results/diagnostics/2026-09-28-ci-cost-60d.json) |
| `ec638ce7` | N/A | 1110 | 951 | 176 | 374.16 | [Job](https://github.com/nazozero/NazoAuth/actions/runs/36409414900/job/108885814020) |
| `01f3c67c` | 2 | 1390 | 1205 | N/A | N/A | [Job](https://github.com/nazozero/NazoAuth/actions/runs/36430863648/job/108956375295) |
| `d1e2e8ea` | N/A | 1484 | 1311 | N/A | N/A | [Exact observed steps](../../../../perf/results/diagnostics/2026-09-28-ci-cost-d1e2.json) |

The dd273216 job spends 18 s restoring cache, 7 s preparing avatar fixtures, 42 s materializing schema (39.47 s compiling its test target), 58 s in Clippy and 1316 s in the workspace step. Its workspace compilation is 201 s and the preserved serial audit suite is 436.87 s. Queue, initialization, compilation and tests remain separate costs. Cache/runner variation prevents attributing a speedup percentage to one change. The serial audit suite remains a major cost. [Exact dd273216 costs](../../../../perf/results/diagnostics/2026-09-28-ci-cost-dd273.json) separate these observed phases; total quality time is 1500 s. Eleven applicable checks must succeed on the delivered final commit. The two existing skips are event conditions: official-source freshness and Rust advisory audit are non-PR checks; their PR counterparts still run. Final SHA and exact-head check links are recorded in the [PR delivery comment](https://github.com/nazozero/NazoAuth/pull/222), rather than claiming an earlier commit's green checks cover this publication.

## Evidence retention and reproduction

[Current structured authority](../../../../perf/results/data/capacity/current-capacity.json), [selected compact evidence](../../../../perf/results/diagnostics/2026-09-28-incremental-b-selected.json), [offline reassessment](../../../../perf/results/diagnostics/2026-09-28-incremental-final-reassessment.json), [frozen reproduction arguments](../../../../perf/results/diagnostics/2026-09-28-incremental-reproduction-recipes.json), [excluded/apparatus controls](../../../../perf/results/diagnostics/2026-09-28-incremental-apparatus-controls.json) and [archive identities](../../../../perf/results/diagnostics/2026-09-28-incremental-evidence-archives.json) are in Git. Large archives remain outside Git in the task artifact storage, with file hashes and explicit scopes. The original 812407286-byte archive has 925 verified members; retained incremental evidence has 463 verified members and explicitly lacks 17 legacy auxiliary stdout logs. Native acceptance inputs are retained. Some bounded auxiliary forensic streams overflowed; these are not represented as complete raw streams and do not replace the independent exact native counters/histograms.

| Archive | Bytes | SHA256 | Scope |
|---|---:|---|---|
| `20260928-new-mixed-critical.tar.gz` | 434443156 | `0d13006b33a9e402d8dfb640b668fd194c10223682f7db27bbfe041251bcd5be` | Complete critical mixed confirmation native gate inputs, maintenance/CPU samplers and full journal; forensic gzip streams remain in final selected archive. |
| `20260928-final-new-gate-evidence.tar.gz` | 5227987 | `70b96dbbe1dd7f188c72d47f803026fc4982ceb6a732650d0c23fc5cad214a69` | Selected complete native JSON acceptance/replay inputs, terminal stdout logs and maintenance/component samplers. Passing mixed full journal is in the separately verified critical archive. Bounded auxiliary diagnostic streams and other journal payloads are explicitly excluded; this is not a complete raw-stream archive. |
| `20260928-final-selected-raw.tar.gz` | 789011196 | `29bb649b67b0fd01d2a7e00b45e4d5a8b262e0627f39d1268d9c1c49c19daf1f` | All available bounded selected-new forensic diagnostic captures plus complete2900/s service-upper journal. Existing capture overflow remains explicit; passing2349/s full journal is separately verified;2610/s delivery-control journal payload is not duplicated. |
| `20260928-final-mixed-critical.tar.gz` | 467071458 | `c5e599aa221b716fd71a9015732f0a7878d641eba3fc99111a44447435a2892d` | Complete critical mixed confirmation native gate inputs, maintenance/CPU samplers and full journal; forensic gzip streams remain in final selected archive. |
| `20260928-final-v2-native-evidence.tar.gz` | 11421108 | `87b606005610cfc95da89690a89852dab147657ea3cacae36784ec96e3541c82` | Selected complete native JSON acceptance/replay inputs, terminal stdout logs and maintenance/component samplers. Passing mixed full journal is in the separately verified critical archive. Bounded auxiliary diagnostic streams and other journal payloads are explicitly excluded; this is not a complete raw-stream archive. |
| `20260928-final-v2-raw-supplement.tar.gz` | 495692806 | `15bc2a2714a494c569fe51ee7db7aebc50030bd462046b1b210bb47a409be1f4` | Additional available bounded final selected forensic streams not present in the earlier verified raw archive. Existing overflow remains explicit. Complete mixed journals are retained separately; this does not claim complete raw-stream coverage. |
| `20260928-final-tool-runtime.tar.gz` | 98705863 | `aa369664274bdc93815e1b96c1ea1e7cca5022abead7a466936abe3b281abdab` | Exact BA sparse-dispatch and 779 periodic-native-flush benchmark tool Docker images; application and original runner images are retained in the earlier migration runtime archive. |


Reassess the preserved point directories with the current controller before requesting more load:

```sh
python perf/tools/current_capacity.py --reevaluate <selected-point.json-files> --output reassessment.json
```

For a new deployment, obtain its process-visible CPU/memory first and freeze its own registered recipe. Use [the existing incremental entry point](../../../../perf/README.md#incremental-current-b-acceptance), set the exact runner image and isolated result root, and specify only the required mode, scene, rate, effective window, VUs, users, pool and stream workers. Mixed also requires its exact sidecar VUs/users/rates and `--confirm --window 660`. Metadata/keys/fixture private inputs are kept outside Git. Do not use an unqualified full-matrix search or mix a newly configured upper with these retained lowers.

## Outstanding acceptance

Service uppers not established: none.

Candidates needing 180-second confirmation: none.

Intervals needing refinement: none.

The requested short-window acceptance is complete within the stated configurations. These observations do not prove production long-term capacity, per-SQL WAL causality or hidden-host resource limits.
