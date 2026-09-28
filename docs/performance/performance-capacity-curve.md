# NazoAuth Current-B Capacity Baseline

Incremental checkpoint: **COMPLETE**. Each row is one frozen recipe on its stated deployment. Both modes use one application instance. Old and new deployments are not combined into a bound. A missing service upper means at least the passing load, never a maximum.

Logical-operation quantiles cover the complete business operation. HTTP rate is reported separately. Short windows do not establish production long-term capacity. Windows below 180 seconds are exploratory candidates and require final verification; they are not labelled 180-second confirmations.

[Structured authority](../../perf/results/data/capacity/current-capacity.json) · [Report](reports/2026-09-28-incremental-b/report.md) · [Native evidence](../../perf/results/diagnostics/2026-09-28-incremental-b-selected.json)

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
