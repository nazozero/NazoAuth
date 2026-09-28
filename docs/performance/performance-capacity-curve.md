# NazoAuth Current-B Capacity Baseline

Incremental checkpoint: **INCOMPLETE**. Each row is one frozen recipe on its stated deployment. Both modes use one application instance. Old and new deployments are not combined into a bound. A missing service upper means at least the passing load, never a maximum.

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
| `mtls_client_credentials` | original-container | 1 | 250 | not established | 250 | 250 | 4/6/12 | 0/0/0/0 | 180/N/A | at least 250/s |
| `par_signed_request_object` | original-container | 1 | 150 | not established | 150 | 150 | 3/5/11 | 0/0/0/0 | 180/N/A | at least 150/s |
| `oidc_cold_login_refresh` | new-container | 1 | 7 | 8 | 7 | 42 | 131/143/517.68 | 0/0/0/0 | 180/180 | [7, 8) observed |

## Multiple logical CPUs (count per row)

| Scenario | Deployment | App CPUs | PASS L | Service FAIL U | Success ops/s | HTTP req/s | Full P50/P95/P99 ms | Error/drop/reject/unfinished | Window L/U s | Conclusion |
|---|---|---:|---:|---:|---:|---:|---|---|---|---|
| `cap_mixed` | new-container | 16 | 2600 | 2900 | 2600.003 | 3769.056 | 4/18/25 | 0/0/0/0 | 660/660 | [2600, 2900) observed |
| `cap_client_credentials` | new-container | 16 | 6000 | 6500 | 6000.022 | 6000.067 | 4/11/29 | 0/0/0/0 | 180/180 | [6000, 6500) observed |
| `cap_authorization_code` | new-container | 16 | 900 | 1000 | 900 | 3599.553 | 63/92/109 | 0/0/0/0 | 180/180 | [900, 1000) observed |
| `cap_refresh_token` | new-container | 16 | 2624 | 2916 | 2624.006 | 2623.994 | 7/13/26 | 0/0/0/0 | 180/180 | [2624, 2916) observed |
| `fapi2_logged_in_high_security` | original-container | 16 | 320 | not established | 320 | 1600.017 | 24/32/42 | 0/0/0/0 | 180/N/A | at least 320/s |
| `cap_introspect` | original-container | 16 | 16000 | 17000 | 15997.911 | 15997.838 | 1/3/15 | 0/376/0/0 | 180/180 | [16000, 17000) observed |
| `cap_revoke` | original-container | 16 | 480 | not established | 480 | 2400.034 | 18/33/42 | 0/0/0/0 | 180/N/A | at least 480/s |
| `mtls_client_credentials` | original-container | 16 | 4000 | not established | 3998.417 | 3998.553 | 4/9/20 | 0/285/0/0 | 180/N/A | at least 4000/s |
| `par_signed_request_object` | new-container | 4 | 11250 | not established | 11246.033 | 11246.39 | 4/58/93 | 0/224/0/0 | 60/N/A | at least 11250/s |
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
| `oidc_cold_login_refresh` / single | 7.456 | 45.62 | 1123/1227/1247 | 98/0/0/0 | 180 | 98 unexpected logical outcomes at8/s; complete-operation P95/P99 1227/1247ms. The unchanged distinct cold-login gate fails. |
| `cap_mixed` / multi | 2900.006 | 4208.812 | 7/44/78 | 0/0/0/0 | 660 | FAPI sidecar full-operation P95 108 ms exceeds 100 ms; its 22050 offered operations all finish successfully with no drops. |
| `cap_client_credentials` / multi | 6497.539 | 6497.615 | 5/39/331.44 | 0/444/0/0 | 180 | Full-operation P99 331.44 ms exceeds 250 ms; delivery/drop/error/unfinished gates pass. |
| `cap_authorization_code` / multi | 1000 | 4002.492 | 57/156/311 | 0/0/0/0 | 180 | Complete-operation P95/P99 156/311 ms exceed 100/250 ms |
| `cap_refresh_token` / multi | 1728.389 | 1728.274 | 1196/1356/1517 | 0/213769/0/0 | 180 | Full-operation P95/P99 1356/1517 ms exceeds 100/250 ms; 40.7273% offered arrivals drop after VUs become occupied by slow responses. |
| `cap_introspect` / multi | 16707.406 | 16989.581 | 1/4/24 | 50802/1892/0/0 | 180 | 50802 unexpected logical outcomes; retained HTTP429 temporarily_unavailable responses demonstrate the unchanged source-IP management admission limit |
| `oidc_cold_login_refresh` / multi | 55.933 | 335.849 | 172/239/263 | 12/0/0/0 | 180 | 12 unexpected complete-operation outcomes; retained failed HTTP points are POST /auth/login 503 |
