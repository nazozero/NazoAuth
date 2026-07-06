# NazoAuth vs Keycloak App-CPU 1-Core Affinity Benchmark

Generated at: `2026-07-06 16:38:00 UTC`

This report compares only the `client_credentials` token endpoint path under a single application CPU affinity or quota. It is not a full OAuth/OIDC feature comparison.

## Test Environment and Topology

| Field | Value |
| --- | --- |
| Source commit | 5a2f7a7c35bfa5d8e208aed912542128865917de |
| Keycloak image | quay.io/keycloak/keycloak:26.6.4 |
| Runner tag | cnb:arch:amd64 |
| Observed logical CPUs | 384 |
| Process allowed CPUs | 84-147 |
| Observed CPU model | AMD EPYC 9K65 192-Core Processor |
| Cgroup CPU max | unknown |
| Memory total | 128.00 GiB |
| Workspace disk available | 512G on /workspace |
| Docker server | 27.5.1 |
| Docker compose | 2.33.0 |
| Compose file | docker-compose.keycloak.perf.yml |
| App CPU quota | 1 |
| App process taskset | 84 |
| Infra CPU model | PostgreSQL and k6 are not CPU-quota limited by this benchmark override. |
| Duration per point | 2m |
| Rates | 1000,2000,5000 |

## Method

- NazoAuth result source: `perf/results/capacity-app-cpu-taskset-1cpu-5k.json`.
- Keycloak result source: `perf/results/keycloak-app-cpu-taskset-1cpu-5k.json`.
- Both sides use fixed-arrival-rate k6 traffic and the same target rates: 1000, 2000, 5000 requests per second.
- Keycloak runs with PostgreSQL and an application CPU limiter of quota=1, taskset=84. In this CNB nested-Docker environment, process-level CPU affinity is the effective application limiter. PostgreSQL and k6 are intentionally left unrestricted, matching the NazoAuth app-CPU smoke-test shape.
- The comparison uses HTTP RPS, p50/p95/p99 latency, error rate, and observed application CPU from Docker stats.
- A point is classified as `target_miss` when observed RPS is below 99% of the requested rate or k6 records dropped iterations, even if every completed HTTP request returns successfully.

## Behavior and Fairness Audit

- Both benchmark clients use `grant_type=client_credentials`, confidential client authentication by `client_secret_post`, and request `scope=profile`.
- Both benchmark assertions require HTTP 200 and an access token in the token response; refresh tokens are not expected for this grant.
- Both services issue JWT access tokens in this path, but token claim sets, subject modeling, signing implementation, and default OIDC mappers are implementation-specific and are not forced to be byte-equivalent.
- NazoAuth verifies the benchmark client secret through its `client-secret-v1:<salt>:<HMAC-SHA256>` digest format. Keycloak uses its own confidential-client secret handling. This benchmark compares endpoint behavior and observed resource usage, not identical credential storage internals.
- The load generator, network shape, application CPU affinity, and database-unrestricted topology are aligned. Product scope is not aligned: Keycloak remains a broad IAM server, while this benchmark exercises only the narrow token endpoint path.

## Keycloak Result

| Target Rate | Status | HTTP RPS | Observed/Target | Dropped Iterations | p50 ms | p95 ms | p99 ms | Error Rate | Keycloak CPU Cores Avg | HTTP RPS/App CPU Core | Postgres CPU Avg % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000 | failed | 485.428 | 0.485 | 58240 | 7899.538 | 10695.251 | 12111.936 | 0.000000 | 1.000 | 485.185 | 5.041 |
| 2000 | failed | 484.858 | 0.242 | 178351 | 7865.477 | 11399.882 | 13612.997 | 0.000000 | 1.000 | 484.669 | 3.639 |
| 5000 | failed | 474.639 | 0.095 | 539750 | 8040.128 | 11699.373 | 14306.058 | 0.000000 | 1.001 | 474.316 | 3.158 |

## Comparison

| Target Rate | NazoAuth RPS | NazoAuth Observed/Target | NazoAuth Dropped Iterations | NazoAuth p95 ms | NazoAuth p99 ms | NazoAuth CPU Cores Avg | NazoAuth RPS/App Core | Keycloak RPS | Keycloak Observed/Target | Keycloak Dropped Iterations | Keycloak p95 ms | Keycloak p99 ms | Keycloak CPU Cores Avg | Keycloak RPS/App Core | Observed RPS Ratio | App-Core Efficiency Ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000 | 999.973 | 1.000 | 0 | 1.404 | 1.561 | 0.636 | 1572.656 | 485.428 | 0.485 | 58240 | 10695.251 | 12111.936 | 1.000 | 485.185 | 2.060x | 3.241x |
| 2000 | 1496.246 | 0.748 | 56533 | 2783.614 | 2885.191 | 0.929 | 1611.223 | 484.858 | 0.242 | 178351 | 11399.882 | 13612.997 | 1.000 | 484.669 | 3.086x | 3.324x |
| 5000 | 1508.455 | 0.302 | 415062 | 2777.112 | 2819.933 | 0.974 | 1549.088 | 474.639 | 0.095 | 539750 | 11699.373 | 14306.058 | 1.001 | 474.316 | 3.178x | 3.266x |

## Interpretation

- This benchmark is suitable for checking the single-core token endpoint order of magnitude, but it does not replace the 30-minute sustained capacity matrix.
- The tested rates are fixed arrival-rate targets. When both systems meet the target, observed RPS is target-limited and should not be interpreted as maximum throughput.
- Under target-limited points, latency and HTTP RPS per observed application CPU core are the more meaningful comparison fields.
- Keycloak is a broad IAM product with administrative, realm, federation, theme, and policy surfaces that are outside this narrow endpoint test.
- The test intentionally avoids TLS, clustering, external caches, custom providers, and production Keycloak tuning so that the result remains simple and reproducible.
