# NazoAuth vs Ory Hydra App-CPU Affinity Benchmark

Generated at: `2026-07-06 17:08:57 UTC`

This report compares only the `client_credentials` token endpoint path under application CPU affinity. It is not a full OAuth/OIDC feature comparison.

## Test Environment and Topology

| Field | Value |
| --- | --- |
| Source commit | 05d4a8fcffead42833708d70fc50139b56443bad |
| Provider | Ory Hydra |
| Provider image | docker.io/oryd/hydra:v26.2.0 |
| Runner tag | cnb:arch:amd64 |
| Observed logical CPUs | 384 |
| Process allowed CPUs | 84-147 |
| Observed CPU model | AMD EPYC 9K65 192-Core Processor |
| Cgroup CPU max | unknown |
| Memory total | 128.00 GiB |
| Workspace disk available | 512G on /workspace |
| Docker server | 27.5.1 |
| Docker compose | 2.33.0 |
| Compose file | docker-compose.hydra.perf.yml |
| Token endpoint | /oauth2/token |
| Client authentication | client_secret_post |
| Grant type | client_credentials |
| Scope | profile |
| App CPU quota | 1 |
| App process taskset | 84 |
| Infra CPU model | PostgreSQL and k6 are not CPU-quota limited by this benchmark override. |
| Duration per point | 2m |
| Rates | 1000,2000 |

## Method

- NazoAuth result source: `perf/results/capacity-app-cpu-taskset-1cpu-5k.json`.
- Ory Hydra result source: `perf/results/hydra-app-cpu-taskset-1core-oauth-compare.json`.
- Both sides use fixed-arrival-rate k6 traffic and the same target rates: 1000, 2000 requests per second.
- Both clients send `grant_type=client_credentials`, `client_id`, `client_secret`, and `scope=profile` as `application/x-www-form-urlencoded` request bodies.
- Ory Hydra runs with PostgreSQL and an application CPU limiter of quota=1, taskset=84. In this CNB nested-Docker environment, process-level CPU affinity is the effective application limiter. PostgreSQL and k6 are intentionally left unrestricted.
- The comparison uses HTTP RPS, p50/p95/p99 latency, error rate, and observed application CPU from Docker stats.
- A point is classified as `target_miss` when observed RPS is below 99% of the requested rate or k6 records dropped iterations, even if every completed HTTP request returns successfully.

## Behavior and Fairness Audit

- Both benchmark assertions require HTTP 200 and an access token in the token response; refresh tokens are not expected for this grant.
- Product scope is intentionally not equalized. This benchmark isolates one OAuth2 token endpoint path and does not compare admin APIs, login/consent UI, federation, policy engines, or full OIDC feature coverage.
- Token claim sets, signing implementation, client-secret storage internals, database schema, and background maintenance behavior remain product-specific.
- The load generator, network shape, application CPU affinity, request body, client authentication method, grant type, and database-unrestricted topology are aligned.

## Ory Hydra Result

| Target Rate | Status | HTTP RPS | Observed/Target | Dropped Iterations | p50 ms | p95 ms | p99 ms | Error Rate | Ory Hydra CPU Cores Avg | HTTP RPS/App CPU Core | Postgres CPU Avg % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000 | failed | 65.992 | 0.066 | 111809 | 60000.442 | 60000.972 | 60001.029 | 1.000000 | 0.276 | 238.738 | 0.892 |
| 2000 | failed | 67.098 | 0.034 | 231809 | 60000.372 | 60000.964 | 60001.034 | 1.000000 | 0.259 | 259.236 | 0.844 |

## Comparison

| Target Rate | NazoAuth RPS | NazoAuth Observed/Target | NazoAuth Dropped Iterations | NazoAuth p95 ms | NazoAuth p99 ms | NazoAuth CPU Cores Avg | NazoAuth RPS/App Core | Ory Hydra RPS | Ory Hydra Observed/Target | Ory Hydra Dropped Iterations | Ory Hydra p95 ms | Ory Hydra p99 ms | Ory Hydra CPU Cores Avg | Ory Hydra RPS/App Core | Observed RPS Ratio | App-Core Efficiency Ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000 | 999.973 | 1.000 | 0 | 1.404 | 1.561 | 0.636 | 1572.656 | 65.992 | 0.066 | 111809 | 60000.972 | 60001.029 | 0.276 | 238.738 | 15.153x | 6.587x |
| 2000 | 1496.246 | 0.748 | 56533 | 2783.614 | 2885.191 | 0.929 | 1611.223 | 67.098 | 0.034 | 231809 | 60000.964 | 60001.034 | 0.259 | 259.236 | 22.299x | 6.215x |

## Interpretation

- This benchmark is suitable for checking token endpoint order of magnitude at a fixed application CPU affinity.
- The tested rates are fixed arrival-rate targets. When both systems meet the target, observed RPS is target-limited and should not be interpreted as maximum throughput.
- Under target-limited points, latency and HTTP RPS per observed application CPU core are the more meaningful comparison fields.
- The test intentionally avoids TLS, clustering, external caches, custom providers, and production-specific tuning so that the result remains simple and reproducible.
