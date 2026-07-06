# NazoAuth vs Keycloak App-CPU 1 vCPU Smoke Benchmark

Generated at: `2026-07-06 15:22:47 UTC`

This report compares only the `client_credentials` token endpoint path under a single application CPU quota. It is not a full OAuth/OIDC feature comparison.

## Test Environment and Topology

| Field | Value |
| --- | --- |
| Source commit | 142d19964503946346dcc0992544ebded3a24d36 |
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
| Infra CPU model | PostgreSQL and k6 are not CPU-quota limited by this benchmark override. |
| Duration per point | 2m |
| Rates | 100,250,500 |

## Method

- NazoAuth result source: `perf/results/capacity-app-cpu-1vcpu-smoke.json`.
- Keycloak result source: `perf/results/keycloak-app-cpu-1vcpu-smoke.json`.
- Both sides use fixed-arrival-rate k6 traffic and the same target rates: 100, 250, and 500 requests per second.
- Keycloak runs with PostgreSQL and a Docker CPU quota of 1 CPU on the Keycloak container only. PostgreSQL and k6 are intentionally left unrestricted, matching the NazoAuth app-CPU smoke-test shape.
- The comparison uses HTTP RPS, p50/p95/p99 latency, error rate, and observed application CPU from Docker stats.

## Keycloak Result

| Target Rate | Status | HTTP RPS | p50 ms | p95 ms | p99 ms | Error Rate | Keycloak CPU Cores Avg | HTTP RPS/App CPU Core | Postgres CPU Avg % |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | passed | 100.007 | 1.579 | 2.670 | 4.731 | 0.000000 | 0.363 | 275.676 | 1.876 |
| 250 | passed | 250.004 | 1.199 | 1.913 | 2.886 | 0.000000 | 0.491 | 508.955 | 3.493 |
| 500 | passed | 500.000 | 1.201 | 1.763 | 2.693 | 0.000000 | 0.763 | 655.394 | 4.478 |

## Comparison

| Target Rate | NazoAuth RPS | NazoAuth p95 ms | NazoAuth p99 ms | NazoAuth CPU Cores Avg | NazoAuth RPS/App Core | Keycloak RPS | Keycloak p95 ms | Keycloak p99 ms | Keycloak CPU Cores Avg | Keycloak RPS/App Core | Observed RPS Ratio | App-Core Efficiency Ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 99.999 | 1.099 | 1.217 | 0.085 | 1173.973 | 100.007 | 2.670 | 4.731 | 0.363 | 275.676 | 1.000x | 4.259x |
| 250 | 250.004 | 1.039 | 1.149 | 0.198 | 1264.626 | 250.004 | 1.913 | 2.886 | 0.491 | 508.955 | 1.000x | 2.485x |
| 500 | 500.001 | 0.997 | 1.110 | 0.381 | 1312.098 | 500.000 | 1.763 | 2.693 | 0.763 | 655.394 | 1.000x | 2.002x |

## Interpretation

- This is a short smoke benchmark. It is suitable for checking the single-core token endpoint order of magnitude, but it does not replace the 30-minute sustained capacity matrix.
- The tested rates are fixed arrival-rate targets. When both systems meet the target, observed RPS is target-limited and should not be interpreted as maximum throughput.
- Under target-limited points, latency and HTTP RPS per observed application CPU core are the more meaningful comparison fields.
- Keycloak is a broad IAM product with administrative, realm, federation, theme, and policy surfaces that are outside this narrow endpoint test.
- The test intentionally avoids TLS, clustering, external caches, custom providers, and production Keycloak tuning so that the result remains simple and reproducible.
