# OAuth Provider App-CPU Affinity Comparison

This report aggregates the comparable client_credentials App CPU affinity points across NazoAuth, Keycloak, and Ory Hydra.

## Method

- Request shape: client_credentials token request with client_id, client_secret, and scope=profile encoded as application/x-www-form-urlencoded.
- Client authentication: client_secret_post.
- Infrastructure: PostgreSQL and k6 are not CPU-quota limited; only the authorization-server process is constrained by taskset affinity.
- Current completed stage: 1 application core, target rates 1000 and 2000 flow/s.

## 1 Application Core

| Target Rate | Provider | Status | HTTP RPS | Observed/Target | Dropped Iterations | p99 ms | Error Rate | App CPU Cores Avg | HTTP RPS/App Core |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1000 | NazoAuth | passed | 999.973 | 1.000 | 0 | 1.561 | 0.000000 | 0.636 | 1572.656 |
| 1000 | Keycloak | failed | 485.428 | 0.485 | 58240 | 12111.936 | 0.000000 | 1.000 | 485.185 |
| 1000 | Ory Hydra | failed | 65.992 | 0.066 | 111809 | 60001.029 | 1.000000 | 0.276 | 238.738 |
| 2000 | NazoAuth | target_miss | 1496.246 | 0.748 | 56533 | 2885.191 | 0.000000 | 0.929 | 1611.223 |
| 2000 | Keycloak | failed | 484.858 | 0.242 | 178351 | 13612.997 | 0.000000 | 1.000 | 484.669 |
| 2000 | Ory Hydra | failed | 67.098 | 0.034 | 231809 | 60001.034 | 1.000000 | 0.259 | 259.236 |

## Source Reports

- docs/performance-capacity-curve-app-cpu-taskset-1cpu-5k.md
- docs/performance-keycloak-comparison-keycloak-app-cpu-taskset-1cpu-5k.md
- docs/performance-hydra-comparison-hydra-app-cpu-taskset-1core-oauth-compare.md
