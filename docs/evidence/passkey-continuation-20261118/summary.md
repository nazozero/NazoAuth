# Passkey continuation: same-host three-way comparison

Workflow run: 44135648844

Six balanced rounds per mode, 5,000 operations per case and round, concurrency one. Values are medians of per-round quantiles, not pooled percentiles. All binaries were compiled before timing; allocation tracing was separate. Hosted-runner observations are not a production SLO or cross-machine comparison.

Baseline: d59b317998e56f4a16a69133d7a854c5c34f795b. Checkpoint: 8260480634fac09e1151ca2b1a9eaa1c02af6f67. Candidate: 6b05844a0cc5f7443e0bec378f904b2c3d39f387 (runtime 84938674306a2ca0b84319e8ee499b61b8f32e84). Baseline uses the archived dependency locks. The baseline and checkpoint use the common harness plus a Signer-trait compatibility import; production source and measurement logic are unchanged.

## native-rustcrypto

| Case | Baseline P50 µs | Checkpoint P50 µs | Candidate P50 µs | P50 vs checkpoint | P95 vs checkpoint | P99 vs checkpoint | Candidate op/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.220 | 0.761 | 0.771 | +1.31% | +1.17% | +2.62% | 1234999 |
| ed25519.authentication_finish | 34.536 | 40.206 | 33.871 | -15.76% | -17.97% | -13.63% | 29208 |
| ed25519.registration_begin | 0.196 | 0.751 | 0.761 | +1.33% | +2.53% | +4.50% | 1248443 |
| ed25519.registration_finish | 2.859 | 5.749 | 5.068 | -11.85% | -11.64% | -16.96% | 193966 |
| es256.authentication_begin | 0.220 | 0.761 | 0.771 | +1.31% | +1.30% | +2.46% | 1227439 |
| es256.authentication_finish | 257.993 | 256.926 | 256.892 | -0.01% | -0.14% | -0.13% | 3860 |
| es256.registration_begin | 0.191 | 0.751 | 0.761 | +1.33% | +2.66% | +2.56% | 1232521 |
| es256.registration_finish | 3.310 | 1.312 | 1.292 | -1.52% | -2.20% | +17.45% | 741959 |
| primitive.ed25519_strict.rustcrypto | 33.826 | 33.716 | 35.999 | +6.77% | +8.12% | +5.62% | 27589 |
| primitive.es256.rustcrypto | 251.348 | 250.617 | 251.233 | +0.25% | +0.62% | +1.13% | 3941 |

## native-aws-lc

| Case | Baseline P50 µs | Checkpoint P50 µs | Candidate P50 µs | P50 vs checkpoint | P95 vs checkpoint | P99 vs checkpoint | Candidate op/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.220 | 0.761 | 0.761 | +0.00% | -0.06% | +0.63% | 1251510 |
| ed25519.authentication_finish | 34.612 | 39.855 | 33.946 | -14.83% | -20.22% | -15.91% | 29098 |
| ed25519.registration_begin | 0.200 | 0.761 | 0.766 | +0.66% | +1.24% | -0.57% | 1248317 |
| ed25519.registration_finish | 2.874 | 5.749 | 5.093 | -11.41% | -11.44% | -7.30% | 193228 |
| es256.authentication_begin | 0.220 | 0.761 | 0.761 | +0.00% | -0.13% | -0.06% | 1248510 |
| es256.authentication_finish | 258.098 | 50.602 | 50.727 | +0.25% | +0.36% | +5.28% | 19480 |
| es256.registration_begin | 0.200 | 0.761 | 0.761 | +0.00% | -1.17% | -1.93% | 1243672 |
| es256.registration_finish | 3.330 | 1.307 | 1.292 | -1.15% | -1.47% | -6.19% | 743784 |
| primitive.ed25519_strict.rustcrypto | 33.795 | 35.334 | 33.740 | -4.51% | -4.73% | -3.51% | 29290 |
| primitive.es256.rustcrypto | 251.433 | 250.582 | 251.408 | +0.33% | +0.37% | +0.19% | 3944 |

## wasi

| Case | Baseline P50 µs | Checkpoint P50 µs | Candidate P50 µs | P50 vs checkpoint | P95 vs checkpoint | P99 vs checkpoint | Candidate op/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ed25519.authentication_begin | 0.420 | 0.997 | 1.002 | +0.50% | +4.99% | +5.34% | 927610 |
| ed25519.authentication_finish | 115.409 | 126.496 | 114.292 | -9.65% | -9.25% | -8.07% | 8552 |
| ed25519.registration_begin | 0.356 | 0.972 | 0.972 | -0.05% | +0.05% | -1.47% | 894915 |
| ed25519.registration_finish | 4.632 | 12.098 | 10.616 | -12.25% | -13.95% | -9.25% | 86944 |
| es256.authentication_begin | 0.425 | 1.016 | 1.026 | +0.98% | +1.40% | +1.28% | 396513 |
| es256.authentication_finish | 604.760 | 601.985 | 602.426 | +0.07% | -0.09% | -0.73% | 1651 |
| es256.registration_begin | 0.525 | 1.157 | 1.157 | +0.00% | +7.13% | +8.66% | 250935 |
| es256.registration_finish | 5.253 | 3.425 | 3.380 | -1.31% | +37.63% | +4.52% | 65824 |
| primitive.ed25519_strict.rustcrypto | 113.977 | 113.566 | 114.106 | +0.48% | +0.45% | +1.48% | 8632 |
| primitive.es256.rustcrypto | 592.010 | 591.109 | 589.432 | -0.28% | -0.37% | -1.27% | 1693 |

