# 2026-07-03 NI-006~NI-011 Official Parallel-Isolated OIDF Results

## Environment

| Field | Value |
| --- | --- |
| Target issuer | `https://auth.nazo.run` |
| Branch | `codex/ni-006-011-oidc-profiles` |
| Workflow | `oidf-conformance-full.yml` |
| Run URL | `https://github.com/nazozero/NazoAuth/actions/runs/28648656293` |
| Workflow head SHA | `056cf7f90061a9054394593ee1fa7b43f5e26b54` |
| Started | `2026-07-03T08:32:55Z` |
| Completed | `2026-07-03T08:50:06Z` |
| Result | `success` |

## Isolation Model

The workflow executed all 20 repository OIDF plans while isolating the
browser-sensitive logout/session plans at the GitHub job boundary:

| Job | Coverage | Isolation | Result |
| --- | --- | --- | --- |
| `oidf-conformance-full` | 18 non-browser-sensitive plans | Single workflow job, runner invoked without `--no-parallel`, export path `oidf-results/concurrent` | `success` |
| `oidf-conformance-browser-isolated (frontchannel...)` | `oidcc-frontchannel-rp-initiated-logout` | Separate matrix job/runner/browser session, invoked with `--no-parallel` | `success` |
| `oidf-conformance-browser-isolated (session-management...)` | `oidcc-session-management-rp-initiated-logout` | Separate matrix job/runner/browser session, invoked with `--no-parallel` | `success` |

This preserves concurrent execution for the 18 plans that are safe to run
together, while preventing shared browser/session state from leaking across the
two logout/session plans.

## Browser-Sensitive Job Totals

| Plan | Plan ID | Runner summary |
| --- | --- | --- |
| `oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | `nNANlyEwVtgIv` | 3 test modules; 87 successes, 0 failures, 0 warnings |
| `oidcc-session-management-certification-test-plan[response_type=code][client_registration=static_client]` | `i4hBkCuFV9Nx9` | 3 test modules; 61 successes, 0 failures, 0 warnings |

## Artifacts

GitHub Actions artifact metadata from run `28648656293`:

| Artifact | ID | Size | Digest | Expires |
| --- | --- | ---: | --- | --- |
| `oidf-conformance-results-concurrent` | `8062044225` | 17827179 bytes | `sha256:85eef0774722c8bf39a322916bad7ad46f07ee7041b9eddd99c48750afb1112c` | `2026-10-01T08:32:56Z` |
| `oidf-conformance-results-frontchannel` | `8061725593` | 30988 bytes | `sha256:ec6c9bf046f6bb5d7cfc5682ea6943dc14831b42ab66bfa5354d80f0117bdf96` | `2026-10-01T08:32:56Z` |
| `oidf-conformance-results-session-management` | `8061727687` | 26215 bytes | `sha256:886818e2116dd01a7a05bf55e829c003a9e9cacc145772f07fda7bd68ed7ddca` | `2026-10-01T08:32:56Z` |
| `oidf-public-plan-configs` | `8061723627` | 51435 bytes | `sha256:9c86d05fd77236c4b5cb5d5410ea9e198c6f3c63dafbf37c7a7eb6bd5113d90d` | `2026-10-01T08:32:56Z` |

The raw artifacts include official suite outputs and rendered test
configuration. Keep only metadata and digests in git; do not commit raw
archives or private rendered configuration.

## Acceptance

This run is the latest recorded official full-matrix regression for the
NI-006~NI-011 branch. It covers the repository's 20-plan OIDF matrix, including
FAPI-CIBA, front-channel logout, and session-management coverage added during
this branch.

