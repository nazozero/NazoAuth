# Performance Documentation

This directory keeps benchmark documentation and durable performance evidence
for NazoAuth. The root of this directory is reserved for stable entry points;
scenario-level reports are grouped below `reports/`.

All reports retain their generation date and source-commit context. They are
historical measurements and regression baselines; none is an implicit claim for
the current release or an unmeasured deployment.

## Entry Points

| Document | Role |
| --- | --- |
| [performance-benchmarks.md](performance-benchmarks.md) | Canonical current baseline: refresh-storage steady state, WAL, audit, stability (Sept 2026 redesign era). |
| [performance-capacity-curve.md](performance-capacity-curve.md) | **Current release capacity matrix** — the only current capacity table; machine-readable form at `perf/results/data/capacity/current-capacity.json`. |
| [reports/2026-09-22-current-capacity](reports/2026-09-22-current-capacity/report.md) | Current capacity evidence report (matrix points, 30m sustained runs, refresh bounds, audit reconciliation). |
| [measurement-accounting.md](measurement-accounting.md) | Successful-operation accounting, prepare-failure classification and observer clock validity. |
| [issuance-maintenance-evidence.md](issuance-maintenance-evidence.md) | Required mature-window expiry-age evidence for single-instance phase-3 acceptance. |

Historical capacity reports under `reports/` retain their generation date
and are regression/root-cause evidence only — none describes the current
release unless it is linked from the entry points above.

## Report Groups

| Group | Directory | Contents |
| --- | --- | --- |
| Special runs | [reports/special](reports/special) | Retained root-cause diagnostics (PG wait events, pool recycling A/B). |

## Evidence Model

- Markdown summaries and scenario reports live under `docs/performance/`.
- Compact structured benchmark results and environment captures live under
  [`../../perf/results`](../../perf/results/) (`data/` for machine-readable
  results, `environments/` for run environment captures, `diagnostics/` for
  retained root-cause evidence — see `perf/results/README.md`).
- Benchmark runner instructions live in [`../../perf/README.md`](../../perf/README.md).
- Retained evidence should be the minimum set needed to reproduce the reported
  numbers: aggregate results, per-point snapshots, run summaries, environment
  metadata, and focused failure probes when they materially support a claim.
- High-frequency sampler streams, transient driver logs, and checksum manifests
  are run artifacts, not durable Git baselines, when their information is already
  represented in retained structured results.

## Common Semantics

- `oidc_cold_login_refresh` includes a fresh Argon2 password login in every
  flow.
- `oidc_logged_in_authorization_code` keeps a session per VU after warm-up and
  measures authorization-code work without per-flow password verification.
- `oidc_refresh_only` uses pre-seeded refresh tokens and measures refresh
  rotation only; password login is intentionally excluded from this scenario.
- `fapi2_logged_in_high_security` keeps a session per VU after warm-up and
  measures PAR, signed request object, `private_key_jwt`, and DPoP
  authorization-code and refresh work without per-flow password verification.
- Per-core normalization uses observed Docker CPU percent for the NazoAuth
  service: `100%` equals one effective CPU core.

## Maintenance Rules

- Keep stable reader entry points in this directory root.
- The current capacity matrix lives only in
  [performance-capacity-curve.md](performance-capacity-curve.md) +
  `perf/results/data/capacity/current-capacity.json`; do not add parallel
  matrices that could be mistaken for the current baseline.
- Put one-off CPU, single-instance, or experiment reports under
  `reports/special/`.
- Keep only compact structured results and environment captures required to
  verify a retained report in `perf/results/`; do not commit redundant sampler
  streams, transient logs, or checksum lists by default.
- Temporary paths in old environment captures describe that run, not a current
  deployment recipe; use `perf/README.md` for current runner commands.
- Update [performance-capacity-curve.md](performance-capacity-curve.md) and
  `current-capacity.json` when adding a durable scenario report.
