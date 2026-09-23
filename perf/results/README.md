# Performance Result Artifacts

Machine-readable benchmark artifacts retained for the reports under
[`../../docs/performance/`](../../docs/performance/). Human-readable benchmark
results do not live here.

## Layout

- `data/capacity/` — the current capacity baseline
  (`current-capacity.json`, the machine-readable form of
  `docs/performance/performance-capacity-curve.md`).
- `data/comparisons/` — retained external-implementation comparisons (only if a
  report consumes them).
- `environments/` — per-run environment/topology captures (`<run-suffix>.md`).
- `diagnostics/` — retained root-cause diagnostic evidence (probe runs with
  independent forensic value).
- `.run/` — transient runtime scratch (never committed).

## Retention policy

- Invalid / misconfigured / harness-bug runs → delete.
- Smoke runs fully covered by a later formal run → delete.
- Canonical valid results cited by a retained report → keep.
- Root-cause diagnostics → keep the minimum evidence that supports the cited
  conclusion.
- Raw debug output, intermediates, and duplicates reproducible from retained
  aggregates → do not commit.

The directory is git-ignored by default; retained artifacts are committed via
`git add -f`. The repository root of `perf/results/` must stay free of flat
`*.json` / `environment-*.md` files — a CI guard enforces this.
