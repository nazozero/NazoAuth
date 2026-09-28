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
- Large raw streams, logs and original journal files for the 2026-09-28 current-B
  run are in its external SHA-256-indexed evidence archive; the compact selected
  snapshots and archive identity are linked from the dated report.
- The incremental report uses separate verified original-container and new-container
  archives. Its gate-replay archive contains native inputs, samplers and terminal
  logs; complete passing mixed journals are separate. Bounded forensic capture
  overflow and unavailable files are explicit, rather than presented as complete streams.
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
