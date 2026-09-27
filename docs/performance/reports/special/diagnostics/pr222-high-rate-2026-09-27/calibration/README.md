# Calibration evidence package

This package contains sanitized calibration results for PR #222 high-rate validation. `calibration-evidence.json` records fixed A/B/H identities, task/profile/tool hashes, evaluator outputs, audit/sidecar results, point configuration, and hashes of retained raw point/PGSS files. `process-resource-summary.json` uses only task component process RSS and CPU ticks and excludes host and cgroup-parent values. `resource-profile-final.json` is the frozen common high-load profile. `calibration-report.md` is the corresponding checkpoint report. See `SHA256SUMS` for file integrity.

No raw SQL text, HTTP diagnostic streams, request credentials, key material, or audit journal contents are included.
