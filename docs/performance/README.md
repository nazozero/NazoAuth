# Performance validation

This directory contains maintained measurement contracts and runner guidance.
Run-specific reports, review findings, task lists, benchmark baselines and raw
results are not source files. Keep them in ignored `perf/results/`, CI artifacts,
or the associated issue/PR, with the tested source revision and configuration.

- [Runner instructions](../../perf/README.md)
- [Successful-operation accounting](measurement-accounting.md)
- [Natural issuance-maintenance measurement](issuance-maintenance-evidence.md)

Record complete-operation latency, successful throughput, errors and dropped
iterations together. Distinguish live retained state, expired eligible backlog,
dead tuples and reusable physical high-water space. Include the tested version, workload and duration with published results.
