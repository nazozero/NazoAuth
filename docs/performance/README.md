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

## Embedded mdoc signing and verification

The ignored `mdoc_embedded_api_latency` test measures the actual
`CredentialSignerPort::sign` and `CredentialVerifierPort::verify` calls. It uses
the normal key-manager path with an in-memory repository, a shared synthetic
signing key and certificate chain, and identical signed presentation bytes.
Verification includes issuer and holder signatures, selective-disclosure
digests, validity, and the application certificate trust path. The fixture has
no MSO status reference and disables certificate revocation policy.

```sh
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
NAZO_MDOC_PERF_OUTPUT="$PWD/perf/results/mdoc-candidate.json" \
NAZO_MDOC_PERF_SAMPLES=2000 \
cargo test --release --locked -p nazo-oauth-server --lib \
  mdoc_embedded_api_latency -- --ignored --nocapture
```

Create the output directory first. The first run creates a fixture containing only newly
generated test material. Reuse that fixture for both revisions in isolated
checkouts and build directories. A fixture expires after 50 minutes; if it has
expired, regenerate it and repeat both revisions. The output includes the
fixture digest, 100 warmup operations, nearest-rank P50/P95/P99, mean latency,
and all sorted samples. Use the same toolchain, build flags, machine and
concurrency, and record the exact revisions with each result.

These are application-port elapsed times at concurrency one. They do not
include HTTP, PostgreSQL, Valkey, network certificate-status checks, or a
credential-status server, and do not replace complete HTTP latency evidence.
The `code-quality` pull-request workflow runs the full test archive against
PostgreSQL and Valkey; those correctness results are separate from performance
measurements.
