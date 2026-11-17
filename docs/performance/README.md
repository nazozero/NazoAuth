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
generated test material, including OS-generated wrapping, persistence and holder keys.
Reuse that fixture for both revisions in isolated
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

## mdoc OID4VP HTTP response

The ignored `mdoc_http_performance::mdoc_oid4vp_http_latency` test starts a real
TCP listener and measures `POST /openid4vp/response/{id}` through the production
Actix adapter and single-tenant NazoAuth facade. It uses PostgreSQL for retained
requests and atomic encrypted-result persistence, and connects the production
Valkey adapter. Each request has its own transaction, nonce, state and holder
signature. An untimed HTTP GET verifies the persisted authenticated credential;
the runner also checks that a completed transaction rejects replay.

Build both revisions before creating the shared fixture described above. Use
separate empty PostgreSQL databases and the same synthetic fixture, toolchain,
build flags and machine for each revision. The runner applies the normal
database migrations, provisions only its synthetic tenant, and seeds requests
outside the timed interval. Reusing a fixture permits another run in its same
database; a new fixture needs a new empty database because the synthetic issuer
host is already bound to the previous tenant.

```sh
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
NAZO_MDOC_HTTP_OUTPUT="$PWD/perf/results/mdoc-http-candidate.json" \
NAZO_MDOC_HTTP_VARIANT=candidate \
NAZO_MDOC_HTTP_REVISION="$(git rev-parse HEAD)" \
NAZO_TEST_DATABASE_URL=postgresql://localhost/nazo_mdoc_candidate \
NAZO_TEST_VALKEY_URL=redis://localhost:6379/0 \
cargo test --release --locked -p nazo-server --lib \
  mdoc_http_performance::mdoc_oid4vp_http_latency \
  -- --ignored --exact --nocapture --test-threads=1
```

The default is 100 warmup requests followed by 1,000 measured requests at client
concurrency one, with one Actix worker and an HTTP/1.1 keep-alive connection.
`NAZO_MDOC_HTTP_WARMUP` and `NAZO_MDOC_HTTP_SAMPLES` can increase those counts.
Results include the shared fixture and deterministic request-corpus hashes,
individual elapsed times, successful P50/P95/P99, failure details and replay
outcome. A failed response or a mismatched persisted result never counts as a
successful latency sample. Compare results only when both runs report
`valid_performance_comparison: true` and matching corpus hashes.

This workload exercises `direct_post`, issuer and holder ES256 verification,
the Final SessionTranscript, X.509 path validation, DCQL and required certificate
revocation checks against an explicit synthetic operator snapshot. It has no
MSO status reference. It excludes wallet signing, request creation, TLS, JWE,
HAIP policy, the native host's tenant router and remote status retrieval. The
key repository is in memory and uses the same sealed test keyset in both runs;
the measured verifier response does not sign a credential.
