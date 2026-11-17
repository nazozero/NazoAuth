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

## Shared mdoc fixture and native API measurements

Build both revisions before generating the fixture. The ignored
`mdoc_embedded_api_latency` helper can create shared synthetic test material
without measuring it:

```sh
mkdir -p perf/results
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
NAZO_MDOC_PERF_PREPARE_ONLY=1 \
cargo test --release --locked -p nazo-oauth-server --lib \
  mdoc_embedded_api_latency -- --ignored --nocapture
```

The helper writes version 2 with newly generated test material, including
OS-generated wrapping, persistence and holder keys. Upgrade it once using the
current candidate's already-built standalone example:

```sh
NAZO_MDOC_ACTION=prepare-fixture \
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
./target/release/examples/mdoc_http_performance
```

This writes version 3 in place after authenticating the new presentation. It
reads two independent 256-bit nonces directly from the operating system CSPRNG
and persists them as `api_nonce` and `interop_nonce`. It rebuilds the API Final
SessionTranscript and holder proof with the API client ID and response URI;
interop uses its separate retained context. The complete original IssuerSigned
wire slice stays byte for byte identical, with its hash recorded in the fixture.
The preparation step rejects expired fixtures, unexpected shapes, repeated
preparation of version 3 and any failed protocol/trust check. No nonce generation
occurs inside a timed operation.

Reuse the single prepared version 3 fixture in isolated checkouts and build
directories. It expires after 50 minutes; after expiration, regenerate it and
repeat every compared variant. Keep the fixture private even though its keys
are synthetic. The helper's historical timing mode uses a test signer on the
production baseline; it is not the native deployment performance measurement.

The standalone `mdoc_http_performance` example provides `NAZO_MDOC_ACTION=native-api`
for actual `CredentialSignerPort::sign` and `CredentialVerifierPort::verify`
measurements. Its version-specific constructor uses each revision's native
signing adapter, including `TokioMdocDocumentSigner` on the production baseline.
It loads the shared sealed keyset, uses the SAN-bound issuer trust policy and
requires certificate revocation validation against an explicit synthetic Good
operator snapshot for the shared leaf and CA. The authenticated MSO has no
credential status reference.

After building the example with the same release flags on both revisions:

```sh
NAZO_MDOC_ACTION=native-api \
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
NAZO_MDOC_API_OUTPUT="$PWD/perf/results/mdoc-api-candidate.json" \
NAZO_MDOC_HTTP_VARIANT=candidate \
NAZO_MDOC_HTTP_REVISION="$(git rev-parse HEAD)" \
NAZO_MDOC_API_SAMPLES=2000 \
./target/release/examples/mdoc_http_performance
```

The runner performs 100 warmups per operation, then at least 1,000 measurements
of each operation, serially at concurrency one. Signing uses three claims
(`given_name`, `age`, `issuing_country`); verification uses the same separate
two-claim signed presentation (`given_name`, `age`) on every revision. The signing metric is native port `Ok`-return latency, not proof that every
legacy issuer output is protocol-conformant. Inspect actual signed outputs
separately and retain rejections. Signing
includes dropping the returned String; verification records elapsed time before
checking and dropping the verified result. Both variants use identical timing
boundaries. Failures stop the run. Results include the fixture digest, ordered
raw samples and nearest-rank P50/P95/P99, mean, minimum and maximum latency.

These are application-port elapsed times. They exclude HTTP, PostgreSQL,
Valkey, network certificate-status checks and credential-status servers. They
do not replace complete HTTP latency evidence.

## Actual issued-output interoperability

Use `NAZO_MDOC_ACTION=interop-export` with `NAZO_MDOC_INTEROP_OUTPUT` to export
an actual native `CredentialSignerPort::sign` result. The independent synthetic
wallet creates a Final SessionTranscript and device signature, then splices the
complete returned IssuerSigned bytes unchanged into a DeviceResponse. The
export includes hashes and the exact issuer slice offset, and must pass a
same-version verification first.

Run the other revision with `NAZO_MDOC_ACTION=interop-verify`,
`NAZO_MDOC_INTEROP_INPUT` pointing to that export and a separate
`NAZO_MDOC_INTEROP_OUTPUT`. It checks the shared fixture identity, the persisted random interop nonce and
exact issuer slice, verifies with the actual application port, and requires
rejection after changing one bit of that nonce and rebuilding the transcript. Source and verifier variant names must be
nonempty and different. Repeat in the reverse direction. A pair of self-checks
or acceptance of helper-generated fixtures does not establish this contract.
These checks do not claim interoperability with a third-party wallet.

## mdoc OID4VP HTTP response

The standalone `mdoc_http_performance` example starts a real TCP listener and
measures `POST /openid4vp/response/{id}` through the production
Actix adapter and single-tenant NazoAuth facade. It uses PostgreSQL for retained
requests and atomic encrypted-result persistence, and connects the production
Valkey adapter. This POST has no Valkey roundtrip; PostgreSQL is on its timed
request path. Each request has its own transaction, nonce, state and holder
signature. An untimed HTTP GET verifies the persisted authenticated credential;
the runner also checks that a completed transaction rejects replay.

Build both revisions before creating the shared fixture described above. Use
separate empty PostgreSQL databases and the same synthetic fixture, toolchain,
build flags and machine for each revision. The runner applies the normal
database migrations, provisions only its synthetic tenant, and seeds requests
outside the timed interval. Reusing a fixture permits another run in its same
database; a new fixture needs a new empty database because the synthetic issuer
host is already bound to the previous tenant.

The example imports the unchanged native configuration and adapter modules but
does not compile the server's unrelated test tree. Its small capability-wiring
fixture is checked byte for byte against the production assembler before any
request runs. The protocol handlers, persistence adapters and trust checks come
from the production implementation. Run it from an isolated working directory;
the native configuration loader creates its normal generated configuration
secrets there. Use the same directory for both revisions.

```sh
NAZO_MDOC_REPOSITORY="$PWD"
CARGO_PROFILE_RELEASE_PANIC=unwind cargo build --release --locked \
  -p nazo-server --example mdoc_http_performance
mkdir -p "$NAZO_MDOC_REPOSITORY/perf/results/mdoc-http-runtime"
cd "$NAZO_MDOC_REPOSITORY/perf/results/mdoc-http-runtime"
NAZO_MDOC_PERF_FIXTURE="$NAZO_MDOC_REPOSITORY/perf/results/mdoc-shared-fixture.json" \
NAZO_MDOC_HTTP_OUTPUT="$NAZO_MDOC_REPOSITORY/perf/results/mdoc-http-candidate.json" \
NAZO_MDOC_HTTP_VARIANT=candidate \
NAZO_MDOC_HTTP_REVISION="$(git -C "$NAZO_MDOC_REPOSITORY" rev-parse HEAD)" \
NAZO_TEST_DATABASE_URL=postgresql://localhost/nazo_mdoc_candidate \
NAZO_TEST_VALKEY_URL=redis://localhost:6379/0 \
CARGO_PROFILE_RELEASE_PANIC=unwind \
cargo run --release --locked --manifest-path "$NAZO_MDOC_REPOSITORY/Cargo.toml" \
  -p nazo-server --example mdoc_http_performance
```

Use the same panic strategy on both revisions. The commands retain unwinding,
matching the original test harness rather than the production abort artifact,
while retaining release optimization,
thin LTO and one code generation unit. Record any build-profile overrides with
the measurements.

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
