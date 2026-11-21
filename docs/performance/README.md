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

Build every compared revision before generating the shared synthetic fixture.
Use the current candidate's already-built standalone example and a new output
path:

```sh
mkdir -p perf/results
NAZO_MDOC_ACTION=prepare-fixture \
NAZO_MDOC_PERF_FIXTURE="$PWD/perf/results/mdoc-shared-fixture.json" \
./target/release/examples/mdoc_http_performance
```

Preparation writes version 4 only after a complete native issuance and
verification succeeds. It creates a persisted key-management generation,
OS-seeded wrapping, persistence and holder keys, two independent 256-bit protocol
nonces, and a synthetic DS/IACA certificate pair using the native certificate
backend. The DS has the mdoc purpose, critical KeyUsage, SKI/AKI, contact and CRL
extensions, PrintableString country and bounded validity required by the tested
profile. Required certificate revocation uses an explicit synthetic Good
operator snapshot. The fixture uses local revocation state and synthetic contact
and CRL addresses.

The actual native `CredentialSignerPort` produces the IssuerSigned bytes for
three claims. An independent synthetic wallet splices that complete original
slice unchanged into a Final presentation, records its hash, and signs the
holder proof. `api_nonce` and `interop_nonce` are generated before all timing and
persisted with their separate client-ID/response-URI contexts. Preparation uses
`create_new`, refuses to overwrite or upgrade an existing file, and writes the
private fixture with mode 0600 on Unix. Every consumer rejects expired or
unsupported fixture versions and mismatched issuer bytes or transcript context.

Reuse this one version 4 fixture in isolated checkouts and build directories.
It expires after 50 minutes; after expiration, generate a new file and repeat
every compared variant. Keep the complete fixture private even though its keys
are synthetic. The historical ignored library-test helper is not used for
fixture generation or native deployment timing.

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
three-claim signed presentation on every revision. The signing metric measures
native port `Ok`-return latency. Check signed outputs through the interoperability
steps below and retain rejections. Signing
includes dropping the returned String; verification records elapsed time before
checking and dropping the verified result. Both variants use identical timing
boundaries. Failures stop the run. Results include the fixture digest, ordered
raw samples and nearest-rank P50/P95/P99, mean, minimum and maximum latency.

These are application-port elapsed times. They exclude HTTP, PostgreSQL,
Valkey, network certificate-status checks and credential-status servers.
The HTTP measurement below includes transport and storage.

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
nonempty and different. Repeat in the reverse direction. This checks the two
application revisions with the synthetic wallet; test production wallet
integrations with the selected wallet implementations.

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
