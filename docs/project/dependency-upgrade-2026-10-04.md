# Dependency upgrade candidate — 2026-10-04

This candidate upgrades direct requirements to the highest published stable
versions and refreshes each legal transitive Cargo graph. Independent root,
fuzz and audit-receiver locks and Python hash locks are resolved separately.
Manifest lower bounds that were already satisfied by the old lock are recorded
as declaration normalization, not runtime upgrades. The current candidate is
being validated; previous green CI and benchmark results do not validate it.

| Area | Target and useful changes | Compatibility decision |
| --- | --- | --- |
| Rust | [1.99.0](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/) throughout stable builds; edition-2024 inherited feature configuration improvements can help future feature isolation. | Keep existing feature and unsafe-code policy. Fuzz requires the separately published nightly-2026-10-04. |
| HTTP | [Actix HTTP 3.18.12](https://github.com/actix/actix-web/blob/http-v3.18.12/actix-http/CHANGES.md), including upstream Host validation/framing fixes, with the existing h2 0.4 transport patch. [Reqwest 0.13.5](https://github.com/seanmonstar/reqwest/releases/tag/v0.13.5) adds DNS error classification and improves read-timeout handling. | Preserve private-CA and mTLS validation. Keep form/query features explicit; consolidate the old 0.12 test client alias. DNS classification is useful for future bounded transport diagnostics; it does not justify request retries. |
| TLS/crypto | [Rustls 0.23.45](https://github.com/rustls/rustls/releases/tag/v/0.23.45) correctness fixes; latest stable RustCrypto requirements. | No new signing algorithms, certificate bypass or insecure JWT decoding. AES-GCM was already stable in the old lock; replacing its prerelease declaration does not change that old binary. |
| Telemetry | [OpenTelemetry Rust 0.33](https://github.com/open-telemetry/opentelemetry-rust/releases), tracing-opentelemetry 0.34. | Review new exporter retry/message defaults against explicit export and shutdown bounds. These defaults must not alter RequiredAudit or token-exchange semantics. |
| Runtime | [Tokio 1.53.2](https://github.com/tokio-rs/tokio/releases/tag/tokio-1.53.2) concurrency fixes. | Preserve pool size, runtime ownership, transaction cancellation and unknown-commit handling. This upgrade is not evidence of the previous performance regression's cause. |
| Python/cache | Python 3.14.8, cryptography 50.0.2, psycopg 3.3.6, redis-py 8.1.0, blake3 1.0.10; [Valkey 9.1.2](https://github.com/valkey-io/valkey/releases/tag/9.1.2) includes Lua/RESP3/AOF fixes. | Perf clients explicitly retain RESP2 and redis-py 7 timeouts, connection limit and three-retry defaults. Real Lua, seed, ledger and sampler checks must pass on Valkey 9; no longer retries or relaxed gates. RESP3/incremental rehash may be evaluated separately. |
| Load generator | [Go 1.27.1](https://go.dev/dl/) builds the pinned k6 2.3 source with the existing JSON throughput patch. | Revalidate JSON golden/periodic/final-flush output and native counts under the newer Go JSON implementation. Acceptance windows, rates and denominators remain fixed. |
| S3 fixture | Latest public MinIO and mc sources; see [fixture provenance](../../tests/fixtures/minio/README.md). | Build exact upstream releases rather than use a stale legacy image. Keep all S3 tests, bucket setup, task cleanup and loopback binding. Upstream tool module graphs remain fixed by their released source/go.sum. |
| CI/release | Latest immutable CodeQL/install actions, cargo-llvm-cov 0.9.1, Trivy 0.75.0, Cosign 3.1.3. | Keep severity gates, OIDC scopes, immutable images and attestations. No wider suppressions or reduced checks. |

Latest-stable comparisons use the official crates.io and PyPI release APIs and
upstream tags/releases on 2026-10-04. Older transitive majors required by an
upstream semver constraint are reported with their reverse dependency; they
are not force-patched into incompatible APIs. Historical performance evidence
remains unchanged. The failed 19df S11/S21 runs and independent diagnostic
branch are distinct from this upgraded candidate.
