# Embed NazoAuth in an existing Hyper host

This independent crate builds NazoAuth from its public `Configuration` and
`Capabilities`, then mounts the prepared tenant around the host's existing Tower
service. `hyper_util::service::TowerToHyperService` bridges the mounted service
to Hyper and drives Tower readiness. The example uses `nazo-http-tower` for mount
selection and transport conversion; it contains no protocol handlers, endpoint
inventory or content decoder.

```rust
let auth = nazoauth_hyper_embedding::build(
    configuration,
    capabilities,
    "my-instance",
    "/testauth",
).await?;

let app = nazoauth_hyper_embedding::mount(
    auth,
    existing_service,
    &["/api", "/users", "/testauth/ui"],
)?;
```

`existing_service` implements Tower's `Service` for standard HTTP requests and
`Response<Full<Bytes>>`, for example a `tower::service_fn` handler. The returned
`app` implements Hyper's `Service` for the host's listener.

Configure the public issuer as `https://example.com/testauth`, the mTLS endpoint
base with the same path, and the protected resource identifier with its intended
public URL. The builder rejects inconsistent paths. The mount handles both the
ordinary prefix and the exact standards-derived discovery resources supplied
by `application.mount()`.

List all existing host route namespaces in the last argument. The mount rejects
collisions before serving traffic. At `/`, declared host namespaces retain their
handlers and NazoAuth serves the remaining fallback surface. `/ui` below the
mount belongs to the host: serve the web application there with its matching
asset/navigation base. The host continues to own the listener, trusted ingress
and TLS facts, database/state capabilities, UI assets and background tasks.
Put `ConnectionFacts` in the request extensions from that authenticated connection
boundary; HTTP request headers are not a substitute.

The shared Tower adapter moves the `http` 1.x method, URI, repeated headers and
extensions directly into the facade. Uncompressed body chunks and responses
preserve their `Bytes` storage. Its streaming gzip, deflate, Brotli and Zstandard
decoding follows the manifest's body mode and endpoint byte limit; raw and
multipart endpoints retain their original content bytes. Decoder state and
buffers are created only when the facade starts reading.
Decoded inputs must end at a complete compressed stream. As in the Actix host,
gzip, deflate and Brotli accept one member, Zstandard accepts concatenated
frames, and Brotli's large-window extension is rejected.

```sh
cargo test --manifest-path examples/hyper-embedding/Cargo.toml
cargo test --locked -p nazo-http-tower --lib
cargo test --locked -p nazoauth --test native_send
cargo test --locked -p nazo-server --lib facade_conformance::hyper_embedding
```

The last command uses the existing PostgreSQL/Valkey test fixture configuration.
It calls this crate's public builder and mount, runs the shared adapter
conformance kit at `/`, `/testauth` and `/nested/testauth`, checks route conflicts
and preservation of an existing API route, and executes the mounted service on
a native Tokio `Send` task. Shared transport tests live in `nazo-http-tower` and
check raw targets, repeated headers, connection extensions,
zero-copy body storage, bounded decoding, trailing input and Brotli window
limits. The independent workspace command checks that the external consumer
builds with its own dependency resolution. See the
[Rust embedding guide](../../docs/integration/rust-embedding.md)
for issuer, session cookie and upstream callback configuration.
