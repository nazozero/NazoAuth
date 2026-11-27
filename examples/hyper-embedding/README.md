# Embed NazoAuth in an existing Hyper host

This independent crate builds NazoAuth from its public `Configuration` and
`Capabilities`, then mounts the prepared tenant into an existing Hyper service.
It contains no protocol handlers or endpoint inventory.

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

The Hyper request already uses `http` 1.x, so its method, URI, repeated headers
and extensions move directly into the facade. Uncompressed body chunks and
responses preserve their `Bytes` storage. Streaming gzip, deflate, Brotli and
Zstandard decoding follows the manifest's body mode and endpoint byte limit;
raw and multipart endpoints retain their original content bytes.
Decoded inputs must end at a complete compressed stream. As in the Actix host,
gzip, deflate and Brotli accept one member, Zstandard accepts concatenated
frames, and Brotli's large-window extension is rejected.

```sh
cargo test --manifest-path examples/hyper-embedding/Cargo.toml
cargo test --locked -p nazoauth --test native_send
cargo test --locked -p nazo-server --lib facade_conformance::hyper_embedding
```

The last command uses the existing PostgreSQL/Valkey test fixture configuration.
It calls this crate's public builder and mount, runs the shared adapter
conformance kit at `/`, `/testauth` and `/nested/testauth`, checks route conflicts
and preservation of an existing API route, and executes the mounted service on
a native Tokio `Send` task. The standalone tests check raw targets, repeated
headers, connection extensions, response bytes, zero-copy body storage,
bounded decoding, trailing input and Brotli window limits. See the
[Rust embedding guide](../../docs/integration/rust-embedding.md)
for issuer, session cookie and upstream callback configuration.
