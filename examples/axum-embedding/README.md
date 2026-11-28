# Embed NazoAuth in an existing Axum application

This independent workspace consumes the public `nazoauth` facade and the
`nazo-http-tower` adapter with its `axum` feature. Prepare the tenant's usual
configuration and real host capabilities, choose the issuer's mount path with
`NazoAuthBuilder::mount_path`, and mount the resulting `Arc<NazoAuth>` once:

```rust
use std::net::SocketAddr;
use axum::ServiceExt;

let app = nazo_http_tower::axum::mount(existing_app, auth, &["/api", "/users"])?;

axum::serve(
    listener,
    app.into_make_service_with_connect_info::<SocketAddr>(),
).await?;
```

`existing_app` is the fully configured `axum::Router`, including its state,
handlers, middleware and fallback. The result is a Tower service ready for
Axum's existing listener. This mount performs transport conversion, declared
content decoding, endpoint byte limits and standards-derived discovery routing;
the consuming application does not register authentication endpoints.

The final argument declares existing literal host namespaces because Axum does
not expose its router inventory. Collisions fail during mounting. For a nested
mount such as `/tenant/auth-v2.1_~`, requests outside the authentication prefix
and its exact discovery locations reach the original router, including its
method-not-allowed and fallback handlers. At the root `/`, declared host
namespaces and `/ui` retain their original handlers and fallback; the remaining
root surface belongs to NazoAuth. Configure the public issuer and mTLS endpoint
base with the same mount path. The protected resource metadata location follows
its configured resource identifier independently.

The [`application`](src/lib.rs) function supplies example business handlers,
host-owned UI and a custom fallback, then makes that one mount call. Its `serve`
function uses the application's listener. The host continues to own TLS,
database/state capabilities, background tasks and UI assets.

`into_make_service_with_connect_info::<SocketAddr>()` supplies the actual socket
peer for NazoAuth's connection facts. An authenticated ingress may instead
insert the public `ConnectionFacts` extension; the adapter preserves existing
facts, including shared certificate data. Ordinary forwarding headers cannot
establish trusted facts. Method, raw URI, repeated headers and extensions stay
intact; uncompressed body chunks and response `Bytes` keep their backing storage.

```sh
cargo test --manifest-path examples/axum-embedding/Cargo.toml
cargo test --locked -p nazo-http-tower --features axum
cargo test --locked -p nazo-server --lib facade_conformance::axum_embedding
```

The native fixture uses the existing PostgreSQL/Valkey test configuration and
actual host capabilities. It runs the shared conformance cases at root and
nested prefixes with optional routes present and absent, checks discovery and
namespace conflicts, preserves business routes, UI, fallback and method errors,
and checks compressed input and native `Send` execution. The separate Tower
readiness test preserves pending/error states and calls the exact ready host
instance. Shared transport tests live in `nazo-http-tower`.

See the [Rust embedding guide](../../docs/integration/rust-embedding.md) for
configuration, cookies, authenticated ingress and upstream callbacks.
