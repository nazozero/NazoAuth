# Embed NazoAuth in an existing Axum application

This independent workspace consumes the public `nazoauth` facade and the
`nazo-http-tower` adapter through its standard Tower service-factory contract.
The adapter has no Axum dependency or feature. Prepare the tenant's usual
configuration and real host capabilities, choose the issuer's mount path with
`NazoAuthBuilder::mount_path`, and mount the resulting `Arc<NazoAuth>` once:

```rust
use std::net::SocketAddr;
use axum::serve::IncomingStream;
use nazoauth::ConnectionFacts;
use tokio::net::TcpListener;

let app = nazo_http_tower::mount_make_service(
    existing_app.into_make_service_with_connect_info::<SocketAddr>(),
    auth,
    &["/api", "/users"],
    |connection: &IncomingStream<'_, TcpListener>| ConnectionFacts {
        peer_addr: Some(*connection.remote_addr()),
        ..ConnectionFacts::default()
    },
)?;

axum::serve(listener, app).await?;
```

`existing_app` is the fully configured `axum::Router`, including its state,
handlers, middleware and fallback. Its native make-service prepares the routes
once. The result remains a standard Tower service factory for the existing
listener. This mount performs transport conversion, declared
content decoding, endpoint byte limits and standards-derived discovery routing;
the consuming application does not register authentication endpoints.

The path list declares existing literal host namespaces because Axum does
not expose its router inventory. Collisions fail during mounting. For a nested
mount such as `/tenant/auth-v2.1_~`, requests outside the authentication prefix
and its exact discovery locations reach the original router, including its
method-not-allowed and fallback handlers. At the root `/`, declared host
namespaces and `/ui` retain their original handlers and fallback; the remaining
root surface belongs to NazoAuth. Configure the public issuer and mTLS endpoint
base with the same mount path. The protected resource metadata location follows
its configured resource identifier independently.

The [`application`](src/lib.rs) function supplies example business handlers,
host-owned UI and a custom fallback. Its `serve` function makes that one mount
call and uses the application's listener. The host continues to own TLS,
database/state capabilities, background tasks and UI assets.

The final closure projects the actual connection target into `ConnectionFacts`
once per connection. The shared adapter does not inspect Axum's `ConnectInfo`;
the original make-service continues to provide it to business handlers. An
authenticated ingress may instead insert the public `ConnectionFacts` extension;
the adapter preserves existing facts, including shared certificate data.
Ordinary forwarding headers cannot establish trusted facts. Method, raw URI,
repeated headers and extensions stay
intact; uncompressed body chunks and response `Bytes` keep their backing storage.

```sh
cargo test --manifest-path examples/axum-embedding/Cargo.toml
cargo test --locked -p nazo-http-tower
cargo test --locked -p nazo-server --lib facade_conformance::axum_embedding
```

The native fixture uses the existing PostgreSQL/Valkey test configuration and
actual host capabilities. It runs the shared conformance cases at root and
nested prefixes with optional routes present and absent, checks discovery and
namespace conflicts, preserves business routes, UI, fallback and method errors,
and checks compressed input and native `Send` execution. A real listener test
uses the example's `serve` function and checks both metadata and a business
handler's connection extractor. Tower readiness tests preserve pending/error
states and call the exact ready host instance. Shared transport tests live in
`nazo-http-tower`.

See the [Rust embedding guide](../../docs/integration/rust-embedding.md) for
configuration, cookies, authenticated ingress and upstream callbacks.
