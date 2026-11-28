# Embed NazoAuth in an existing Axum application

This independent workspace consumes the public `nazoauth` facade and the
`nazo-http-tower` adapter through its standard Tower service-factory contract.
The adapter has no Axum dependency or feature. Prepare the tenant's usual
configuration and real host capabilities. `NazoAuthBuilder` derives the mount
path from the issuer; mount the resulting `Arc<NazoAuth>` once:

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
call and uses the application's listener. The host supplies its TLS, storage
ports and UI assets. `nazo-runtime-tokio` owns NazoAuth background tasks and
their shutdown, using the same implementation as the standalone server.

## Shared runtime lifecycle

A fixed deployment uses one prepared tenant graph directly. Construct its
`TenantTasks` with that graph, its key manager, prepublication window and CIBA
delivery worker, then start the shared runtime with the process workers:

```rust
let runtime = nazo_runtime_tokio::Runtime::fixed(tenant_tasks.clone(), process_workers)?;
runtime.run(nazoauth_axum_embedding::serve(
    listener,
    tenant_tasks.application().clone(),
)).await?;
```

The fixed adapter performs no tenant selection or registry lookup.
The runtime owns key rotation, runtime-module reconciliation, CIBA delivery,
back-channel logout and security-state maintenance. `run` awaits the listener and
shuts down its tasks before returning the listener's result, including errors.
The listener must stop accepting requests and drain its connections before it
completes; active signing-key writes then finish cooperatively.

For dynamic tenants, supply the configured directory and cache ports and a
`TenantRuntimeBuildPort` that builds each tenant's configured graph and task
owner. The core refresher publishes complete immutable snapshots; the shared
Tokio runtime schedules the same directory reconciliation as the native server.

```rust
use std::sync::Arc;
use nazoauth::runtime::{TenantRuntimeRefresher, TenantRuntimeRegistry};

let tenants = TenantRuntimeRegistry::empty();
let initial = directory.load_active().await?;
let refresher = Arc::new(TenantRuntimeRefresher::new(
    tenants.clone(), directory, directory_cache, tenant_factory,
));
let runtime = nazo_runtime_tokio::Runtime::dynamic(
    refresher, initial, process_workers,
).await?;
runtime.run(nazoauth_axum_embedding::serve_dynamic(
    listener, existing_app, tenants,
)).await?;
```

The example's dynamic helper reserves `/api` and `/users` for the business
router. Other requests select the current graph using the actual HTTP authority
and authenticated TLS server name. Each graph retains its configured prefix and
discovery locations. Tenant additions, replacements and removals become visible
without reconstructing the Axum router; future snapshots must respect the same
host namespace reservations. Missing tenants fail closed. Provide deployment
capabilities through the shared builder when deployment control is enabled.
For a selected tenant's host-owned paths, including its UI, the router receives
that exact graph as `Arc<NazoAuth>` in the request extensions. This preserves the
selected generation during hot updates. Reserved business namespaces bypass
selection and do not receive this extension.

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
service assembly, configuration, cookies, authenticated ingress and upstream
callbacks. Add `nazo-runtime-tokio` alongside the facade and HTTP adapter when
the host uses Tokio scheduling.
