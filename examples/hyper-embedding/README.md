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
public URL. The builder derives the mount path from the issuer and rejects an
inconsistent mTLS path. The mount handles both the
ordinary prefix and the exact standards-derived discovery resources supplied
by `application.mount()`.

List all existing host route namespaces in the last argument. The mount rejects
collisions before serving traffic. At `/`, declared host namespaces retain their
handlers and NazoAuth serves the remaining fallback surface. `/ui` below the
mount belongs to the host: serve the web application there with its matching
asset/navigation base. The host owns the listener, trusted ingress and TLS facts,
configured database/state ports and UI assets. `nazo-runtime-tokio` owns NazoAuth's
task scheduling and lifecycle, shared with the standalone server.
Put `ConnectionFacts` in the request extensions from that authenticated connection
boundary; HTTP request headers are not a substitute.

## Fixed and dynamic runtimes

For a fixed tenant, start `nazo_runtime_tokio::Runtime::fixed(tenant_tasks,
process_workers)` around the listener's lifetime. `TenantTasks` holds the same
prepared application passed to `mount`, its key manager, prepublication window
and CIBA worker. Fixed HTTP dispatch reads that application directly and never
loads a directory or selects a tenant.

Dynamic embedding uses the same `TenantRuntimeRegistry`, authoritative directory
reconciliation and tenant task owner as native deployment:

```rust
use std::sync::Arc;
use nazoauth::runtime::{TenantRuntimeRefresher, TenantRuntimeRegistry};

let tenants = TenantRuntimeRegistry::empty();
let initial = directory.load_active().await?;
let refresher = Arc::new(TenantRuntimeRefresher::new(
    tenants.clone(), directory, directory_cache, tenant_factory,
));
let app = nazoauth_hyper_embedding::mount_dynamic(
    tenants, existing_service, &["/api", "/users"],
)?;
let runtime = nazo_runtime_tokio::Runtime::dynamic(
    refresher, initial, process_workers,
).await?;

// `serve_existing_listener` is the host's accept/drain loop for Hyper services.
runtime.run(serve_existing_listener(listener, app)).await?;
```

`tenant_factory` implements the public `TenantRuntimeBuildPort` and supplies the
configured graph and lifecycle for each authoritative binding. The HTTP adapter
uses each published graph's mount and discovery locations. A directory update
atomically replaces the active mapping; it does not rebuild the host's service.
Reserved business namespaces bypass tenant selection. Other requests select by
actual HTTP authority and authenticated TLS server name; unknown tenants fail
closed. Reservations are also validated for future directory snapshots.
For a selected tenant's host-owned paths, including its UI, the existing service
receives that exact graph as `Arc<NazoAuth>` in the request extensions. It stays
consistent with the selected generation during hot updates; reserved business
namespaces bypass selection and do not receive this extension.

The runtime manages key rotation, runtime-module hot updates, CIBA delivery,
back-channel logout and security-state maintenance. `run` shuts those tasks down
after the host's serving future completes, including on error. The host stops
accepting requests and drains connections before its future completes, allowing
active key writes to finish during shared shutdown. Deployment control uses the
same optional deployment capabilities supplied to the application builder.
Add `nazo-runtime-tokio` alongside the HTTP adapter for these Tokio task owners;
its scheduling does not depend on Hyper or a particular storage backend.

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
