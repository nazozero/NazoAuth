# Rust embedding and framework adapters

`nazoauth` is the framework-neutral product library. `nazo-server` owns native
configuration loading, PostgreSQL/Valkey connections, listeners, TLS, file and
network adapters, and task scheduling. The distributed executable is named
`nazoauth`. `nazo-http-actix` translates Actix transport values into the public
library contract.

## Dependencies in an external workspace

Cargo does not inherit `[patch]` entries from dependencies. Copy the applicable
`[patch.crates-io]` overrides from the [workspace manifest](../../Cargo.toml)
for the NazoAuth revision being consumed into your own workspace-root
`Cargo.toml`. The neutral facade requires the `mdoc-rs` and `passkey-auth`
overrides. `nazo-http-actix` also requires both `actix-http` and `actix-router`
overrides to share HTTP 1.x metadata types with the facade. The `rustls` override
applies to the native host's shared-certificate TLS integration.

## Build one tenant

Create `nazoauth::config::Configuration` with the tenant context, issuer and
client-secret pepper. Its constructor supplies the existing product defaults;
`NazoAuthBuilder::build` validates the completed configuration. Configuration is
plain data and does not read environment variables or files.

```rust
let configuration = nazoauth::config::Configuration::new(
    tenant,
    "https://issuer.example",
    client_secret_pepper,
)?;
let application = std::sync::Arc::new(
    nazoauth::NazoAuthBuilder::new(configuration, capabilities, instance_id)
        .build()
        .await?,
);
```

The host supplies `capabilities::Capabilities`: prepared persistence and
transient-state bindings, keys, password work, audit, outbound documents,
verification email, federation HTTP, module lifecycle and SCIM event delivery.
These are real I/O capabilities. The builder creates the authorization, token,
identity, credential and HTTP endpoint graphs once. A framework adapter receives
the completed `NazoAuth`; it does not construct these graphs.

Optional builder methods install avatar storage, deployment-wide control
identity and tenant membership, and signed mdoc CRL delivery. Deployment controls
remain restricted to their configured control tenant. Host-specific scheduling
calls `plan_reconciliation` and `reconcile_once`; the neutral library does not
spawn a timer or task. Native bounded module drain and SCIM long polling remain
in the corresponding native capabilities.

For a native composition example, see
[`application_capabilities` and startup assembly](../../crates/server/src/bootstrap/startup/services.rs).

## Adapt a Web framework

The adapter contract is `http::Request` / `http::Response`, `bytes::Bytes`,
`integration::ConnectionFacts`, and the canonical route manifest. There is no
framework or runtime trait to implement.

1. Enumerate `integration::routes()` to register all resources with one request
   forwarding handler. Each resource contains its method metadata, body mode and
   registration guard. Bind a forwarding fallback as well so the facade owns
   unknown-path responses. Keep framework-owned UI resources separate.
2. Preserve the original method, URI and repeated header values. In particular,
   do not rebuild a URL from forwarded headers, decode the raw target, collapse
   duplicate headers, parse form fields, or deserialize JSON in framework glue.
3. Use the matched resource's `Route::needs_connection_facts()` declaration to
   decide whether to put `ConnectionFacts` in the standard request extensions;
   retain facts for unknown paths. `peer_addr` is the actual socket peer. Supply
   the actual TLS server name and client certificate facts captured from the
   connection. Trusted-proxy interpretation and token binding remain inside
   NazoAuth. The declaration applies to the whole resource, including unsupported
   methods, because admission checks may precede method resolution.
4. Forward the body with `NazoAuth::handle_stream`. Its input is an ordinary
   `Request<S>` where `S: Stream<Item = Result<Bytes, E>>` and
   `E: Error + Send + Sync + 'static`. The stream may be local and need not be
   `Send`. Route registration, body-header validation and the endpoint's
   pre-body admission checks run before the stream is polled.
5. Move the returned status, repeated headers and `Bytes` into the framework
   response. Preserve redirect locations, challenge headers, cookies, DPoP
   nonces, cache headers and retained replay bytes verbatim.

`NazoAuth::handle(Request<Bytes>)` is the convenience entry point when an embedding
already has the complete body. Request bodies must retain their original bytes;
serializing a parsed JSON or form value changes signed and replay-sensitive input.

### Content decoding and body limits

An adapter with framework-provided content decoding consumes the manifest's
`Route::body(method)` metadata. `BodyMode::decode_content()` distinguishes the
existing decoded JSON/form/byte extractors from raw CIBA/logout and multipart
streams. Use `BodyMode::limit()` to bound the decoder itself before it allocates
an oversized output chunk. Report decoder overflow as
`std::io::ErrorKind::FileTooLarge`; other stream errors remain ordinary errors.
The facade owns the endpoint-specific error response and final byte budget.

Multipart avatar uploads remain incremental. Unrelated fields are skipped, and
the avatar service enforces the uploaded file's bound. The adapter must not
collect the entire multipart body or invent a total upload limit.

The Actix adapter and facade use the same HTTP 1.x metadata types. URI components,
header names and header values share their byte storage; owned response headers
and bodies move into Actix. Header maps still allocate entry storage, and shared
values retain their reference counts. No per-value ownership wrapper or URI text
conversion is needed.

The four public discovery/authorization-server/protected-resource/JWKS metadata
endpoints do not consume connection facts. Their manifest resources let adapters
omit the unused extension allocation. All other resources retain facts, including
the credential nonce resource's IP budget for unsupported methods. The standalone
`nazo_http_actix::forward_request` conversion always preserves complete facts;
the registered forwarding handler consumes the resource declaration.

Uncompressed `Bytes` chunks and completed response bodies retain their storage.
The collector reuses a single chunk and combines chunks only when the endpoint
needs a contiguous body. Content decoding, serialization and combining multiple
chunks perform the work required by their inputs.

### Routing and host response policy

The manifest is the sole endpoint inventory. NazoAuth uses a radix tree to find a
resource, checks process registration separately from tenant capability, applies
CORS, and resolves the method. Path normalization is distinct from the original
URI: ordinary escapes are decoded for matching, while escaped slash, percent and
plus remain protected until parameter extraction. Framework glue does not apply
OAuth or administrative policy to captures.

The facade applies its security headers to every response it produces. Hosts
also need the same policy on listener rejections and static UI responses.
`integration::security_headers(path)` supplies immutable default headers for
that purpose; add only headers not already supplied by the response.

An Actix embedding installs `web::Data::from(application)` and
`.configure(nazo_http_actix::configure)`. The adapter groups the manifest's
resources into path scopes while preserving their complete route patterns and
forwarding unknown paths to the facade. Apply `nazo_http_actix::security_headers`
to host-owned routes; facade responses already contain the policy. The native
host applies it to its static UI and adds the same defaults when rejecting tenant
selection. A multi-tenant host selects one immutable tenant snapshot before
forwarding; it does not rebuild the facade per request.

## Run the adapter conformance kit

Enable the `conformance` feature on the adapter's development dependency:

```toml
[dev-dependencies]
nazoauth = { version = "0.3.9", features = ["conformance"] }
```

`nazoauth::integration::conformance` supplies the reusable checks below. Its
inputs and outputs are standard HTTP types, so the adapter test needs only its
framework's ordinary test client and conversion functions.

| Check | How to run it |
| --- | --- |
| Complete registration | `registration_requests()` pairs each request with its expected manifest route. Send the request through the production router and compare its selected resource with `route.path`, including captured and catch-all paths. |
| Request fidelity | Pass `transport_requests()` through the real request conversion and call `assert_request`; it checks method, raw target, repeated headers, body bytes and connection facts. |
| Response fidelity | Pass each `response_cases()` response through the real framework response conversion and call `assert_response`. The corpus invokes production presenters for redirects, OAuth challenges, cache policy, DPoP nonces, cookies and retained credential JSON/JWT bytes. |
| Public facade equivalence | Build a fresh tenant fixture, then call `assert_adapter(&application, send).await`, where `send` uses the framework's production registration and returns a standard HTTP response. |
| Connection provenance | Use a real listener connection callback to supply TLS facts and verify the converted facts with `assert_request`; supply conflicting forwarded headers to ensure the bridge does not replace connection facts. |
| Stateful replay | Use the host's real credential/token fixture to obtain a retained response and send its replay through the adapter. Use `assert_response` to compare the original bytes, status and headers. |

Run the facade comparison with optional protocols both enabled and disabled and
with process registration independent from tenant enablement. The built-in
request corpus uses invalid methods and unauthenticated/malformed requests to
avoid generating random challenges or performing mutations. The response
comparison ignores only wire-generated `Date`, `Content-Length` and
`Transfer-Encoding`; it does not normalize nonces, reorder duplicate values,
deserialize response JSON, or ignore body differences.

The shipped examples are the
[Actix transport tests](../../crates/http-actix/tests/unit/transport.rs) and
[native facade comparison](../../crates/server/tests/unit/facade_conformance.rs).
The [credential replay fixture](../../crates/server/tests/unit/facade_credentials.rs)
seeds subject data through the configured persistence capability, creates offers
and tokens through the public facade, and verifies original JSON and encrypted
JWT response bytes on repeated calls through both transports.
The `test-support` feature exposes internal services only for the native host's
focused regression tests. Architecture checks reject it in adapter dependencies;
new adapters use `conformance` and the public embedding API.
