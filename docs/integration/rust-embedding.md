# Rust embedding and framework adapters

`nazoauth` is the framework-neutral product library. `nazo-server` owns native
configuration loading, PostgreSQL/Valkey connections, listeners, TLS, file and
network adapters, and task scheduling. The distributed executable is named
`nazoauth`. `nazo-http-actix` translates Actix transport values into the public
library contract.

## Dependencies in an external workspace

The `nazo-mdoc` and `nazo-passkey` dependencies select immutable Git revisions
directly in the [workspace manifest](../../Cargo.toml). Embedding workspaces
inherit those dependencies and do not need `[patch.crates-io]` overrides.
Actix uses official registry releases.
The native host also uses official rustls releases. Its connection callback
owns the peer certificate chain once and shares immutable facts across requests;
there is no per-request DER copy. rustls is not a dependency of the neutral facade.

### Native HTTP protocol support

The shipped native host serves HTTP/1.1 on plaintext, TLS and mTLS listeners.
Inbound HTTP/2 is disabled at build time while upstream Actix uses the affected
`h2` 0.3 backend (RUSTSEC-2026-0258). There is no runtime switch to enable it.
TLS 1.3, mTLS, keep-alive, streaming bodies and protocol authentication remain
available. Clients requiring HTTP/2 must use a maintained HTTP/2-terminating
proxy with an HTTP/1.1 upstream, or a separate safe host adapter. Proxy deployments
must retain the documented connection-fact and certificate trust boundaries.
Outbound clients may still use patched HTTP/2 dependencies.

An Actix embedder should use `default-features = false` and explicitly enable its
needed TLS, macros, compression and cookie features without `http2`. Resolve
`actix-http` 3.21.3 or later for the chunked-body and keep-alive timeout fixes. Cargo
features are additive; another dependency can re-enable Actix HTTP/2. Run
`python3 scripts/check_native_transport.py` to check the actual workspace graph,
and verify negotiated ALPN in the deployment. Removing `.auto_h2c(false)` alone
is not a protocol policy; that method only applies to cleartext connections.

### Dependency upgrades

Changing a credential-library revision requires regenerating the lockfile,
checking advisories and running its registration, authentication, issuance or
presentation contracts on native and WASM targets. Keep immutable revisions or
stable registry versions recorded in `Cargo.lock`.

### mdoc adapter contract

`nazo-mdoc` is the protocol core in the `nazozero/nazo-mdoc`
repository. Embedders migrate
once to `nazo_mdoc`, preserve the exact production revision in the workspace
manifest and lockfile, and use `issue` only where credentials are constructed.
The WASM issuer enables its `wasm-js` randomness backend. Upgrades require mdoc
issuance, presentation, status, transcript and WASM regressions.

Before deploying the new verifier, inventory credentials issued by the old
`mdoc-rs` production revision `9dd3ef60fb98b427065d7ad940cfbdd9a400b2bc`.
Its issuer sampled digest identifiers across the full `u32` range;
[ISO/IEC 18013-5:2021 §9.1.2.4](https://law.resource.org/pub/us/cfr/ibr/inc/iec/iec.18013-5.2021.pdf)
requires each value to be smaller than `2^31`. The maintained issuer generates
identifiers within that range, and the verifier rejects larger identifiers in
both IssuerSignedItem and MSO valueDigests. Unconditional acceptance of all old
issuer outputs is therefore not a migration guarantee. Reissue affected
credentials through the authorized issuance flow before relying on the new
verifier. Identifiers participate in signed issuer data: editing or re-encoding
stored credentials cannot repair them. Preserve the strict protocol check.

Direct core callers use `nazo_mdoc::Timestamp` for validity and verification
times. Unix constructors are fallible and preserve ordinary nanoseconds;
RFC 3339 parsing retains whole leap seconds, whose Unix accessors return `None`.
NazoAuth converts its existing application time values at the mdoc boundary.
An authenticated historical whole leap second remains a distinct MSO timestamp;
it is not converted to an ordinary Unix instant to validate a certificate path.

mdoc issuance uses the existing key lease asynchronously: the protocol core
prepares the COSE signing input, `Openid4vcSigningLease` signs it, and the core
completes the credential. There is no separate mdoc signing capability, native
runtime adapter, private-key import or blocking runtime bridge to supply.
Signing material retains the authenticated issuing authority from the selected
lease. The issuer removes configured trust anchors by their exact certificate
identity before building `IssuerAuth.x5chain`; the IACA root is not sent.

The core returns `PendingTrustDocumentRef` after authenticating issuer data, holder
proof and protocol constraints. NazoAuth separately validates the current X.509
path, the configured certificate revocation policy and any authenticated MSO
status reference before returning `VerifiedCredential`. MSO `signed` must be
within the DS certificate's validity interval; live path and certificate
revocation checks use the same current-time observation as MSO validity checks.
The mdoc boundary requires a non-CA Document Signer with a critical
`digitalSignature`-only KeyUsage, critical `1.0.18013.5.1.2` EKU, and a validity
period no longer than 457 days. Its PrintableString country and any required
state must match the actual authenticated issuing CA. Pinning an IACA as a
scoped trust anchor does not authorize that CA to act as a Document Signer.
The shared profile implementation also checks serial, SKI/AKI, issuer contact,
CRL URI and extension constraints; native material admission uses the same
rules. When mDL issuer attributes are disclosed, their country matches DS
country and their jurisdiction matches DS state when present. Unrevealed
attributes remain valid selective disclosures. See the
[protocol responsibility matrix](../protocol/openid4vc-validation.md#mdoc-protocol-and-trust-responsibilities)
for the distinction between these profile checks and path authentication.

`MdocStatusIssuancePolicy::Disabled` is the default and rejects a supplied
status reference. `PublishedTokenStatusList` enables references only when a
configured resolver can authenticate an already published, current list under
the credential's IACA and confirm that the allocated index is active. The
caller owns durable allocation and publication. The shipped issuance endpoints
do not allocate references. Verification preserves authenticated status presence
and rejects unsupported mechanisms; certificate revocation and credential
status are separate checks.

When calling `CredentialVerifierPort` directly for mdoc, construct
`PresentedCredential.mdoc_session_transcript` from the verifier's retained
request context: nonce, full client ID, response URI and actual response
encryption key. The built-in `PresentationService` owns this construction.
Wallet-supplied transcript bytes cannot serve as the expected transcript;
`expected_nonce` and `expected_audience` alone cannot validate an opaque
handover hash. The core checks the supplied CBOR and verifies the holder's
signature against those exact bytes.

### Passkey adapter contract

The integration uses the pinned `nazo-passkey` 0.2 API under `nazo_passkey`. Existing credential JSONB
remains readable without a schema migration or re-registration. Optional UV and
backup history missing from an older record must remain unknown; adapters must
not replace missing history with trusted values. The relational credential ID
and sign counter remain authoritative.

Stored COSE metadata remains subject to its declared schema and usage: when
`key_ops` is present it must permit signature verification. Malformed or
contradictory metadata is not a compatibility exception. Ed25519 uses dalek 3
with the verifier's existing strict acceptance policy over borrowed transcript
parts. Do not enable dalek's `legacy_compatibility` feature in an embedding
application; it relaxes the signature scalar bound.

Custom `PasskeyRepositoryPort` implementations use `update_authentication` to
commit the counter and signed backup facts together. Compare both the expected
counter and prior backup eligibility before writing, and return `Conflict` when
either changed. An authorized `initialize_user_verification` update only promotes
UV history to true; concurrent updates must never revert it. Session creation
follows this successful update. Zero-only counters remain supported, with
one-time ceremony consumption providing replay protection.

`PasskeyLoginFinishCommand::csrf_verified` is a trusted transport fact. Set it
only after validating the existing session cookie's CSRF proof; false preserves
ordinary login without authorizing UV initialization. Do not accept it from the
client JSON. The application separately resolves the session and checks fresh,
independent OTP or recovery-code evidence for the same tenant and user. The
HTTP finish request wraps standard `PublicKeyCredential.toJSON()` output under
`response`. NazoAuth owns this HTTP envelope and the pending-ceremony lifecycle;
`nazo-passkey` supplies the protocol parser and verifier. NazoAuth consumes pending
state once and reports missing, expired or incompatible state through the existing
ceremony-expired response. A fresh begin request uses the current verifier state
without changing stored credentials. See the [passkey guide](../features/passkeys.md)
for the wire format and MFA behavior.

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

The manifest exposes transport metadata. CORS, route guards and method rejection
rules remain internal to the facade.

1. Bind a default request forwarding handler so the facade receives known and
   unknown paths. Keep framework-owned UI resources separate. Use
   `integration::route_for_path(request.uri().path())` to obtain transport
   metadata from the canonical manifest. This lookup does not apply method,
   registration or capability policy. `integration::routes()` exposes the whole
   inventory for mechanical coverage checks.
2. Preserve the original method and URI. `Route::request_headers()` declares
   which request headers the resource consumes: `None` requires every header;
   a list permits forwarding only those names, retaining all their repeated
   values. Forward all headers for unknown paths. Do not rebuild a URL from
   forwarded headers, decode the raw target, collapse duplicate values, parse
   form fields, or deserialize JSON in framework glue.
3. Use the matched resource's `Route::needs_connection_facts()` declaration to
   decide whether to put `ConnectionFacts` in the standard request extensions;
   retain facts for unknown paths. `peer_addr` is the actual socket peer. Supply
   the actual TLS server name and client certificate facts captured from the
   connection. Trusted-proxy interpretation and token binding remain inside
   NazoAuth. The declaration applies to the whole resource, including unsupported
   methods, because admission checks may precede method resolution.
   A host with an authenticated ingress source can supply
   `authenticated_client_ip` when the platform does not expose a socket peer.
   Source-IP budgets and auditing use that fact before considering proxy headers.
   It does not establish a trusted socket peer or certificate trust. Ordinary
   client-supplied forwarding headers cannot populate this field.
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

The official Actix adapter uses HTTP 0.2 metadata while the facade uses HTTP 1.x.
The adapter converts the head once, preserving original URI spelling, repeated
header values, opaque bytes and sensitivity flags. URI/header metadata may be
copied across these versions; this is not a fully zero-allocation boundary.
Body chunks, completed response bodies and stored replay bytes retain their
`Bytes` storage. No protocol re-parsing or per-value ownership wrapper is added.

The four public discovery/authorization-server/protected-resource/JWKS metadata
endpoints consume only `Origin`, `Access-Control-Request-Method` and
`Access-Control-Request-Headers` for CORS, and do not consume connection facts.
Their six manifest resources let adapters omit unused request-header storage and
the connection-facts extension. Host tenant selection still uses the original
request's authority and TLS server name before forwarding. All other resources
retain every header and connection facts, including the credential nonce
resource's IP budget for unsupported methods. The two transport requirements are
independent declarations for the whole resource and are computed from the
manifest at compile time. The standalone `nazo_http_actix::forward_request`
conversion always preserves every header and complete facts; the registered
forwarding handler consumes the resource declarations.

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
`.configure(nazo_http_actix::configure)`. The adapter installs one default
forwarding service and looks up transport metadata with `route_for_path`.
Framework-owned resources, including the native host's static UI, retain their
own handlers. The facade performs its own authoritative lookup for captures,
guards, CORS and method resolution.

The native request observer keeps an Actix route pattern for host-owned resources
and otherwise uses the manifest's canonical `Route::path`; unknown paths and
framework errors are labeled `unmatched`. Catch-all API labels therefore use
`{*tail}`, replacing the adapter's former Actix `{tail:.*}` spelling. The adapter,
facade and observer each use the canonical radix tree; no lookup result or
parameter captures are passed through request extensions.

Apply `nazo_http_actix::security_headers` to host-owned routes; facade responses
already contain the policy. The native host applies it to its static UI and adds
the same defaults when rejecting tenant selection. A multi-tenant host selects
one immutable tenant snapshot before forwarding; it does not rebuild the facade
per request.

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
| Complete registration | `registration_requests()` pairs each request with its expected manifest route. Verify `route_for_path` returns that route, including captured and catch-all paths, and send every case through the production forwarder. Use the public facade comparison to verify the resulting protocol behavior. |
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
