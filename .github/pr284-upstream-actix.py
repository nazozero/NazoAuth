from pathlib import Path


def replace(path, old, new, count=1):
    p = Path(path)
    source = p.read_text()
    actual = source.count(old)
    if actual != count:
        raise RuntimeError(f'{path}: expected {count} matches, got {actual}: {old[:90]!r}')
    p.write_text(source.replace(old, new))


replace('Cargo.toml', 'actix-web = "4.19.0"', '''# Keep the native listener on HTTP/1.1 while upstream HTTP/2 uses affected h2 0.3.
# Explicit features preserve the other framework capabilities without enabling http2.
actix-web = { version = "4.19.0", default-features = false, features = ["macros", "compress-brotli", "compress-gzip", "compress-zstd", "cookies", "unicode", "compat", "ws"] }''')
replace('Cargo.toml', '''# Keep Actix, h2 and the facade on shared HTTP 1.x metadata. Retire these coupled
# overrides when stable upstream packages provide the same type graph.
[patch.crates-io]
actix-http = { git = "https://github.com/nazozero/actix-web", rev = "cd9d8e580065d8e285f5835fc5bd75d88dc35482" }
actix-router = { git = "https://github.com/nazozero/actix-web", rev = "cd9d8e580065d8e285f5835fc5bd75d88dc35482" }
''', '[patch.crates-io]\n')

Path('crates/http-actix/src/lib.rs').write_text('''#![forbid(unsafe_code)]
//! Actix registration, connection facts and HTTP value conversion for NazoAuth.
//! All routing, protocol interpretation and endpoint policy belong to the facade.

use std::io;

use actix_web::{
    Error, HttpRequest, HttpResponse,
    body::MessageBody,
    dev::{Decompress, ServiceRequest, ServiceResponse},
    error::PayloadError,
    middleware::Next,
    web,
};
use bytes::Bytes;
use futures_util::{TryStreamExt as _, future::Either};
use nazoauth::{ConnectionFacts, NazoAuth, integration::Route};

/// Register the canonical product surface. Install the already-built tenant as
/// `web::Data<NazoAuth>` in application data, including tenant-selected data.
pub fn configure(config: &mut web::ServiceConfig) {
    config.default_service(web::to(serve));
}

/// Forward transport facts without assembling services or buffering the payload.
pub async fn serve(
    application: web::Data<NazoAuth>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let route = nazoauth::integration::route_for_path(request.uri().path());
    let forwarded = forward_request_for_route(&request, (), route);
    let body_mode = route
        .map(|route| route.body(forwarded.method()))
        .unwrap_or(nazoauth::integration::BodyMode::None);
    let body = forward_payload(&request, payload.into_inner(), body_mode);
    forward_response(application.handle_stream(forwarded.map(|()| body)).await)
}

fn forward_payload(
    request: &HttpRequest,
    payload: actix_web::dev::Payload,
    body_mode: nazoauth::integration::BodyMode,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
    if body_mode.decode_content() {
        Either::Left(
            Decompress::from_headers(payload, request.headers())
                .limit(body_mode.limit().expect("decoded bodies have a limit")),
        )
    } else {
        Either::Right(payload)
    }
    .map_err(payload_error)
}

fn payload_error(error: PayloadError) -> io::Error {
    if matches!(error, PayloadError::Overflow) {
        io::Error::new(io::ErrorKind::FileTooLarge, error)
    } else {
        io::Error::other(error)
    }
}

fn request_header(value: &actix_web::http::header::HeaderValue) -> http::HeaderValue {
    let mut converted = http::HeaderValue::from_bytes(value.as_bytes())
        .expect("validated Actix header value");
    converted.set_sensitive(value.is_sensitive());
    converted
}

fn response_header(value: &http::HeaderValue) -> actix_web::http::header::HeaderValue {
    let mut converted = actix_web::http::header::HeaderValue::from_bytes(value.as_bytes())
        .expect("validated HTTP header value");
    converted.set_sensitive(value.is_sensitive());
    converted
}

/// Convert HTTP 0.2 metadata once; the supplied body keeps its original storage.
/// Raw targets and header bytes are preserved without protocol interpretation.
pub fn forward_request<B>(request: &HttpRequest, body: B) -> http::Request<B> {
    forward_request_for_route(request, body, None)
}

fn forward_request_for_route<B>(
    request: &HttpRequest,
    body: B,
    route: Option<&Route>,
) -> http::Request<B> {
    use actix_web::http::Version;
    let mut forwarded = http::Request::new(body);
    *forwarded.method_mut() = http::Method::from_bytes(request.method().as_str().as_bytes())
        .expect("validated Actix method");
    *forwarded.uri_mut() = request.uri().to_string().parse().expect("validated Actix URI");
    *forwarded.version_mut() = match request.version() {
        Version::HTTP_09 => http::Version::HTTP_09,
        Version::HTTP_10 => http::Version::HTTP_10,
        Version::HTTP_11 => http::Version::HTTP_11,
        Version::HTTP_2 => http::Version::HTTP_2,
        Version::HTTP_3 => http::Version::HTTP_3,
        _ => unreachable!("http 0.2 exposes only these HTTP versions"),
    };
    if let Some(names) = route.and_then(Route::request_headers) {
        for name in names {
            for value in request.headers().get_all(name.as_str()) {
                forwarded.headers_mut().append(name.clone(), request_header(value));
            }
        }
    } else {
        forwarded.headers_mut().reserve(request.headers().len_keys());
        for (name, value) in request.headers() {
            forwarded.headers_mut().append(
                http::HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("validated Actix header name"),
                request_header(value),
            );
        }
    }
    if route.is_none_or(Route::needs_connection_facts) {
        let mut facts = request.conn_data::<ConnectionFacts>().cloned().unwrap_or_default();
        facts.peer_addr = request.peer_addr();
        forwarded.extensions_mut().insert(facts);
    }
    forwarded
}

/// Convert response metadata once and move the existing body bytes into Actix.
pub fn forward_response(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let mut forwarded = HttpResponse::new(
        actix_web::http::StatusCode::from_u16(parts.status.as_u16())
            .expect("validated HTTP status"),
    );
    let mut name = None;
    for (next_name, value) in parts.headers {
        if let Some(next_name) = next_name {
            name = Some(
                actix_web::http::header::HeaderName::from_bytes(next_name.as_str().as_bytes())
                    .expect("validated HTTP header name"),
            );
        }
        forwarded.headers_mut().append(
            name.as_ref().expect("header iterator starts with a name").clone(),
            response_header(&value),
        );
    }
    forwarded.set_body(body).map_into_boxed_body()
}

/// Apply the same neutral security policy to host-owned responses and rejections.
pub async fn security_headers<B: MessageBody>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let defaults = nazoauth::integration::security_headers(request.path());
    let mut response = next.call(request).await?;
    for (name, value) in defaults {
        if !response.headers().contains_key(name.as_str()) {
            response.headers_mut().insert(
                actix_web::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("validated security header name"),
                response_header(value),
            );
        }
    }
    Ok(response)
}

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
''')

p = Path('crates/http-actix/tests/unit/transport.rs')
s = p.read_text()
s = s.replace('.method(request.method().clone())', '.method(actix_web::http::Method::from_bytes(request.method().as_str().as_bytes()).unwrap())')
s = s.replace('builder = builder.append_header((name.clone(), value.clone()));', '''let mut converted = actix_web::http::header::HeaderValue::from_bytes(value.as_bytes()).unwrap();
        converted.set_sensitive(value.is_sensitive());
        builder = builder.append_header((name.as_str(), converted));''')
s = s.replace('.get_all(name)\n                .zip(actual.headers()', '.get_all(name.as_str())\n                .zip(actual.headers()')
s = s.replace('source.as_bytes().as_ptr(), target.as_bytes().as_ptr()', 'source.as_bytes(), target.as_bytes()')
s = s.replace('actual.uri().path_and_query().unwrap().as_str().as_ptr()', 'actual.uri().path_and_query().unwrap().as_str()')
s = s.replace('path.as_str().as_ptr()', 'path.as_str()')
s = s.replace('original.uri().path_and_query().unwrap().as_str().as_ptr()', 'original.uri().path_and_query().unwrap().as_str()')
s = s.replace('http::StatusCode::', 'actix_web::http::StatusCode::')
s = s.replace('matched.body(response.request().method())', 'matched.body(&http::Method::from_bytes(response.request().method().as_str().as_bytes()).unwrap())')
s = s.replace('.append("x-context", http::HeaderValue::from_static("public"));', '''.append("x-context", http::HeaderValue::from_static("public"));
        let mut binary = http::HeaderValue::from_bytes(&[b'x', 0x80, 0xff]).unwrap();
        binary.set_sensitive(true);
        expected.headers_mut().append("x-context", binary);''')
p.write_text(s)

factory = 'crates/server/src/bootstrap/startup/services/factory.rs'
replace(factory, '''    let mut response = HttpResponse::new(status);
    for (name, value) in nazoauth::integration::security_headers(request.path()) {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    request.into_response(response)''', '''    let mut response = http::Response::new(bytes::Bytes::new());
    *response.status_mut() = http::StatusCode::from_u16(status.as_u16())
        .expect("validated Actix status");
    for (name, value) in nazoauth::integration::security_headers(request.path()) {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    request.into_response(nazo_http_actix::forward_response(response))''')
replace(factory, '''    // Keep the existing plaintext listener HTTP/1-only; Actix 4.19 otherwise
    // enables cleartext HTTP/2 detection by default.
    .auto_h2c(false)
''', '''    // Inbound HTTP/2 is not enabled in the native dependency graph.
''')
replace(factory, '    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");', '''    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");
    tracing::info!("inbound HTTP/1.1 only; HTTP/2 is disabled in this build; TLS and mTLS remain supported");''')

bootstrap = 'crates/server/tests/unit/bootstrap.rs'
replace(bootstrap, '        .http2_prior_knowledge()\n', '')
replace(bootstrap, 'assert_eq!(public_response.version(), reqwest::Version::HTTP_2);', 'assert_eq!(public_response.version(), reqwest::Version::HTTP_11);')
replace(bootstrap, '    let identity = reqwest::Identity::from_pem(material.client_identity_pem.as_bytes())', '''    // A default client can offer h2, but these native listeners only serve HTTP/1.1.
    // A client requiring h2 must fail rather than reach the vulnerable legacy backend.
    let h2_only = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .http2_prior_knowledge()
        .timeout(std::time::Duration::from_secs(2))
        .tls_backend_rustls()
        .tls_certs_only([root_certificate.clone()])
        .build()
        .unwrap();
    for address in [public_address, mtls_address] {
        assert!(h2_only.get(format!("https://localhost:{}/probe", address.port()))
            .send().await.is_err(), "native listener accepted HTTP/2");
    }

    let identity = reqwest::Identity::from_pem(material.client_identity_pem.as_bytes())''')

Path('scripts/check_native_transport.py').write_text('''#!/usr/bin/env python3
"""Check the resolved native transport graph, including feature unification."""
import json
import subprocess
import sys


def main():
    host = next(line.split(": ", 1)[1] for line in subprocess.check_output(
        ["rustc", "-vV"], text=True).splitlines() if line.startswith("host: "))
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--format-version", "1", "--locked",
        "--all-features", "--filter-platform", host,
    ], text=True))
    packages = {package["id"]: package for package in metadata["packages"]}
    errors = []
    for node in metadata["resolve"]["nodes"]:
        package = packages[node["id"]]
        name = package["name"]
        if name in {"actix-web", "actix-http", "actix-router"}:
            if not (package.get("source") or "").startswith("registry+"):
                errors.append(f"{name} must use an official registry release")
            if "http2" in node["features"]:
                errors.append(f"{name}/http2 is enabled by feature unification")
        if name == "h2":
            version = tuple(int(part) for part in package["version"].split("-")[0].split("."))
            if version < (0, 4, 16):
                errors.append(f"h2 {package['version']} is affected by RUSTSEC-2026-0258")
    if errors:
        raise SystemExit("\\n".join(errors))
    print("Native transport: official Actix, inbound HTTP/2 disabled, no affected h2 version")


if __name__ == "__main__":
    main()
''')
replace('.github/workflows/code-quality.yml', '      - name: Format\n', '''      - name: Check native transport dependencies
        run: python3 scripts/check_native_transport.py

      - name: Format
''', count=2)

embedding = 'docs/integration/rust-embedding.md'
replace(embedding, '''overrides. `nazo-http-actix` also requires both `actix-http` and `actix-router`
overrides to share HTTP 1.x metadata types with the facade. The `rustls` override
applies to the native host's shared-certificate TLS integration.''', '''overrides. Actix uses official registry releases and requires no Git override.
The `rustls` override applies only to the native host's shared-certificate TLS
integration; it is not a dependency of the neutral facade.

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
needed TLS, macros, compression and cookie features without `http2`. Cargo
features are additive; another dependency can re-enable Actix HTTP/2. Run
`python3 scripts/check_native_transport.py` to check the actual workspace graph,
and verify negotiated ALPN in the deployment. Removing `.auto_h2c(false)` alone
is not a protocol policy; that method only applies to cleartext connections.

### Remaining override exit conditions

The overrides are selected only in the workspace root; the facade does not
select a fork or expose an alternative backend abstraction. Switching sources
requires regenerating the lockfile, checking advisories and running the affected
contracts; it is not guaranteed to be a drop-in operation.

- `rustls`: the native connection-facts adapter uses `peer_certificates_shared`.
  A stable release with this ownership API can replace the pin directly. With
  the existing upstream borrowed `peer_certificates` API, own the chain once per
  connection in this adapter and retain the same neutral certificate facts.
  Re-run direct TLS/mTLS, certificate rotation and connection-boundary tests.
- `mdoc-rs`: replace the pin only with a maintained, advisory-clean release that
  supports the current `coset` and borrowed-transcript contracts. Re-run mdoc
  issuance, presentation, signature and transcript tests, including WASM.
- `passkey-auth`: require an advisory-clean cryptographic dependency graph and
  equivalent registration, authentication and attestation behavior. Re-run
  passkey and attestation tests before replacing the pin.

No mutable upstream branch is used as a release dependency. Prefer official
stable registry releases, with the resulting versions recorded in `Cargo.lock`.''')
replace(embedding, '''The Actix adapter and facade use the same HTTP 1.x metadata types. URI components,
header names and header values share their byte storage; owned response headers
and bodies move into Actix. Header maps still allocate entry storage, and shared
values retain their reference counts. No per-value ownership wrapper or URI text
conversion is needed.''', '''The official Actix adapter uses HTTP 0.2 metadata while the facade uses HTTP 1.x.
The adapter converts the head once, preserving original URI spelling, repeated
header values, opaque bytes and sensitivity flags. URI/header metadata may be
copied across these versions; this is not a fully zero-allocation boundary.
Body chunks, completed response bodies and stored replay bytes retain their
`Bytes` storage. No protocol re-parsing or per-value ownership wrapper is added.''')

p = Path('docs/operations/configuration.md')
p.write_text(p.read_text().rstrip() + '''

## Inbound HTTP versions

The native server uses official Actix releases with inbound HTTP/2 disabled in
the build. Plaintext, direct TLS and direct mTLS listeners serve HTTP/1.1; startup
logs state this explicitly. TLS 1.3 and client-certificate authentication are
unchanged. There is no environment option to activate the affected legacy h2
backend. HTTP/2-only clients must use a safe terminating proxy with HTTP/1.1
upstream and the documented trusted-proxy certificate configuration. Outbound
HTTP clients are independent and may negotiate HTTP/2 using patched dependencies.
See [embedding and dependency contracts](../integration/rust-embedding.md).
''')
p = Path('docs/project/testing.md')
s = p.read_text()
s = s.replace('cargo test -p nazo-http-actix --lib\n', 'python3 scripts/check_native_transport.py\ncargo test -p nazo-http-actix --lib\n', 1)
s = s.replace('The last command uses the ordinary test PostgreSQL and Valkey configuration.', '''The dependency check verifies official Actix sources and rejects feature
unification that re-enables inbound HTTP/2 or an affected h2 version. The direct
TLS/mTLS test verifies HTTP/1.1 negotiation and rejection of an h2-only client.
Metadata conversion tests preserve raw URI/header semantics; only body and replay
bytes require pointer identity across the HTTP 0.2/1.x boundary.

The last command uses the ordinary test PostgreSQL and Valkey configuration.''')
p.write_text(s)

print('Prepared upstream Actix candidate; dependency resolution and compilation still required')
