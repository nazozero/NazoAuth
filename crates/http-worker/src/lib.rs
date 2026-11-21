#![forbid(unsafe_code)]
//! Cloudflare Workers transport for the public NazoAuth HTTP contract.

use bytes::Bytes;
use http_body_util::Full;

#[cfg(target_arch = "wasm32")]
mod ingress;

#[cfg(target_arch = "wasm32")]
pub use ingress::{RequestBody, direct_ingress_facts, forward_request, serve};

/// Move the facade's complete response into the Workers HTTP body representation.
/// Status, repeated headers and body storage are retained. The SDK performs the
/// required copy into JavaScript memory when the runtime consumes the response.
pub fn forward_response(response: http::Response<Bytes>) -> http::Response<Full<Bytes>> {
    response.map(Full::new)
}
