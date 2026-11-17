//! Select the host's immutable tenant snapshot from actual HTTP authority.
use actix_web::{
    dev::RequestHead,
    http::{Version, header::HOST, uri::Authority},
};
use nazo_identity::canonical_tenant_host;
pub(crate) fn canonical_request_host(request: &RequestHead) -> Option<String> {
    let header_authority;
    let authority = if request.version < Version::HTTP_2
        && let Some(value) = request
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
    {
        header_authority = value.parse::<Authority>().ok()?;
        &header_authority
    } else {
        request.uri.authority()?
    };
    if authority.as_str().contains('@') {
        return None;
    }
    canonical_tenant_host(authority.host()).ok()
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap/host.rs"]
mod tests;
