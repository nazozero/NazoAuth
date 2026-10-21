#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpopErrorContext {
    TokenEndpoint,
    ProtectedResource,
}

/// Header parsing errors are retained until the original DPoP validation point.
#[derive(Clone, Debug)]
pub struct DpopRequestFacts<'a> {
    pub method: http::Method,
    pub path: &'a str,
    /// Original HTTP authority, excluding forwarding headers. It selects one
    /// configured endpoint origin; it never introduces an arbitrary origin.
    pub authority: Option<&'a str>,
    pub proof: Result<Option<&'a str>, nazo_auth::DpopError>,
    pub proof_present: bool,
}
