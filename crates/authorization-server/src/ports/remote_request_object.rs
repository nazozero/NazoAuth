use std::{future::Future, pin::Pin};

pub type RequestObjectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;

pub trait RemoteRequestObjectResolverPort: Send + Sync {
    fn resolve_request_object<'a>(&'a self, uri: &'a str) -> RequestObjectFuture<'a>;
}
