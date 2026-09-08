use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use nazo_http_actix::{RemoteJwksFuture, RemoteJwksResolverPort};
use serde_json::Value;

/// Deterministic in-process resolver used by client-key consumer tests.
///
/// It counts every resolve call and returns a configured document (or a
/// deliberate dependency error), allowing tests to prove both rotation and
/// no-network branches without replacing the production resolver path.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub(crate) struct CountingJwksResolver {
    calls: Arc<AtomicUsize>,
    documents: Arc<Mutex<HashMap<String, Value>>>,
    failure: Arc<Mutex<Option<String>>>,
}

#[allow(dead_code)]
impl CountingJwksResolver {
    pub(crate) fn with_document(uri: impl Into<String>, document: Value) -> Self {
        let resolver = Self::default();
        resolver
            .documents
            .lock()
            .expect("resolver document lock should not be poisoned")
            .insert(uri.into(), document);
        resolver
    }

    pub(crate) fn with_failure(message: impl Into<String>) -> Self {
        let resolver = Self::default();
        *resolver
            .failure
            .lock()
            .expect("resolver failure lock should not be poisoned") = Some(message.into());
        resolver
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl RemoteJwksResolverPort for CountingJwksResolver {
    fn resolve<'a>(&'a self, uri: &'a str, _expected_kid: Option<&'a str>) -> RemoteJwksFuture<'a> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let failure = self
            .failure
            .lock()
            .expect("resolver failure lock should not be poisoned")
            .clone();
        let document = self
            .documents
            .lock()
            .expect("resolver document lock should not be poisoned")
            .get(uri)
            .cloned();
        Box::pin(async move {
            if let Some(message) = failure {
                return Err(message);
            }
            document.ok_or_else(|| "test JWKS URI is not configured".to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn counting_resolver_covers_success_missing_and_failure_paths() {
        let resolver = CountingJwksResolver::with_document(
            "https://client.example/jwks",
            json!({"keys": [{"kid": "rotated"}]}),
        );
        assert_eq!(resolver.calls(), 0);
        let document = resolver
            .resolve("https://client.example/jwks", Some("rotated"))
            .await
            .expect("configured document should resolve");
        assert_eq!(document["keys"][0]["kid"], "rotated");
        let missing = resolver
            .resolve("https://other.example/jwks", None)
            .await
            .expect_err("unknown URI should fail closed");
        assert_eq!(missing, "test JWKS URI is not configured");

        let failing = CountingJwksResolver::with_failure("resolver unavailable");
        let error = failing
            .resolve("https://client.example/jwks", None)
            .await
            .expect_err("configured dependency failure should propagate");
        assert_eq!(error, "resolver unavailable");
        assert_eq!(resolver.calls(), 2);
        assert_eq!(failing.calls(), 1);
    }
}
