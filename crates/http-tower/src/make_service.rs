use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use nazoauth::{ConnectionFacts, NazoAuth};
use pin_project_lite::pin_project;
use tower_service::Service;

use crate::{MountContext, Mounted, Registration};

/// A host's native connection factory with NazoAuth mounted on each service.
#[derive(Clone)]
pub struct MountedMakeService<M, F> {
    existing: M,
    registration: Registration,
    connection_facts: F,
}

/// Mount around the request services returned by a host's connection factory.
///
/// Pass the host's normally prepared make-service. `connection_facts` borrows
/// its connection target once and returns trusted transport facts. Request
/// extensions supplied by authenticated ingress retain precedence. The factory
/// and every resulting request service keep the host's readiness and errors.
/// Path reservations have the same meaning as in [`crate::mount`].
pub fn mount_make_service<M, F>(
    existing: M,
    application: Arc<NazoAuth>,
    occupied_paths: &[&str],
    connection_facts: F,
) -> anyhow::Result<MountedMakeService<M, F>> {
    Ok(MountedMakeService {
        existing,
        registration: Registration::new(application, occupied_paths)?,
        connection_facts,
    })
}

impl<M, F, T> Service<T> for MountedMakeService<M, F>
where
    M: Service<T>,
    F: FnMut(&T) -> ConnectionFacts,
{
    type Response = Mounted<M::Response>;
    type Error = M::Error;
    type Future = MakeServiceFuture<M::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.existing.poll_ready(cx)
    }

    fn call(&mut self, target: T) -> Self::Future {
        let connection_facts = (self.connection_facts)(&target);
        MakeServiceFuture {
            future: self.existing.call(target),
            context: Some(MountContext {
                registration: self.registration.clone(),
                connection_facts: Some(connection_facts),
            }),
        }
    }
}

pin_project! {
    /// The host's connection future followed by mounting its completed service.
    pub struct MakeServiceFuture<F> {
        #[pin]
        future: F,
        context: Option<MountContext>,
    }
}

impl<F, S, E> Future for MakeServiceFuture<F>
where
    F: Future<Output = Result<S, E>>,
{
    type Output = Result<Mounted<S>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let existing = ready!(this.future.poll(cx))?;
        let context = this
            .context
            .take()
            .expect("make-service future polled after completion");
        Poll::Ready(Ok(Mounted {
            existing,
            context: Arc::new(context),
        }))
    }
}
