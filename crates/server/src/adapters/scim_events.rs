use std::time::Duration;

use nazo_scim_events::{
    EventFuture, EventPollerPort, EventReceiver, PollError, PollResponse, ValidatedPollRequest,
};

/// Native waiting for the existing SET poll capability. HTTP authorization and
/// response policy remain in the neutral endpoint.
pub(crate) struct ScimEventLongPoll<P> {
    events: P,
}

impl<P> ScimEventLongPoll<P> {
    pub(crate) fn new(events: P) -> Self {
        Self { events }
    }
}

impl<P: EventPollerPort> EventPollerPort for ScimEventLongPoll<P> {
    fn poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<PollResponse, PollError>> {
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            let mut response = self.events.poll(receiver, request).await?;
            if request.return_immediately {
                return Ok(response);
            }
            // Dispositions belong to the first read only. Later polls borrow
            // this empty request without copying the caller's ACKs or errors.
            let next = ValidatedPollRequest {
                max_events: request.max_events,
                return_immediately: false,
                ack: Vec::new(),
                set_errors: Default::default(),
            };
            while response.sets.is_empty()
                && !response.more_available
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
                response = self.events.poll(receiver, &next).await?;
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/scim_events.rs"]
mod tests;
