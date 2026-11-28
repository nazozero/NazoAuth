#![cfg(not(target_arch = "wasm32"))]

use std::{convert::Infallible, rc::Rc};

use bytes::Bytes;
use futures_util::stream;
use http::Request;
use nazoauth::NazoAuth;

fn assert_send<T: Send>(_: T) {}

#[test]
fn native_requests_can_run_on_a_send_executor() {
    // Type-check the real dispatch graph without constructing storage fixtures.
    let _: fn(&NazoAuth) = |application| {
        assert_send(application.handle(Request::new(Bytes::new())));
        let body = stream::once(async { Ok::<_, Infallible>(Bytes::new()) });
        assert_send(application.handle_stream(Request::new(body)));
    };
    fn assert_shared<T: Send + Sync>() {}
    assert_shared::<NazoAuth>();
}

#[test]
fn local_streams_remain_supported() {
    let _: fn(&NazoAuth) = |application| {
        let local = Rc::new(Bytes::new());
        let body = stream::once(async move { Ok::<_, Infallible>((*local).clone()) });
        // Actix and single-threaded hosts keep their non-Send body stream.
        drop(application.handle_stream(Request::new(body)));
    };
}
