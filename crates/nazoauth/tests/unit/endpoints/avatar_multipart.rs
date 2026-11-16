use super::*;
use futures_executor::block_on;
use futures_util::stream;
use std::{cell::Cell, convert::Infallible, rc::Rc};

fn request() -> Request {
    http::Request::post("/auth/me/avatar")
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=avatar-boundary",
        )
        .body(Bytes::new())
        .unwrap()
}

fn body(fields: &[(&str, &[u8])]) -> Bytes {
    let mut body = Vec::new();
    for (name, bytes) in fields {
        body.extend_from_slice(b"--avatar-boundary\r\nContent-Disposition: form-data; name=\"");
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(b"\"\r\nContent-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--avatar-boundary--\r\n");
    body.into()
}

fn parse(chunks: impl IntoIterator<Item = Bytes>, max: usize) -> Result<Vec<u8>, Response> {
    block_on(read_avatar(
        &request(),
        stream::iter(chunks.into_iter().map(Ok::<_, Infallible>)),
        max,
    ))
}

#[test]
fn multipart_matches_every_two_chunk_split_and_single_byte_chunks() {
    let file = b"before\r\n--avatar-boundarX\r\n--different\rafter\0\xff";
    let wire = body(&[("ignored", b"discard this"), ("avatar", file)]);
    for split in 0..=wire.len() {
        let result = parse([wire.slice(..split), wire.slice(split..)], file.len()).unwrap();
        assert_eq!(result, file, "chunk boundary at {split}");
    }
    let chunks = (0..wire.len()).map(|index| wire.slice(index..index + 1));
    assert_eq!(parse(chunks, file.len()).unwrap(), file);
}

#[test]
fn unrelated_fields_do_not_consume_the_avatar_budget() {
    let large_ignored = vec![b'x'; 256 * 1024];
    let wire = body(&[("ignored", &large_ignored), ("avatar", b"image")]);
    let chunks = (0..wire.len())
        .step_by(1024)
        .map(|offset| wire.slice(offset..(offset + 1024).min(wire.len())));
    assert_eq!(parse(chunks, 5).unwrap(), b"image");
}

#[test]
fn avatar_budget_is_exact_and_stops_reading_on_overflow() {
    assert_eq!(parse([body(&[("avatar", b"12345")])], 5).unwrap(), b"12345");
    assert_eq!(
        parse([body(&[("avatar", b"123456")])], 5)
            .unwrap_err()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let polls = Rc::new(Cell::new(0));
    let counter = polls.clone();
    let prefix = body(&[("avatar", &[b'a'; 64 * 1024])]);
    let source = stream::poll_fn(move |_| {
        counter.set(counter.get() + 1);
        match counter.get() {
            1 => Poll::Ready(Some(Ok::<_, Infallible>(prefix.clone()))),
            _ => panic!("overflow must stop before polling more network data"),
        }
    });
    let response = block_on(read_avatar(&request(), source, 5)).unwrap_err();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(polls.get(), 1);
}

#[test]
fn local_stream_stops_after_first_avatar_field() {
    // Rc proves that the original stream can be !Send. Trailing fields and
    // source errors must not affect an already complete first avatar.
    let observed = Rc::new(Cell::new(false));
    let source = stream::poll_fn({
        let observed = observed.clone();
        move |_| {
            assert!(!observed.replace(true));
            Poll::Ready(Some(Ok::<_, Infallible>(body(&[
                ("avatar", b"first"),
                ("avatar", b"second"),
            ]))))
        }
    });
    assert_eq!(
        block_on(read_avatar(&request(), source, 5)).unwrap(),
        b"first"
    );
    assert!(observed.get());
}

#[test]
fn malformed_headers_boundaries_and_stream_errors_are_read_errors() {
    for wire in [
        b"malformed".as_slice(),
        b"--avatar-boundary\r\nContent-Disposition: form-data; name=\"avatar\r\n\r\nimage\r\n--avatar-boundary--\r\n",
        b"--avatar-boundary\r\nContent-Disposition: attachment; name=\"avatar\"\r\n\r\nimage\r\n--avatar-boundary--\r\n",
        b"--avatar-boundary\r\nContent-Type: image/png\r\n\r\nimage\r\n--avatar-boundary--\r\n",
        b"--avatar-boundary\r\nInvalid header\r\n\r\nimage\r\n--avatar-boundary--\r\n",
        b"--avatar-boundary\r\nContent-Disposition: form-data; name=\"avatar\"\r\n\r\nimage",
    ] {
        let response = parse([Bytes::copy_from_slice(wire)], 100).unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(error["error_description"], "Failed to read avatar file.");
    }
    let source = stream::iter([Err::<Bytes, _>(std::io::Error::other("broken input"))]);
    assert_eq!(
        block_on(read_avatar(&request(), source, 100))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn header_reads_have_a_bounded_budget() {
    let polls = Rc::new(Cell::new(0));
    let counter = polls.clone();
    let source = stream::poll_fn(move |_| {
        let call = counter.get();
        counter.set(call + 1);
        let chunk = if call == 0 {
            Bytes::from_static(
                b"--avatar-boundary\r\nContent-Disposition: form-data; name=\"avatar\"\r\nLong: ",
            )
        } else {
            Bytes::from(vec![b'x'; 1024])
        };
        Poll::Ready(Some(Ok::<_, Infallible>(chunk)))
    });
    assert_eq!(
        block_on(read_avatar(&request(), source, usize::MAX))
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        polls.get() <= 66,
        "malformed headers must not drain the source"
    );
}

#[test]
fn the_same_task_input_slot_preserves_bytes_allocation() {
    let chunk = Bytes::from(vec![7; 100]);
    let address = chunk.as_ptr();
    let source = stream::iter([Ok::<_, Infallible>(chunk)]);
    let mut source = std::pin::pin!(source);
    let input = Mutex::new(Input::default());
    let mut pending = Bytes::new();
    let operation = std::future::poll_fn(|_| match input.lock().unwrap().chunk.take() {
        Some(chunk) => Poll::Ready(Ok(chunk)),
        None => Poll::Pending,
    });
    let result = block_on(drive(
        &input,
        source.as_mut(),
        &mut pending,
        HEADER_READ_LIMIT,
        operation,
    ))
    .unwrap();
    assert_eq!(result.as_ptr(), address);
}
