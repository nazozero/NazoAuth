//! Multipart parsing driven on the caller's task, including local HTTP streams.

use std::{convert::Infallible, future::Future, pin::Pin, sync::Mutex, task::Poll};

use bytes::Bytes;
use futures_util::Stream;
use http::{StatusCode, header};

use crate::http::{Request, Response, oauth_error};

pub const HEADER_READ_LIMIT: usize = 64 * 1024;
pub const INPUT_CHUNK: usize = 16 * 1024;

#[derive(Default)]
pub struct Input {
    pub chunk: Option<Bytes>,
    pub eof: bool,
}

/// Multer requires a Send input, although it never moves the input to another
/// task. This borrowed slot supplies one Bytes chunk at a time; the caller polls
/// its actual stream only after the parser needs input. No task or channel is
/// involved, and Bytes keeps its original allocation.
pub async fn drive<S, E, F, T>(
    input: &Mutex<Input>,
    mut source: Pin<&mut S>,
    pending: &mut Bytes,
    mut budget: usize,
    operation: F,
) -> Result<T, Response>
where
    S: Stream<Item = Result<Bytes, E>>,
    F: Future<Output = multer::Result<T>>,
{
    let mut operation = std::pin::pin!(operation);
    std::future::poll_fn(|cx| {
        loop {
            if let Poll::Ready(result) = operation.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(|_| invalid_read()));
            }
            if budget == 0 {
                return Poll::Ready(Err(invalid_read()));
            }
            if pending.is_empty() {
                match source.as_mut().poll_next(cx) {
                    Poll::Ready(Some(Ok(chunk))) => *pending = chunk,
                    Poll::Ready(Some(Err(_))) => return Poll::Ready(Err(invalid_read())),
                    Poll::Ready(None) => {
                        input.lock().expect("multipart input lock").eof = true;
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            let length = pending.len().min(INPUT_CHUNK).min(budget);
            budget -= length;
            input.lock().expect("multipart input lock").chunk = Some(pending.split_to(length));
        }
    })
    .await
}

pub async fn read_avatar<S, E>(
    request: &Request,
    source: S,
    max_bytes: usize,
) -> Result<Vec<u8>, Response>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    let boundary = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| multer::parse_boundary(value).ok())
        .ok_or_else(invalid_read)?;
    let input = Mutex::new(Input::default());
    let parser_stream = futures_util::stream::poll_fn(|_| {
        let mut input = input.lock().expect("multipart input lock");
        if let Some(chunk) = input.chunk.take() {
            Poll::Ready(Some(Ok::<_, Infallible>(chunk)))
        } else if input.eof {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    });
    let mut parser = multer::Multipart::new(parser_stream, boundary);
    let mut source = std::pin::pin!(source);
    let mut pending = Bytes::new();
    while let Some(mut field) = drive(
        &input,
        source.as_mut(),
        &mut pending,
        HEADER_READ_LIMIT,
        parser.next_field(),
    )
    .await?
    {
        let disposition = field
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("form-data"));
        let name = field.name().ok_or_else(invalid_read)?;
        if !disposition {
            return Err(invalid_read());
        }
        let is_avatar = name == "avatar";
        let mut bytes = Vec::new();
        while let Some(chunk) = drive(
            &input,
            source.as_mut(),
            &mut pending,
            usize::MAX,
            field.chunk(),
        )
        .await?
        {
            if is_avatar {
                if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err(oauth_error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "invalid_request",
                        "Avatar file is too large.",
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
        }
        if is_avatar {
            return Ok(bytes);
        }
    }
    Err(oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Missing avatar file.",
    ))
}

pub fn invalid_read() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Failed to read avatar file.",
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/endpoints/avatar_multipart.rs"]
mod tests;
