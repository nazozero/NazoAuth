#![forbid(unsafe_code)]
//! A native Hyper host for the public NazoAuth embedding contract.

use std::{
    error::Error,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt, future::Either};
use http::{Request, Response, header};
use http_body_util::{BodyExt, Full};
use hyper::{body::Body, service::Service};
use nazoauth::{
    NazoAuth, NazoAuthBuilder, capabilities::Capabilities, config::Configuration,
    integration::BodyMode,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};

/// Prepare one tenant with the embedding application's actual I/O capabilities.
pub async fn build(
    configuration: Configuration,
    capabilities: Capabilities,
    instance_id: impl Into<String>,
    prefix: &str,
) -> anyhow::Result<Arc<NazoAuth>> {
    Ok(Arc::new(
        NazoAuthBuilder::new(configuration, capabilities, instance_id)
            .mount_path(prefix)
            .build()
            .await?,
    ))
}

/// Mount the complete authentication surface in an existing Hyper service.
///
/// `occupied_paths` lists the existing service's literal path namespaces. The
/// mount checks them once and preserves those handlers, including at `/`.
/// Supply connection facts through request extensions at the listener boundary.
/// The host continues to own TLS, UI assets, tasks and all I/O capabilities.
pub fn mount<S, B>(
    application: Arc<NazoAuth>,
    existing: S,
    occupied_paths: &[&str],
) -> anyhow::Result<
    impl Service<Request<B>, Response = Response<Full<Bytes>>, Error = S::Error, Future: Send>
    + Clone
    + use<S, B>,
>
where
    S: Service<Request<B>, Response = Response<Full<Bytes>>> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    application.mount().check_conflicts(occupied_paths)?;
    let existing_root_paths: Arc<[String]> = if application.mount().path() == "/" {
        occupied_paths
            .iter()
            .map(|path| path.trim_end_matches('/').to_owned())
            .collect()
    } else {
        Arc::from([])
    };
    Ok(hyper::service::service_fn(move |request: Request<B>| {
        let is_existing = existing_root_paths.iter().any(|prefix| {
            request
                .uri()
                .path()
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        });
        if is_existing || !application.mount().owns_path(request.uri().path()) {
            return Either::Left(existing.call(request));
        }
        let application = application.clone();
        Either::Right(async move {
            let body_mode = application
                .route_for_path(request.uri().path())
                .map_or(BodyMode::None, |route| route.body(request.method()));
            Ok(forward_response(
                application
                    .handle_stream(forward_request(request, body_mode))
                    .await,
            ))
        })
    }))
}

/// Keep the standard request head and raw target. Only declared decoded bodies
/// pass through a streaming content decoder; every other body keeps its chunks.
pub fn forward_request<B>(
    request: Request<B>,
    mode: BodyMode,
) -> Request<impl Stream<Item = Result<Bytes, io::Error>> + Send>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    let encoding = request
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    let encoding = if mode.decode_content() {
        ["gzip", "deflate", "br", "zstd"]
            .into_iter()
            .find(|candidate| encoding.eq_ignore_ascii_case(candidate))
    } else {
        None
    };
    request.map(move |body| {
        let source = body.into_data_stream().map_err(io::Error::other);
        let Some(encoding) = encoding else {
            return Either::Left(source);
        };
        let mut first_brotli_chunk = encoding == "br";
        let source = source.map(move |chunk| {
            let chunk = chunk?;
            if first_brotli_chunk && !chunk.is_empty() {
                first_brotli_chunk = false;
                // Standard Brotli WBITS occupies 1–7 bits. 0x11 selects the
                // large-window extension, which Actix also rejects.
                if chunk[0] & 0x7f == 0x11 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Brotli large window is not supported",
                    ));
                }
            }
            Ok(chunk)
        });
        let source = StreamReader::new(Box::pin(source));
        let decoder: Pin<Box<dyn AsyncRead + Send>> = match encoding {
            "gzip" => Box::pin(DecodeToEof {
                decoder: GzipDecoder::new(source),
                source: GzipDecoder::get_mut,
            }),
            "deflate" => Box::pin(DecodeToEof {
                decoder: ZlibDecoder::new(source),
                source: ZlibDecoder::get_mut,
            }),
            "br" => Box::pin(DecodeToEof {
                decoder: BrotliDecoder::new(source),
                source: BrotliDecoder::get_mut,
            }),
            "zstd" => {
                let mut decoder = ZstdDecoder::new(source);
                decoder.multiple_members(true);
                Box::pin(decoder)
            }
            _ => unreachable!("recognized content encoding"),
        };
        // The facade owns the endpoint-specific overflow response. Supply at
        // most one byte beyond its budget without allocating a large chunk.
        let limit = mode.limit().expect("decoded body limit") + 1;
        Either::Right(ReaderStream::with_capacity(
            decoder.take(limit as u64),
            limit.min(8192),
        ))
    })
}

/// A completed single-member decoder must not hide trailing bytes or I/O errors.
struct DecodeToEof<D, R> {
    decoder: D,
    source: fn(&mut D) -> &mut R,
}

impl<D: AsyncRead + Unpin, R: AsyncBufRead + Unpin> AsyncRead for DecodeToEof<D, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let before = output.filled().len();
        ready!(Pin::new(&mut this.decoder).poll_read(cx, output))?;
        if output.filled().len() != before {
            return Poll::Ready(Ok(()));
        }
        let remaining = ready!(Pin::new((this.source)(&mut this.decoder)).poll_fill_buf(cx))?;
        Poll::Ready(if remaining.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes after compressed body",
            ))
        })
    }
}

/// Move status, repeated headers and the already prepared body into Hyper.
pub fn forward_response(response: Response<Bytes>) -> Response<Full<Bytes>> {
    response.map(Full::new)
}

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
