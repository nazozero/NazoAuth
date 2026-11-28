use std::{
    error::Error,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt, future::Either, stream};
use http::{Request, header};
use http_body::Body;
use http_body_util::BodyExt;
use nazoauth::integration::BodyMode;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};

/// Keep the standard request head and raw target. Only declared decoded bodies
/// pass through a streaming content decoder; every other body keeps its chunks.
pub(crate) fn forward_request<B>(
    request: Request<B>,
    mode: BodyMode,
) -> Request<impl Stream<Item = Result<Bytes, io::Error>> + Send>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let encoding = if mode.decode_content() {
        let encoding = request
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or("");
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
        // Admission may reject the request without reading its body. Construct
        // the decoder and its buffers only when the facade first polls it.
        Either::Right(
            stream::once(async move {
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
                ReaderStream::with_capacity(decoder.take(limit as u64), limit.min(8192))
            })
            .flatten(),
        )
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

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
