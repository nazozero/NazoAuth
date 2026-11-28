use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{HeaderMap, header};
use http_body_util::Full;
use nazoauth::{ConnectionFacts, NazoAuth, integration::BodyMode};
use wasm_streams::readable::IntoStream;
use worker::{
    js_sys::{Array, Function, Reflect, Uint8Array},
    wasm_bindgen::JsCast,
};

use crate::forward_response;

/// Read the source address for an explicitly configured direct Cloudflare host.
///
/// The deployment must block Worker subrequests with the WAF rule
/// `cf.worker.upstream_zone ne ""` and not expose service-binding ingress.
/// Cloudflare's platform metadata and generated source header are required;
/// Worker subrequests and Cloudflare's cross-zone placeholder are rejected.
/// The caller decides whether this ingress profile applies and inserts the
/// returned facts. This function does not create socket or certificate facts.
pub fn direct_ingress_facts(request: &worker::HttpRequest) -> io::Result<ConnectionFacts> {
    if request.extensions().get::<worker::Cf>().is_none()
        || request.headers().contains_key("cf-worker")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "direct Cloudflare ingress is required",
        ));
    }
    let mut addresses = request.headers().get_all("cf-connecting-ip").iter();
    let ip = addresses
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .filter(|_| addresses.next().is_none())
        .filter(|ip| *ip != std::net::Ipv6Addr::new(0x2a06, 0x98c0, 0x3600, 0, 0, 0, 0, 0x103));
    let Some(ip) = ip else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated client address is unavailable",
        ));
    };
    Ok(ConnectionFacts {
        authenticated_client_ip: Some(ip),
        ..ConnectionFacts::default()
    })
}

/// Serve every path through the neutral facade, including its 404/405 behavior.
///
/// The SDK supplies standard HTTP values. Connection facts remain absent unless
/// the host inserts independently authenticated `nazoauth::ConnectionFacts` into
/// the request extensions. No forwarding or certificate header becomes a fact.
/// Workers normalizes incoming duplicate headers before this adapter sees them.
pub async fn serve(
    application: &NazoAuth,
    request: worker::HttpRequest,
) -> http::Response<Full<Bytes>> {
    let mode = application
        .route_for_path(request.uri().path())
        .map_or(BodyMode::None, |route| route.body(request.method()));
    forward_response(
        application
            .handle_stream(forward_request_with_mode(request, mode))
            .await,
    )
}

/// Convert a root-mounted request with lazy, bounded body conversion.
///
/// Use [`serve`] with a prepared application for a configured mount prefix.
/// Gzip and deflate are decoded only for the route modes that request decoding.
/// Raw and multipart modes retain wire bytes. Admission in `handle_stream` runs
/// before the body is polled, including before a decompressor is constructed.
pub fn forward_request(request: worker::HttpRequest) -> http::Request<RequestBody> {
    let mode = nazoauth::integration::route_for_path(request.uri().path())
        .map_or(BodyMode::None, |route| route.body(request.method()));
    forward_request_with_mode(request, mode)
}

fn forward_request_with_mode(
    request: worker::HttpRequest,
    mode: BodyMode,
) -> http::Request<RequestBody> {
    let encoding = Encoding::from_headers(request.headers(), mode);
    request.map(|body| RequestBody {
        source: Some(body),
        stream: None,
        pending: None,
        encoding,
        remaining: mode.limit(),
        stopped: mode == BodyMode::None,
    })
}

#[derive(Clone, Copy)]
enum Encoding {
    Identity,
    Gzip,
    Deflate,
    Unsupported,
}

impl Encoding {
    fn from_headers(headers: &HeaderMap, mode: BodyMode) -> Self {
        if !mode.decode_content() {
            return Self::Identity;
        }
        let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
        let Some(value) = values.next() else {
            return Self::Identity;
        };
        if values.next().is_some() {
            return Self::Unsupported;
        }
        let value = value.as_bytes().trim_ascii();
        if value.eq_ignore_ascii_case(b"identity") {
            Self::Identity
        } else if value.eq_ignore_ascii_case(b"gzip") {
            Self::Gzip
        } else if value.eq_ignore_ascii_case(b"deflate") {
            Self::Deflate
        } else {
            Self::Unsupported
        }
    }

    fn decode(self, stream: web_sys::ReadableStream) -> io::Result<web_sys::ReadableStream> {
        let format = match self {
            Self::Identity => return Ok(stream),
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Unsupported => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported request content encoding",
                ));
            }
        };
        // The runtime API is stable; web-sys still gates its typed constructor
        // behind web_sys_unstable_apis. Reflect invokes the same platform API.
        let constructor = Reflect::get(&worker::js_sys::global(), &"DecompressionStream".into())
            .and_then(|value| value.dyn_into::<Function>())
            .map_err(|_| io::Error::other("request decompression is unavailable"))?;
        let decoder = Reflect::construct(&constructor, &Array::of1(&format.into()))
            .map_err(|_| io::Error::other("request decompression failed"))?;
        let pair: web_sys::ReadableWritablePair = decoder.unchecked_into();
        Ok(stream.pipe_through(&pair))
    }
}

/// A local Workers byte stream. Each JavaScript chunk is checked before copying
/// into WASM memory; the resulting Vec allocation moves directly into `Bytes`.
/// Multipart remains incremental without a transport-wide upload size limit.
pub struct RequestBody {
    source: Option<worker::Body>,
    stream: Option<IntoStream<'static>>,
    pending: Option<(Uint8Array, u32)>,
    encoding: Encoding,
    remaining: Option<usize>,
    stopped: bool,
}

impl RequestBody {
    fn initialize(&mut self) -> io::Result<()> {
        let Some(body) = self.source.take() else {
            return Ok(());
        };
        if let Some(stream) = body.into_inner() {
            let decoded = self.encoding.decode(stream)?;
            self.stream = Some(
                wasm_streams::ReadableStream::from_raw(decoded.unchecked_into()).into_stream(),
            );
        }
        Ok(())
    }

    fn fail(&mut self, error: io::Error) -> Poll<Option<io::Result<Bytes>>> {
        self.stopped = true;
        self.source = None;
        self.stream = None;
        self.pending = None;
        Poll::Ready(Some(Err(error)))
    }

    fn copy_pending(&mut self) -> Bytes {
        let (chunk, offset) = self.pending.as_mut().expect("pending Worker body chunk");
        // Unbounded multipart streams still use bounded individual WASM copies.
        // Ordinary bounded bodies retain one chunk to avoid extra concatenation.
        let end = if self.remaining.is_none() {
            offset.saturating_add(64 * 1024).min(chunk.length())
        } else {
            chunk.length()
        };
        let bytes = Bytes::from(if *offset == 0 && end == chunk.length() {
            chunk.to_vec()
        } else {
            chunk.subarray(*offset, end).to_vec()
        });
        *offset = end;
        if end == chunk.length() {
            self.pending = None;
        }
        bytes
    }
}

impl Stream for RequestBody {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.stopped {
            return Poll::Ready(None);
        }
        if let Err(error) = this.initialize() {
            return this.fail(error);
        }
        if this.pending.is_some() {
            return Poll::Ready(Some(Ok(this.copy_pending())));
        }
        let Some(stream) = this.stream.as_mut() else {
            this.stopped = true;
            return Poll::Ready(None);
        };
        let chunk = match futures_util::ready!(stream.poll_next_unpin(cx)) {
            Some(Ok(value)) => match value.dyn_into::<Uint8Array>() {
                Ok(chunk) => chunk,
                Err(_) => {
                    return this.fail(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Worker request body did not contain bytes",
                    ));
                }
            },
            Some(Err(_)) => {
                return this.fail(io::Error::other("Worker request body failed"));
            }
            None => {
                this.stopped = true;
                this.stream = None;
                return Poll::Ready(None);
            }
        };
        if let Some(remaining) = this.remaining.as_mut() {
            let Some(next) = remaining.checked_sub(chunk.length() as usize) else {
                return this.fail(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "request body exceeds the route limit",
                ));
            };
            *remaining = next;
        }
        this.pending = Some((chunk, 0));
        Poll::Ready(Some(Ok(this.copy_pending())))
    }
}
