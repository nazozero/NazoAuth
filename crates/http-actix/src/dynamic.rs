//! Shared tenant selection at the Actix transport boundary.

use std::{
    cell::RefCell,
    collections::HashMap,
    future::{Ready, ready},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error,
    body::{EitherBody, MessageBody},
    dev::{Extensions, Service, ServiceRequest, ServiceResponse, Transform, Url},
    http::{Version, header::HOST},
    web,
};
use futures_util::{
    FutureExt,
    future::{Either, LocalBoxFuture, Map},
};
use nazoauth::{
    ConnectionFacts, NazoAuth,
    runtime::{TenantHostIndex, TenantRuntimeRegistry},
};

/// Mount a live tenant directory around an existing Actix application or scope.
///
/// Declared host namespaces bypass tenant selection. Every other request selects
/// its tenant from the actual authority and TLS server name. Authentication paths
/// use the selected immutable graph; unowned paths continue to the host with that
/// graph installed as `web::Data<NazoAuth>`, including its mounted UI namespace.
/// All current and future directory snapshots respect the host reservations.
#[derive(Clone)]
pub struct DynamicMount {
    registry: TenantRuntimeRegistry,
    occupied_paths: Arc<[Url]>,
}

impl DynamicMount {
    pub fn new(registry: TenantRuntimeRegistry, occupied_paths: &[&str]) -> anyhow::Result<Self> {
        let occupied = occupied_paths
            .iter()
            .map(|path| path.trim_end_matches('/').parse().map(Url::new))
            .collect::<Result<_, _>>()?;
        registry.require_mount_paths(occupied_paths)?;
        Ok(Self {
            registry,
            occupied_paths: occupied,
        })
    }
}

/// A worker's host service and transport-local tenant data cache.
pub struct DynamicMountService<S> {
    existing: S,
    registration: DynamicMount,
    tenants: RefCell<WorkerTenantData>,
}

#[derive(Default)]
struct WorkerTenantData {
    index: Option<Arc<TenantHostIndex>>,
    by_host: HashMap<String, Rc<Extensions>>,
}

impl WorkerTenantData {
    fn resolve(
        &mut self,
        index: Arc<TenantHostIndex>,
        authority: &str,
        server_name: Option<&str>,
    ) -> Result<Rc<Extensions>, http::StatusCode> {
        if self
            .index
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, &index))
        {
            self.by_host.clear();
            self.index = Some(index.clone());
        }
        let runtime = index.resolve(authority, server_name)?;
        let host = &runtime.binding().external_host;
        if let Some(data) = self.by_host.get(host) {
            return Ok(data.clone());
        }
        let mut data = Extensions::new();
        data.insert(web::Data::from(runtime.application().clone()));
        let data = Rc::new(data);
        self.by_host.insert(host.clone(), data.clone());
        Ok(data)
    }
}

impl<S, B> Transform<S, ServiceRequest> for DynamicMount
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = DynamicMountService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, existing: S) -> Self::Future {
        ready(Ok(DynamicMountService {
            existing,
            registration: self.clone(),
            tenants: RefCell::new(WorkerTenantData::default()),
        }))
    }
}

type HostResponse<B> =
    fn(Result<ServiceResponse<B>, Error>) -> Result<ServiceResponse<EitherBody<B>>, Error>;

fn host_response<B>(
    response: Result<ServiceResponse<B>, Error>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    response.map(ServiceResponse::map_into_left_body)
}

impl<S, B> Service<ServiceRequest> for DynamicMountService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Either<
        Map<S::Future, HostResponse<B>>,
        LocalBoxFuture<'static, Result<Self::Response, Error>>,
    >;

    fn poll_ready(&self, context: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.existing.poll_ready(context)
    }

    fn call(&self, mut request: ServiceRequest) -> Self::Future {
        let path = request.uri().path();
        let decoded = path.contains('%').then(|| Url::new(request.uri().clone()));
        let host_path = decoded.as_ref().map_or(path, Url::path);
        if self.registration.occupied_paths.iter().any(|prefix| {
            host_path
                .strip_prefix(prefix.path())
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        }) {
            return Either::Left(
                self.existing
                    .call(request)
                    .map(host_response::<B> as HostResponse<B>),
            );
        }
        let selected = request_authority(request.request()).and_then(|authority| {
            self.tenants.borrow_mut().resolve(
                self.registration.registry.load(),
                authority,
                request
                    .request()
                    .conn_data::<ConnectionFacts>()
                    .and_then(|facts| facts.server_name.as_deref()),
            )
        });
        let container = match selected {
            Ok(container) => container,
            Err(status) => {
                let response = super::rejection(status, path);
                return Either::Right(Box::pin(async move {
                    Ok(request.into_response(response).map_into_right_body())
                }));
            }
        };
        let application = container
            .get::<web::Data<NazoAuth>>()
            .expect("selected tenant data");
        // Follow Actix's decoded host/UI aliases without changing the raw target
        // sent to proof verification or the prefix used to select the tenant.
        let owned = application.mount().owns_path(path)
            && decoded.as_ref().is_none_or(|url| {
                application.mount().owns_path(url.path())
                    || application
                        .mount()
                        .discovery_paths()
                        .any(|exact| exact == path)
            });
        request.add_data_container(container);
        if !owned {
            return Either::Left(
                self.existing
                    .call(request)
                    .map(host_response::<B> as HostResponse<B>),
            );
        }
        Either::Right(Box::pin(async move {
            let (request, payload) = request.into_parts();
            let application = request
                .app_data::<web::Data<NazoAuth>>()
                .expect("selected tenant data");
            let response = super::serve_request(application, &request, payload).await;
            Ok(ServiceResponse::new(request, response).map_into_right_body())
        }))
    }
}

pub(super) fn request_authority(
    request: &actix_web::HttpRequest,
) -> Result<&str, http::StatusCode> {
    let mut hosts = request.headers().get_all(HOST);
    let host = hosts
        .next()
        .map(|host| host.to_str())
        .transpose()
        .map_err(|_| http::StatusCode::BAD_REQUEST)?;
    if hosts.next().is_some() {
        return Err(http::StatusCode::BAD_REQUEST);
    }
    if request.version() >= Version::HTTP_2 {
        let version = if request.version() == Version::HTTP_3 {
            http::Version::HTTP_3
        } else {
            http::Version::HTTP_2
        };
        return nazoauth::integration::multiplexed_authority(
            version,
            request.uri().scheme_str(),
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
            host,
        )
        .ok_or(http::StatusCode::BAD_REQUEST);
    }
    if host.is_some_and(|host| !nazoauth::integration::valid_host_header(host))
        || request.version() == Version::HTTP_11 && host.is_none()
    {
        return Err(http::StatusCode::BAD_REQUEST);
    }
    // RFC 9112 section 3.2.2: an absolute-form request target supplies the
    // authority even when the Host field disagrees.
    if let Some(authority) = request.uri().authority() {
        return Ok(authority.as_str());
    }
    host.ok_or(http::StatusCode::NOT_FOUND)
}

#[cfg(test)]
#[path = "../tests/unit/dynamic.rs"]
mod tests;
