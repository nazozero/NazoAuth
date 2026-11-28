use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use actix_web::{App, HttpResponse, test as awtest, web};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use nazo_identity::{TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot, TenantId};
use nazo_oauth_server::ports::transient_state::{TenantDirectoryCachePort, TransientStateFuture};
use nazoauth::{
    NazoAuth,
    runtime::{
        TenantLifecycle, TenantRuntime, TenantRuntimeBuildFuture, TenantRuntimeBuildPort,
        TenantRuntimeRefresher, TenantRuntimeRegistry,
    },
};
use tower::ServiceExt;

#[derive(Default)]
struct Lifecycle {
    starts: AtomicUsize,
    stops: AtomicUsize,
}

impl TenantLifecycle for Lifecycle {
    fn start(&self) -> anyhow::Result<()> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn stop(&self) -> BoxFuture<'_, ()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
}

struct Directory(Mutex<TenantDirectorySnapshot>);

impl nazo_persistence::TenantDirectoryStore for Directory {
    fn current_revision(
        &self,
    ) -> BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>> {
        Box::pin(async { Ok(self.0.lock().unwrap().revision) })
    }

    fn load_active(
        &self,
    ) -> BoxFuture<'_, Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>> {
        Box::pin(async { Ok(self.0.lock().unwrap().clone()) })
    }

    fn find_active_binding(
        &self,
        tenant_id: TenantId,
    ) -> BoxFuture<'_, Result<Option<TenantDirectoryBinding>, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .unwrap()
                .tenants
                .iter()
                .find(|binding| binding.tenant.tenant_id == tenant_id)
                .cloned())
        })
    }
}

struct Cache;

impl TenantDirectoryCachePort for Cache {
    fn load(&self) -> TransientStateFuture<'_, Option<Arc<TenantDirectorySnapshot>>> {
        Box::pin(async { Ok(None) })
    }

    fn publish_authoritative<'a>(
        &'a self,
        _: &'a TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }
}

struct Factory {
    state: crate::test_support::TestInfrastructure,
    deployment: Arc<nazoauth::capabilities::DeploymentCapabilities>,
    lifecycles: Mutex<Vec<Arc<Lifecycle>>>,
}

impl TenantRuntimeBuildPort for Factory {
    fn build(&self, binding: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
        let binding = binding.clone();
        Box::pin(async move {
            let mut state = self.state.clone();
            let settings = Arc::make_mut(&mut state.settings);
            settings.tenant.context = binding.tenant;
            settings.endpoint.issuer = binding.issuer.clone();
            settings.endpoint.mtls_endpoint_base_url = binding.issuer.clone();
            settings.protocol.protected_resource_identifier =
                format!("https://{}/external-resource%20v1", binding.external_host);
            settings.endpoint.cors_allowed_origins = vec!["https://admin.example".to_owned()];
            let application = Arc::new(
                crate::test_support::facade::builder(&state, Default::default())?
                    .with_deployment(self.deployment.clone())
                    .build()
                    .await?,
            );
            let lifecycle = Arc::new(Lifecycle::default());
            self.lifecycles.lock().unwrap().push(lifecycle.clone());
            Ok(Arc::new(TenantRuntime::new(
                binding,
                application,
                lifecycle,
            )?))
        })
    }
}

pub(crate) struct Fixture {
    pub(crate) registry: TenantRuntimeRegistry,
    pub(crate) refresher: Arc<TenantRuntimeRefresher>,
    directory: Arc<Directory>,
    factory: Arc<Factory>,
}

pub(crate) fn binding(id: u128, host: &str, prefix: &str) -> TenantDirectoryBinding {
    let mut tenant = TenantContext::default_system();
    if id != 0 {
        tenant.tenant_id = TenantId::new(uuid::Uuid::from_u128(id)).unwrap();
    }
    TenantDirectoryBinding {
        tenant,
        runtime_revision: 1,
        issuer: format!("https://{host}{}", prefix.trim_end_matches('/')),
        external_host: host.to_owned(),
    }
}

impl Fixture {
    pub(crate) async fn new(tenants: Vec<TenantDirectoryBinding>) -> Self {
        let state = super::infrastructure(false).await;
        let registry = TenantRuntimeRegistry::empty();
        let initial = TenantDirectorySnapshot {
            revision: 1,
            tenants,
        };
        let directory = Arc::new(Directory(Mutex::new(initial.clone())));
        let deployment =
            super::deployment(TenantContext::default_system().tenant_id, &state.diesel_db);
        let deployment = Arc::new(nazoauth::capabilities::DeploymentCapabilities {
            identity: deployment.identity.clone(),
            control_tenant: deployment.control_tenant,
            tenants: registry.availability(),
            controller_registry: deployment.controller_registry.clone(),
            recovery_root: deployment.recovery_root.clone(),
        });
        let factory = Arc::new(Factory {
            state,
            deployment,
            lifecycles: Mutex::new(Vec::new()),
        });
        let refresher = Arc::new(TenantRuntimeRefresher::new(
            registry.clone(),
            directory.clone(),
            Arc::new(Cache),
            factory.clone(),
        ));
        refresher.install_initial(initial).await.unwrap();
        Self {
            registry,
            refresher,
            directory,
            factory,
        }
    }

    async fn replace(&self, tenants: Vec<TenantDirectoryBinding>) -> anyhow::Result<()> {
        {
            let mut directory = self.directory.0.lock().unwrap();
            directory.revision += 1;
            directory.tenants = tenants;
        }
        self.refresher.reconcile_database_once().await?;
        Ok(())
    }
}

/// Use one already-built graph to run complete protocol flows through both
/// fixed and directory-selected adapters without changing its capabilities.
pub(crate) async fn registered_application(
    binding: TenantDirectoryBinding,
    application: Arc<NazoAuth>,
) -> (TenantRuntimeRegistry, Arc<TenantRuntimeRefresher>) {
    struct Built(Arc<TenantRuntime>);
    impl TenantRuntimeBuildPort for Built {
        fn build(&self, _: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
            Box::pin(async { Ok(self.0.clone()) })
        }
    }
    let registry = TenantRuntimeRegistry::empty();
    let snapshot = TenantDirectorySnapshot {
        revision: 1,
        tenants: vec![binding.clone()],
    };
    let runtime =
        Arc::new(TenantRuntime::new(binding, application, Arc::new(Lifecycle::default())).unwrap());
    let refresher = Arc::new(TenantRuntimeRefresher::new(
        registry.clone(),
        Arc::new(Directory(Mutex::new(snapshot.clone()))),
        Arc::new(Cache),
        Arc::new(Built(runtime)),
    ));
    refresher.install_initial(snapshot).await.unwrap();
    (registry, refresher)
}

fn host(
    request: Request<Full<Bytes>>,
) -> std::future::Ready<Result<Response<Full<Bytes>>, Infallible>> {
    let (status, body) = if request.uri().path().starts_with("/api/") {
        assert!(request.extensions().get::<Arc<NazoAuth>>().is_none());
        (StatusCode::OK, Bytes::from_static(b"host"))
    } else if let Some(application) = request.extensions().get::<Arc<NazoAuth>>()
        && request.uri().path()
            == format!(
                "{}/ui/selected",
                application.mount().path().trim_end_matches('/')
            )
    {
        (
            StatusCode::OK,
            Bytes::copy_from_slice(application.mount().path().as_bytes()),
        )
    } else {
        (StatusCode::NOT_FOUND, Bytes::new())
    };
    std::future::ready(Ok(Response::builder()
        .status(status)
        .body(Full::new(body))
        .unwrap()))
}

fn request(host: &str, path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[actix_web::test]
async fn dynamic_tenant_requires_one_mtls_hostname_and_accepts_a_separate_port() {
    let mut state = super::infrastructure(false).await;
    let binding = TenantDirectoryBinding {
        tenant: state.settings.tenant.context,
        runtime_revision: 1,
        issuer: state.settings.endpoint.issuer.clone(),
        external_host: "issuer.example".to_owned(),
    };
    let application = crate::test_support::facade::application(&state)
        .await
        .unwrap();
    // Fixed registration supports its independently configured mTLS hostname.
    assert!(nazo_http_tower::mount(tower::service_fn(host), application.clone(), &[]).is_ok());
    let error = TenantRuntime::new(binding.clone(), application, Arc::new(Lifecycle::default()))
        .err()
        .expect("a dynamic directory cannot route an unbound mTLS hostname");
    assert!(
        error
            .to_string()
            .contains("mTLS endpoint must use its directory hostname")
    );

    Arc::make_mut(&mut state.settings)
        .endpoint
        .mtls_endpoint_base_url = "https://issuer.example:8443".to_owned();
    let application = crate::test_support::facade::application(&state)
        .await
        .unwrap();
    assert!(TenantRuntime::new(binding, application, Arc::new(Lifecycle::default())).is_ok());
}

#[actix_web::test]
async fn dynamic_transports_share_real_graphs_and_follow_directory_changes() {
    let first = binding(0, "first.example", "/auth");
    let second = binding(42, "second.example", "/parent/ui/auth");
    let fixture = Fixture::new(vec![first.clone(), second.clone()]).await;
    let tower = nazo_http_tower::mount_dynamic(
        tower::service_fn(host),
        fixture.registry.clone(),
        &["/api"],
    )
    .unwrap();
    let actix = awtest::init_service(
        App::new()
            .route(
                "/api/health",
                web::get().to(|| async { HttpResponse::Ok().body("host") }),
            )
            .wrap(nazo_http_actix::DynamicMount::new(fixture.registry.clone(), &["/api"]).unwrap()),
    )
    .await;

    for binding in [&first, &second] {
        let path = format!(
            "{}/.well-known/openid-configuration",
            nazo_auth::issuer_path(&binding.issuer)
        );
        let tower_response = tower
            .clone()
            .oneshot(request(&binding.external_host, &path))
            .await
            .unwrap();
        assert_eq!(tower_response.status(), StatusCode::OK);
        let tower_body = tower_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let metadata: serde_json::Value = serde_json::from_slice(&tower_body).unwrap();
        assert_eq!(metadata["issuer"], binding.issuer);
        assert_eq!(
            metadata["token_endpoint"],
            format!("{}/token", binding.issuer)
        );
        let actix_response = awtest::call_service(
            &actix,
            awtest::TestRequest::get()
                .uri(&path)
                .insert_header(("host", binding.external_host.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(actix_response.status().as_u16(), 200);
        assert_eq!(awtest::read_body(actix_response).await, tower_body);
        let ui = format!("{}/ui/selected", nazo_auth::issuer_path(&binding.issuer));
        let response = tower
            .clone()
            .oneshot(request(&binding.external_host, &ui))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            nazo_auth::issuer_path(&binding.issuer)
        );

        // Discovery deliberately filters ingress headers after tenant selection.
        let relocated = format!(
            "/.well-known/oauth-authorization-server{}",
            nazo_auth::issuer_path(&binding.issuer)
        );
        assert_eq!(
            tower
                .clone()
                .oneshot(request(&binding.external_host, &relocated))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resource = "/.well-known/oauth-protected-resource/external-resource%20v1";
        assert_eq!(
            tower
                .clone()
                .oneshot(request(&binding.external_host, resource))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let metadata = awtest::call_service(
            &actix,
            awtest::TestRequest::get()
                .uri(resource)
                .insert_header(("host", binding.external_host.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(metadata.status().as_u16(), 200);
        let alias = "/.well-known/oauth-protected-resource/%65xternal-resource%20v1";
        assert_eq!(
            tower
                .clone()
                .oneshot(request(&binding.external_host, alias))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            awtest::call_service(
                &actix,
                awtest::TestRequest::get()
                    .uri(alias)
                    .insert_header(("host", binding.external_host.as_str()))
                    .to_request(),
            )
            .await
            .status()
            .as_u16(),
            404
        );
        let old = fixture
            .registry
            .resolve(&binding.external_host, None)
            .unwrap();
        nazoauth::integration::conformance::assert_adapter(old.application(), |mut prepared| {
            prepared
                .headers_mut()
                .insert("host", binding.external_host.parse().unwrap());
            let tower = tower.clone();
            async move {
                let (head, body) = tower
                    .oneshot(prepared.map(Full::new))
                    .await
                    .unwrap()
                    .into_parts();
                Response::from_parts(head, body.collect().await.unwrap().to_bytes())
            }
        })
        .await;
    }

    assert_eq!(
        tower
            .clone()
            .oneshot(request("unknown.example", "/api/health"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        tower
            .clone()
            .oneshot(request("unknown.example", "/auth/jwks.json"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let mut wrong_sni = request("first.example", "/auth/.well-known/openid-configuration");
    wrong_sni
        .extensions_mut()
        .insert(nazoauth::ConnectionFacts {
            server_name: Some("second.example".into()),
            ..Default::default()
        });
    assert_eq!(
        tower.clone().oneshot(wrong_sni).await.unwrap().status(),
        StatusCode::MISDIRECTED_REQUEST
    );

    let absolute = "https://first.example/auth/.well-known/openid-configuration";
    for (sni, status) in [
        ("first.example", StatusCode::OK),
        ("second.example", StatusCode::MISDIRECTED_REQUEST),
    ] {
        let mut prepared = request("second.example", absolute);
        prepared.extensions_mut().insert(nazoauth::ConnectionFacts {
            server_name: Some(sni.into()),
            ..Default::default()
        });
        let response = tower.clone().oneshot(prepared).await.unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(metadata["issuer"], first.issuer);
        }
    }
    let response = awtest::call_service(
        &actix,
        awtest::TestRequest::get()
            .uri(absolute)
            .insert_header(("host", "second.example"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status().as_u16(), 200);
    let metadata: serde_json::Value =
        serde_json::from_slice(&awtest::read_body(response).await).unwrap();
    assert_eq!(metadata["issuer"], first.issuer);

    let held = fixture.registry.resolve("first.example", None).unwrap();
    let mut replacement = first.clone();
    replacement.issuer = "https://first.example/new-auth".into();
    replacement.runtime_revision += 1;
    fixture.replace(vec![replacement.clone()]).await.unwrap();
    assert_eq!(held.application().mount().path(), "/auth");
    let ui = tower
        .clone()
        .oneshot(request("first.example", "/new-auth/ui/selected"))
        .await
        .unwrap();
    assert_eq!(ui.status(), StatusCode::OK);
    assert_eq!(
        ui.into_body().collect().await.unwrap().to_bytes(),
        "/new-auth"
    );
    for (host, path, status) in [
        (
            "first.example",
            "/new-auth/.well-known/openid-configuration",
            StatusCode::OK,
        ),
        (
            "first.example",
            "/auth/.well-known/openid-configuration",
            StatusCode::NOT_FOUND,
        ),
        (
            "second.example",
            "/parent/ui/auth/.well-known/openid-configuration",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            tower
                .clone()
                .oneshot(request(host, path))
                .await
                .unwrap()
                .status(),
            status
        );
        let actual = awtest::call_service(
            &actix,
            awtest::TestRequest::get()
                .uri(path)
                .insert_header(("host", host))
                .to_request(),
        )
        .await;
        assert_eq!(actual.status().as_u16(), status.as_u16());
    }
    assert_eq!(
        fixture.factory.lifecycles.lock().unwrap()[0]
            .stops
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture.factory.lifecycles.lock().unwrap()[1]
            .stops
            .load(Ordering::SeqCst),
        1
    );

    // A subsequently added tenant cannot claim a namespace reserved before it existed.
    assert!(
        fixture
            .replace(vec![replacement, binding(43, "third.example", "/api")])
            .await
            .is_err()
    );
    assert_eq!(
        tower
            .oneshot(request("first.example", "/api/health"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(fixture.registry.resolve("third.example", None).is_err());
    fixture.refresher.shutdown().await;
    assert!(fixture.registry.load().by_host.is_empty());
}

#[actix_web::test]
async fn fixed_and_dynamic_transports_admit_version_specific_authority_before_metadata_filtering() {
    let fixture = Fixture::new(vec![binding(0, "issuer.example", "/auth")]).await;
    let application = fixture
        .registry
        .resolve("issuer.example", None)
        .unwrap()
        .application()
        .clone();
    let fixed_actix = awtest::init_service(
        App::new().configure(nazo_http_actix::mount(application.clone(), &[]).unwrap()),
    )
    .await;
    let dynamic_actix = awtest::init_service(
        App::new().wrap(nazo_http_actix::DynamicMount::new(fixture.registry.clone(), &[]).unwrap()),
    )
    .await;
    let fixed_tower = nazo_http_tower::mount(tower::service_fn(host), application, &[]).unwrap();
    let dynamic_tower =
        nazo_http_tower::mount_dynamic(tower::service_fn(host), fixture.registry.clone(), &[])
            .unwrap();
    let absolute = "https://issuer.example/auth/.well-known/openid-configuration";
    let relative = "/auth/.well-known/openid-configuration";
    for (version, target, host, expected) in [
        (
            http::Version::HTTP_11,
            absolute,
            Some("other.example"),
            StatusCode::OK,
        ),
        (http::Version::HTTP_2, absolute, None, StatusCode::OK),
        (
            http::Version::HTTP_2,
            absolute,
            Some("ISSUER.example:443"),
            StatusCode::OK,
        ),
        (
            http::Version::HTTP_2,
            absolute,
            Some("other.example"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_2,
            absolute,
            Some("issuer.example:8443"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_2,
            relative,
            Some("issuer.example"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_3,
            relative,
            Some("issuer.example"),
            StatusCode::OK,
        ),
        (http::Version::HTTP_3, absolute, None, StatusCode::OK),
        (
            http::Version::HTTP_3,
            absolute,
            Some("issuer.example"),
            StatusCode::OK,
        ),
        (
            http::Version::HTTP_3,
            absolute,
            Some("ISSUER.example"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_3,
            absolute,
            Some("issuer.example:443"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_3,
            absolute,
            Some("other.example"),
            StatusCode::BAD_REQUEST,
        ),
        (
            http::Version::HTTP_3,
            absolute,
            Some(""),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut builder = Request::builder().version(version).uri(target);
        if let Some(host) = host {
            builder = builder.header("host", host);
        }
        let prepared = builder.body(Bytes::new()).unwrap();
        let actix_version = match version {
            http::Version::HTTP_2 => actix_web::http::Version::HTTP_2,
            http::Version::HTTP_3 => actix_web::http::Version::HTTP_3,
            _ => actix_web::http::Version::HTTP_11,
        };
        let actix_request = || {
            super::framework_request(&prepared)
                .version(actix_version)
                .to_request()
        };
        let fixed = super::standard_response(
            awtest::call_service(&fixed_actix, actix_request())
                .await
                .into_parts()
                .1,
        )
        .await;
        let dynamic = super::standard_response(
            awtest::call_service(&dynamic_actix, actix_request())
                .await
                .into_parts()
                .1
                .map_into_boxed_body(),
        )
        .await;
        let fixed_stream = fixed_tower
            .clone()
            .oneshot(prepared.clone().map(Full::new))
            .await
            .unwrap();
        let (fixed_head, fixed_body) = fixed_stream.into_parts();
        let fixed_stream =
            Response::from_parts(fixed_head, fixed_body.collect().await.unwrap().to_bytes());
        let dynamic_stream = dynamic_tower
            .clone()
            .oneshot(prepared.map(Full::new))
            .await
            .unwrap();
        let (dynamic_head, dynamic_body) = dynamic_stream.into_parts();
        let dynamic_stream = Response::from_parts(
            dynamic_head,
            dynamic_body.collect().await.unwrap().to_bytes(),
        );
        for response in [fixed, dynamic, fixed_stream, dynamic_stream] {
            assert_eq!(
                response.status(),
                expected,
                "{version:?} {target} Host={host:?}"
            );
            if expected == StatusCode::OK {
                let metadata: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
                assert_eq!(metadata["issuer"], "https://issuer.example/auth");
            }
        }
    }
    fixture.refresher.shutdown().await;
}

#[actix_web::test]
async fn dynamic_selection_and_bodyless_routes_never_poll_the_payload() {
    let fixture = Fixture::new(vec![binding(0, "issuer.example", "/auth")]).await;
    let actix = awtest::init_service(
        App::new().wrap(nazo_http_actix::DynamicMount::new(fixture.registry.clone(), &[]).unwrap()),
    )
    .await;
    let tower = nazo_http_tower::mount_dynamic(
        tower::service_fn(|_: Request<_>| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        }),
        fixture.registry.clone(),
        &[],
    )
    .unwrap();
    for (host, path, status) in [
        ("unknown.example", "/auth/token", StatusCode::NOT_FOUND),
        ("issuer.example:abc", "/auth/token", StatusCode::BAD_REQUEST),
        ("issuer.example", "/auth/missing", StatusCode::NOT_FOUND),
        (
            "issuer.example",
            "/auth/token",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        ("issuer.example", "/auth/jwks.json", StatusCode::OK),
    ] {
        let body = http_body_util::StreamBody::new(futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
                panic!("dynamic Tower rejection or bodyless route must not poll its payload")
            },
        ));
        let prepared = Request::builder()
            .uri(path)
            .header("host", host)
            .header("content-encoding", "gzip")
            .body(body)
            .unwrap();
        assert_eq!(
            tower.clone().oneshot(prepared).await.unwrap().status(),
            status
        );
        let mut prepared = awtest::TestRequest::get()
            .uri(path)
            .insert_header(("host", host))
            .insert_header(("content-encoding", "gzip"))
            .to_request();
        *prepared.payload() = actix_web::dev::Payload::Stream {
            payload: Box::pin(futures_util::stream::poll_fn(
                |_| -> std::task::Poll<Option<Result<Bytes, actix_web::error::PayloadError>>> {
                    panic!("dynamic Actix rejection or bodyless route must not poll its payload")
                },
            )),
        };
        assert_eq!(
            awtest::call_service(&actix, prepared)
                .await
                .status()
                .as_u16(),
            status.as_u16()
        );
    }
    fixture.refresher.shutdown().await;
}

#[actix_web::test]
async fn native_ui_uses_the_selected_prefix_and_keeps_nested_ui_segments() {
    let fixture = Fixture::new(vec![
        binding(0, "first.example", "/auth"),
        binding(42, "second.example", "/parent/ui/auth"),
    ])
    .await;
    let root = std::env::temp_dir().join(format!("runtime-ui-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(root.join("sub/ui")).unwrap();
    std::fs::write(root.join("index.html"), "index").unwrap();
    std::fs::write(root.join("file.js"), "wrong-file").unwrap();
    std::fs::write(root.join("sub/ui/file.js"), "correct-nested-file").unwrap();
    let app = awtest::init_service(
        App::new()
            .service(crate::bootstrap::ui_static_files(root.clone()))
            .wrap(nazo_http_actix::DynamicMount::new(fixture.registry.clone(), &[]).unwrap()),
    )
    .await;
    for (host, prefix) in [
        ("first.example", "/auth"),
        ("second.example", "/parent/ui/auth"),
    ] {
        for (suffix, body) in [
            ("/ui/sub/ui/file.js", "correct-nested-file"),
            ("/ui/profile", "index"),
        ] {
            let response = awtest::call_service(
                &app,
                awtest::TestRequest::get()
                    .uri(&format!("{prefix}{suffix}"))
                    .insert_header(("host", host))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status().as_u16(), 200);
            assert_eq!(awtest::read_body(response).await, body);
        }
        let outside = awtest::call_service(
            &app,
            awtest::TestRequest::get()
                .uri("/ui/file.js")
                .insert_header(("host", host))
                .to_request(),
        )
        .await;
        assert_eq!(outside.status().as_u16(), 404);
    }
    fixture
        .replace(vec![binding(0, "first.example", "/new-auth")])
        .await
        .unwrap();
    for (path, status) in [
        ("/new-auth/ui/sub/ui/file.js", 200),
        ("/auth/ui/sub/ui/file.js", 404),
    ] {
        let response = awtest::call_service(
            &app,
            awtest::TestRequest::get()
                .uri(path)
                .insert_header(("host", "first.example"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status().as_u16(), status);
        if status == 200 {
            assert_eq!(awtest::read_body(response).await, "correct-nested-file");
        }
    }
    fixture.refresher.shutdown().await;
    std::fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn shared_dynamic_mount_keeps_deployment_controls_on_the_control_tenant() {
    let fixture = Fixture::new(vec![
        binding(0, "system.example", "/"),
        binding(42, "tenant.example", "/auth"),
    ])
    .await;
    let app = awtest::init_service(
        App::new().wrap(nazo_http_actix::DynamicMount::new(fixture.registry.clone(), &[]).unwrap()),
    )
    .await;
    for (host, path) in [
        ("system.example", "/admin/runtime-modules"),
        ("tenant.example", "/auth/admin/runtime-modules"),
    ] {
        let response = awtest::call_service(
            &app,
            awtest::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri(path)
                .insert_header(("host", host))
                .insert_header(("origin", "https://admin.example"))
                .insert_header(("access-control-request-method", "GET"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
    }
    let forbidden = awtest::call_service(
        &app,
        awtest::TestRequest::post()
            .uri("/auth/.well-known/nazoauth-control")
            .insert_header(("host", "tenant.example"))
            .to_request(),
    )
    .await;
    assert_eq!(forbidden.status().as_u16(), 404);
    let allowed = awtest::call_service(
        &app,
        awtest::TestRequest::post()
            .uri("/.well-known/nazoauth-control")
            .insert_header(("host", "system.example"))
            .set_json(nazo_operator_protocol::DiscoveryRequest {
                schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            })
            .to_request(),
    )
    .await;
    assert_eq!(allowed.status().as_u16(), 200);
    fixture.refresher.shutdown().await;
}
