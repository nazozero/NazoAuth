use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use nazo_oauth_server_d1::{D1Provider, Database};
use worker::{Env, HttpRequest, event, wasm_bindgen::JsValue};

use crate::{Ingress, WorkerApplication, WorkerConfiguration, WorkerSecrets};

struct Cached {
    bindings: ([JsValue; 10], String),
    prepared: WorkerApplication,
    refresh_after: Cell<i64>,
    refreshing: Cell<bool>,
}

thread_local! {
    static APPLICATION: RefCell<Option<Rc<Cached>>> = const { RefCell::new(None) };
}

#[event(fetch)]
async fn fetch(
    request: worker::Request,
    env: Env,
    _: worker::Context,
) -> worker::Result<Response<Full<Bytes>>> {
    let path = request.path();
    let mut response = dispatch(request, env).await?;
    for (name, value) in nazoauth::integration::security_headers(&path) {
        if !response.headers().contains_key(name) {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    Ok(response)
}

async fn dispatch(request: worker::Request, env: Env) -> worker::Result<Response<Full<Bytes>>> {
    let presented_certificate = crate::mtls::PresentedCertificate::capture(&request);
    let mut request: HttpRequest = request.try_into()?;
    let Ok(bindings) = binding_values(&env) else {
        return Ok(unavailable());
    };
    let prepared = APPLICATION.with_borrow(|cached| {
        cached
            .as_ref()
            .filter(|cached| cached.bindings == bindings)
            .cloned()
    });
    let cold_configuration;
    let configuration = if let Some(cached) = &prepared {
        &cached.prepared.configuration
    } else {
        let Ok(configuration) = configuration(&env) else {
            return Ok(unavailable());
        };
        cold_configuration = configuration;
        &cold_configuration
    };
    if !configuration.accepts_authority(request.uri(), request.headers()) {
        return Ok(response(StatusCode::MISDIRECTED_REQUEST, Bytes::new()));
    }
    // Most Web assets do not depend on module state. The Device shell is an
    // existing-transaction entry and follows the same current drain admission
    // as the protocol after the authoritative synchronization below.
    let module_ui = !configuration.machine_only
        && matches!(*request.method(), http::Method::GET | http::Method::HEAD)
        && crate::ui::is_device_page(request.uri().path())
        && configuration
            .modules
            .contains(&nazo_runtime_modules::ModuleId::DeviceAuthorization);
    if !module_ui && let Some(reply) = crate::ui::serve(&request, &env, configuration).await {
        return reply;
    }
    if configuration.ingress == Ingress::DirectCloudflare {
        let Ok(mut facts) = nazo_http_worker::direct_ingress_facts(&request) else {
            return Ok(response(StatusCode::FORBIDDEN, Bytes::new()));
        };
        if configuration.services.mtls {
            facts.client_certificate =
                presented_certificate.and_then(crate::mtls::PresentedCertificate::facts);
        }
        request.extensions_mut().insert(facts);
    }
    if !configuration.machine_only
        && request.method() == http::Method::GET
        && let Some(reply) = crate::setup::page(request.uri().path())
    {
        return Ok(reply);
    }
    let cached = match prepared {
        Some(cached) => cached,
        None => match application(&env, bindings, configuration.clone()).await {
            Ok(cached) => cached,
            Err(_) => {
                worker::console_error!("NazoAuth Worker initialization failed");
                return Ok(unavailable());
            }
        },
    };
    if cached
        .prepared
        .application
        .synchronize_runtime_modules_step()
        .await
        .is_err()
    {
        worker::console_error!("NazoAuth Worker module synchronization failed");
        return Ok(unavailable());
    }
    let active_modules = cached.prepared.application.runtime_module_snapshot();
    if module_ui {
        if !active_modules.permits(
            nazo_runtime_modules::ModuleId::DeviceAuthorization,
            nazo_runtime_modules::CapabilityAdmission::ExistingTransaction,
        ) {
            return Ok(response(StatusCode::NOT_FOUND, Bytes::new()));
        }
        if let Some(reply) = crate::ui::serve(&request, &env, &cached.prepared.configuration).await
        {
            return reply;
        }
    }
    if !cached.prepared.configuration.machine_only
        && let Some(reply) = crate::setup::handle(&request, &env, &cached.prepared).await
    {
        return Ok(reply);
    }
    let now = jiff::Timestamp::now().as_second();
    if now >= cached.refresh_after.get() && !cached.refreshing.replace(true) {
        struct Reset<'a>(&'a Cell<bool>);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _reset = Reset(&cached.refreshing);
        if cached.prepared.keys.refresh().await.is_err() {
            worker::console_error!("NazoAuth Worker signing-key refresh failed");
            return Ok(unavailable());
        }
        cached.refresh_after.set(now + 60);
    }
    Ok(nazo_http_worker::serve(&cached.prepared.application, request).await)
}

fn configuration(env: &Env) -> anyhow::Result<WorkerConfiguration> {
    Ok(serde_json::from_str(&env.var("NAZO_CONFIG")?.to_string())?)
}

fn avatar_bucket(env: &Env) -> anyhow::Result<Option<worker::Bucket>> {
    use crate::avatars::AVATAR_BUCKET;

    match env.bucket(AVATAR_BUCKET) {
        Ok(bucket) => Ok(Some(bucket)),
        // The SDK reports a missing binding as a RustError. Other binding
        // errors, including a configured binding of the wrong type, must fail.
        Err(worker::Error::RustError(message))
            if message
                .strip_prefix("Binding `")
                .and_then(|s| s.strip_suffix("` is undefined."))
                == Some(AVATAR_BUCKET) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

async fn application(
    env: &Env,
    bindings: ([JsValue; 10], String),
    configuration: WorkerConfiguration,
) -> anyhow::Result<Rc<Cached>> {
    let mut secrets: WorkerSecrets = env
        .secret("NAZO_SERVICE_SECRETS")
        .ok()
        .map(|value| serde_json::from_str(&value.to_string()))
        .transpose()?
        .unwrap_or_default();
    let wrapping_keys = secrets.take_signing_wrapping_keys(
        env.var("NAZO_SIGNING_KEY_ID")?.to_string(),
        env.secret("NAZO_SIGNING_KEY")?.to_string(),
        env.secret("NAZO_PREVIOUS_SIGNING_KEY")
            .ok()
            .map(|key| key.to_string()),
    )?;
    let prepared = WorkerApplication::build(
        configuration,
        Database::from_binding(env.d1("NAZO_DB")?),
        env.secret("NAZO_CLIENT_SECRET_PEPPER")?.to_string(),
        wrapping_keys,
        env.secret("NAZO_DUMMY_PASSWORD_HASH")?.to_string(),
        env.secret("NAZO_DCR_INITIAL_ACCESS_TOKEN")
            .ok()
            .map(|token| token.to_string()),
        secrets,
        avatar_bucket(env)?,
    )
    .await?;
    let initialized = Rc::new(Cached {
        bindings,
        prepared,
        refresh_after: Cell::new(jiff::Timestamp::now().as_second() + 60),
        refreshing: Cell::new(false),
    });
    // Do not share an in-flight I/O future across Cloudflare request contexts.
    // Concurrent cold requests may prepare independently; only the completed
    // graph is retained, and all subsequent requests borrow it without a lock.
    Ok(APPLICATION.with_borrow_mut(|cached| {
        if let Some(existing) = cached
            .as_ref()
            .filter(|cached| cached.bindings == initialized.bindings)
        {
            return existing.clone();
        }
        *cached = Some(initialized.clone());
        initialized
    }))
}

fn binding_values(env: &Env) -> anyhow::Result<([JsValue; 10], String)> {
    // Binding-only deployments may reuse an isolate. Compare the actual values
    // in JS (including D1 object identity), without copying secrets or parsing
    // configuration on every request. Never reuse a graph for changed bindings.
    let values = [
        env.var("NAZO_CONFIG")?.into(),
        env.d1("NAZO_DB")?.into(),
        env.var("NAZO_SIGNING_KEY_ID")?.into(),
        env.secret("NAZO_SIGNING_KEY")?.into(),
        env.secret("NAZO_CLIENT_SECRET_PEPPER")?.into(),
        env.secret("NAZO_DUMMY_PASSWORD_HASH")?.into(),
        env.secret("NAZO_DCR_INITIAL_ACCESS_TOKEN")
            .map(JsValue::from)
            .unwrap_or(JsValue::UNDEFINED),
        env.secret("NAZO_SERVICE_SECRETS")
            .map(JsValue::from)
            .unwrap_or(JsValue::UNDEFINED),
        env.secret("NAZO_PREVIOUS_SIGNING_KEY")
            .map(JsValue::from)
            .unwrap_or(JsValue::UNDEFINED),
        avatar_bucket(env)?
            .map(JsValue::from)
            .unwrap_or(JsValue::UNDEFINED),
    ];
    // A platform version captures bindings even when the same JS capability
    // object can refer to a different per-request I/O channel after deployment.
    let version = env
        .get_binding::<worker::WorkerVersionMetadata>("NAZO_VERSION")?
        .id();
    anyhow::ensure!(!version.is_empty(), "Worker version ID is missing");
    Ok((values, version))
}

fn unavailable() -> Response<Full<Bytes>> {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        Bytes::from_static(b"Service unavailable"),
    )
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[event(scheduled)]
async fn scheduled(_: worker::ScheduledEvent, env: Env, context: worker::ScheduleContext) {
    context.wait_until(async move {
        let result = async {
            let configuration: WorkerConfiguration =
                serde_json::from_str(&env.var("NAZO_CONFIG")?.to_string())?;
            let provider = D1Provider::new(
                Database::from_binding(env.d1("NAZO_DB")?),
                configuration.tenant.tenant_id,
            );
            // One bounded pass per Cron event on every deployment profile.
            // Enabling password login does not change the Workers plan budget.
            let total = provider.prune_expired(500).await?;
            if let Some(bucket) = avatar_bucket(&env)?
                && crate::avatars::R2Avatars::new(
                    provider,
                    configuration.tenant.tenant_id.as_uuid(),
                    bucket,
                )
                .clean_up()
                .await
                .is_err()
            {
                worker::console_error!("NazoAuth R2 avatar cleanup failed");
            }
            let bindings = binding_values(&env)?;
            let cached = APPLICATION.with_borrow(|cached| {
                cached
                    .as_ref()
                    .filter(|cached| cached.bindings == bindings)
                    .cloned()
            });
            let application = match cached {
                Some(cached) => cached,
                None => application(&env, bindings, configuration.clone()).await?,
            };
            if application
                .prepared
                .application
                .synchronize_runtime_modules_step()
                .await
                .is_err()
            {
                worker::console_error!("NazoAuth scheduled module synchronization failed");
            }
            if !configuration.services.outbound_origins.is_empty() {
                if configuration
                    .modules
                    .contains(&nazo_runtime_modules::ModuleId::Ciba)
                    && application
                        .prepared
                        .ciba_ping
                        .process_due_batch()
                        .await
                        .is_err()
                {
                    worker::console_error!("NazoAuth CIBA delivery batch failed");
                }
                if application
                    .prepared
                    .backchannel_logout
                    .process_due_batch()
                    .await
                    .is_err()
                {
                    worker::console_error!("NazoAuth logout delivery batch failed");
                }
            }
            Ok::<_, anyhow::Error>(total)
        }
        .await;
        match result {
            Ok(removed) => worker::console_log!("NazoAuth expired state removed: {}", removed),
            Err(_) => worker::console_error!("NazoAuth scheduled state cleanup failed"),
        }
    });
}
