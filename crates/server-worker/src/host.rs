use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use nazo_key_management::SigningKeyWrappingKeyRing;
use nazo_oauth_server_d1::{D1Provider, Database};
use worker::{Env, HttpRequest, event, wasm_bindgen::JsValue};
use zeroize::Zeroizing;

use crate::{Ingress, WorkerApplication, WorkerConfiguration};

struct Cached {
    bindings: ([JsValue; 7], String),
    prepared: WorkerApplication,
    refresh_after: Cell<i64>,
    refreshing: Cell<bool>,
}

thread_local! {
    static APPLICATION: RefCell<Option<Rc<Cached>>> = const { RefCell::new(None) };
}

#[event(fetch)]
async fn fetch(
    mut request: HttpRequest,
    env: Env,
    _: worker::Context,
) -> worker::Result<Response<Full<Bytes>>> {
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
    if !configuration.allows_route(request.method(), request.uri().path()) {
        return Ok(response(StatusCode::NOT_FOUND, Bytes::new()));
    }
    if configuration.ingress == Ingress::DirectCloudflare {
        let Ok(facts) = nazo_http_worker::direct_ingress_facts(&request) else {
            return Ok(response(StatusCode::FORBIDDEN, Bytes::new()));
        };
        request.extensions_mut().insert(facts);
    }
    if configuration.passkey_only
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
    if cached.prepared.configuration.machine_only
        && request.method() == http::Method::GET
        && request.uri().path() == "/.well-known/oauth-authorization-server"
    {
        // A machine-only deployment must not advertise browser grants.
        let body = serde_json::to_vec(&cached.prepared.configuration.machine_metadata())
            .map(Bytes::from)
            .map_err(|_| worker::Error::RustError("OAuth metadata encoding failed".into()))?;
        let mut result = response(StatusCode::OK, body);
        result.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        return Ok(result);
    }
    if cached.prepared.configuration.passkey_only
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

async fn application(
    env: &Env,
    bindings: ([JsValue; 7], String),
    configuration: WorkerConfiguration,
) -> anyhow::Result<Rc<Cached>> {
    let encoded_key = Zeroizing::new(env.secret("NAZO_SIGNING_KEY")?.to_string());
    let mut key = Zeroizing::new([0_u8; 32]);
    anyhow::ensure!(
        STANDARD.decode_slice(encoded_key.as_bytes(), key.as_mut_slice())? == 32,
        "signing wrapping key must decode to exactly 32 bytes"
    );
    let wrapping_keys =
        SigningKeyWrappingKeyRing::new(env.var("NAZO_SIGNING_KEY_ID")?.to_string(), *key, None)?;
    let prepared = WorkerApplication::build(
        configuration,
        Database::from_binding(env.d1("NAZO_DB")?),
        env.secret("NAZO_CLIENT_SECRET_PEPPER")?.to_string(),
        wrapping_keys,
        env.secret("NAZO_DUMMY_PASSWORD_HASH")?.to_string(),
        env.secret("NAZO_DCR_INITIAL_ACCESS_TOKEN")
            .ok()
            .map(|token| token.to_string()),
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

fn binding_values(env: &Env) -> anyhow::Result<([JsValue; 7], String)> {
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
            let started = jiff::Timestamp::now().as_second();
            let mut total = 0;
            // Workers Free Cron events have a 10 ms CPU limit; avoid the
            // full-profile multi-pass cleanup loop.
            let (passes, batch) = if configuration.machine_only || configuration.passkey_only {
                (1, 500)
            } else {
                (64, 1_000)
            };
            // Drain a bounded backlog outside requests. One 1,000-row pass per
            // minute would fall behind even moderate DPoP/replay traffic.
            for _ in 0..passes {
                let removed = provider.prune_expired(batch).await?;
                total += removed;
                if removed < batch || jiff::Timestamp::now().as_second() - started >= 20 {
                    break;
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
