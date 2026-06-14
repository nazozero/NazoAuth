//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod cors;
mod observability;
mod routes;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, dev::Service, http::header, middleware::DefaultHeaders, web};
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};

use crate::config::{ConfigSource, database_url};
use crate::db::create_pool;
use crate::domain::AppState;
use crate::settings::Settings;
use crate::support::load_or_create_keyset;
use tracing::Instrument;

pub async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let _observability = observability::init(&config)?;

    // 配置只在启动阶段读取，运行期通过 AppState 共享不可变配置。
    let database_url = database_url(&config);
    let valkey_url = config.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
    let valkey_command_timeout_ms = config.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
    if valkey_command_timeout_ms == 0 {
        anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
    }
    let valkey_command_timeout = Duration::from_millis(valkey_command_timeout_ms);

    // 数据库和 Valkey 客户端在 server factory 外创建，避免每个 worker 重复初始化。
    let diesel_db = create_pool(database_url.clone(), 32)?;
    let mut valkey_builder = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url)?);
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = valkey_command_timeout;
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = valkey_command_timeout;
        connection.internal_command_timeout = valkey_command_timeout;
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder.build()?;
    valkey.init().await?;

    let settings = Arc::new(Settings::from_config(&config)?);
    tokio::fs::create_dir_all(&settings.avatar_storage_dir)
        .await
        .ok();
    let keyset = Arc::new(load_or_create_keyset(&settings).await?);

    let state = web::Data::new(AppState {
        diesel_db,
        valkey,
        settings,
        keyset,
    });

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    HttpServer::new(move || {
        App::new()
            .wrap_fn(|req, service| {
                let method = req.method().clone();
                let path = req.path().to_owned();
                let started = std::time::Instant::now();
                let span = tracing::info_span!(
                    "http.request",
                    "otel.kind" = "server",
                    "http.request.method" = %method,
                    "url.path" = %path
                );
                let future = service.call(req);
                async move {
                    let result = future.await;
                    if let Ok(response) = &result {
                        let status = response.status().as_u16();
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
                        tracing::info!(
                            monotonic_counter.http_server_requests = 1_u64,
                            histogram.http_server_request_duration_ms = elapsed_ms,
                            "http.request.method" = %method,
                            "http.response.status_code" = status as i64,
                            "url.path" = %path,
                            "HTTP request completed"
                        );
                    }
                    result
                }
                .instrument(span)
            })
            .wrap(security_headers())
            .wrap(cors::build(&state.settings))
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((header::X_FRAME_OPTIONS, "DENY"))
        .add((
            "Content-Security-Policy",
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        ))
        .add(("Referrer-Policy", "no-referrer"))
        .add(("Permissions-Policy", "interest-cohort=()"))
        .add(("X-Content-Type-Options", "nosniff"))
}

#[cfg(test)]
#[path = "tests/bootstrap.rs"]
mod tests;
