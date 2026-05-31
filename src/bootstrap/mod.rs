//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod cors;
mod routes;

use std::{net::SocketAddr, sync::Arc};

use actix_web::{App, HttpServer, http::header, middleware::DefaultHeaders, web};
use anyhow::Context;
use fred::{
    interfaces::ClientLike,
    prelude::{Builder as ValkeyBuilder, Config as ValkeyConfig},
};

use crate::config::ConfigSource;
use crate::database_config::normalize_database_url;
use crate::db::create_pool;
use crate::domain::AppState;
use crate::settings::Settings;
use crate::support::load_or_create_keyset;

pub async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let env_filter = config.string("RUST_LOG", "info");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(env_filter)
                .context("RUST_LOG must be a valid tracing filter")?,
        )
        .init();

    // 配置只在启动阶段读取，运行期通过 AppState 共享不可变配置。
    let database_url = normalize_database_url(&config.string(
        "DATABASE_URL",
        "postgresql://postgres:postgres@127.0.0.1:5432/oauth",
    ));
    let valkey_url = config.string("VALKEY_URL", "redis://127.0.0.1:6379/0");

    // 数据库和 Valkey 客户端在 server factory 外创建，避免每个 worker 重复初始化。
    let diesel_db = create_pool(database_url.clone(), 32)?;
    let valkey = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url)?).build()?;
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
            .wrap(
                DefaultHeaders::new()
                    .add((header::X_FRAME_OPTIONS, "DENY"))
                    .add((
                        "Content-Security-Policy",
                        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
                    ))
                    .add(("Referrer-Policy", "no-referrer"))
                    .add(("X-Content-Type-Options", "nosniff")),
            )
            .wrap(cors::build(&state.settings))
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}
