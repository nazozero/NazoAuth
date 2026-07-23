FROM docker.io/library/rust:1.97.0-slim@sha256:686a437ead83701e8f871e66e838c3ec55f46b5fc235b025756396ac823bdc51 AS build-base

ENV RUSTUP_TOOLCHAIN=1.97.0

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./
COPY crates ./crates
COPY migrations ./migrations

FROM build-base AS product-builder

RUN cargo build --release --locked --package nazo-oauth-server --bin nazoauth

FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS runtime-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM runtime-base AS runtime

COPY --from=product-builder /app/target/release/nazoauth /usr/local/bin/nazoauth

EXPOSE 8000

CMD ["nazoauth", "server"]

FROM runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
