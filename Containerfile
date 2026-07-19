FROM docker.io/library/rust:1.97.0-slim@sha256:14c4fe50ea427dc42381a1a09a9a839c1d2346a2e508cd491bf02c659dbc0ed7 AS build-base

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations

FROM build-base AS product-builder

RUN cargo build --release --locked --package nazo-oauth-server --bins

FROM docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS runtime-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM runtime-base AS runtime

COPY --from=product-builder /app/target/release/nazo-oauth-server /usr/local/bin/nazo-oauth-server
COPY --from=product-builder /app/target/release/nazo-oauth-migrate /usr/local/bin/nazo-oauth-migrate
COPY --from=product-builder /app/target/release/nazo-oauth-keyctl /usr/local/bin/nazo-oauth-keyctl

EXPOSE 8000

CMD ["nazo-oauth-server"]

FROM runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
