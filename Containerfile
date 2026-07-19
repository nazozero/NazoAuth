FROM docker.io/library/rust:1.97.0-slim@sha256:686a437ead83701e8f871e66e838c3ec55f46b5fc235b025756396ac823bdc51 AS build-base

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

FROM docker.io/library/debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2 AS runtime-base

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
