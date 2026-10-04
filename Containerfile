# syntax=docker/dockerfile:1.7

FROM docker.io/library/rust:1.99.0-slim@sha256:01dd4f9c24801cfc8ba9cf8a5dd6dcca451cd17d1ae73574edc22591de6e6816 AS build-base

ENV RUSTUP_TOOLCHAIN=1.99.0

WORKDIR /app

RUN mkdir -p /usr/local/cargo \
    && printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git make perl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml .env.yaml.example ./
COPY crates ./crates
COPY migrations ./migrations

FROM build-base AS product-builder

# The cargo target cache mount is keyed by source identity: --no-cache does
# not clear BuildKit cache mounts, and a shared id lets cargo ship a binary
# fingerprinted from a previously built tree. Registry/git mounts stay
# shared — they are already content-addressed downloads.
ARG SOURCE_SHA=unknown

RUN --mount=type=cache,id=nazoauth-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=nazoauth-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=nazoauth-target-${SOURCE_SHA},target=/app/target,sharing=locked \
    cargo build --release --locked \
      --package nazoauth --bin nazoauth \
    && install -Dm755 target/release/nazoauth /out/nazoauth \
    && printf "%s" "${SOURCE_SHA}" > /out/source-sha

FROM docker.io/library/debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS runtime-base

# Security fixes not yet in the pinned base digest are installed at exact
# versions (Renovate-managed); never blanket-upgrade the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        gzip=1.13-1+deb13u1 \
        libpcre2-8-0=10.46-1~deb13u3 \
        libsqlite3-0=3.46.1-7+deb13u2 \
        perl-base=5.40.1-6+deb13u1 \
    && groupadd --gid 10001 nazoauth \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nazoauth \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM runtime-base AS runtime

ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.revision="${SOURCE_SHA}"

COPY --from=product-builder /out/nazoauth /usr/local/bin/nazoauth
COPY --from=product-builder /out/source-sha /etc/nazoauth-source-sha

USER 10001:10001

EXPOSE 8000

CMD ["nazoauth", "server"]

FROM runtime-base AS release-export

COPY --from=product-builder /out/nazoauth /usr/local/bin/nazoauth

FROM runtime AS development-runtime

COPY --from=product-builder /app/.env.yaml.example /app/.env.yaml

FROM docker.io/library/postgres:18.6@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722 AS compose-postgres

COPY --chmod=0555 deploy/compose/initialize-postgres.sh /docker-entrypoint-initdb.d/initialize-nazoauth-runtime.sh

FROM development-runtime AS perf-runtime

COPY perf/env.yaml /app/.env.yaml
