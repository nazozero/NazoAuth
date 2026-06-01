FROM docker.io/library/rust:1.96-slim AS builder

WORKDIR /app

RUN sed -i \
        -e 's|http://deb.debian.org/debian|http://mirrors.ustc.edu.cn/debian|g' \
        -e 's|http://deb.debian.org/debian-security|http://mirrors.ustc.edu.cn/debian-security|g' \
        /etc/apt/sources.list.d/debian.sources \
    && mkdir -p /usr/local/cargo \
    && printf '[source.crates-io]\nreplace-with = "rsproxy"\n\n[source.rsproxy]\nregistry = "sparse+https://rsproxy.cn/index/"\n' > /usr/local/cargo/config.toml \
    && apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --release

FROM docker.io/library/debian:trixie-slim

RUN sed -i \
        -e 's|http://deb.debian.org/debian|http://mirrors.ustc.edu.cn/debian|g' \
        -e 's|http://deb.debian.org/debian-security|http://mirrors.ustc.edu.cn/debian-security|g' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/nazo-oauth-server /usr/local/bin/nazo-oauth-server
COPY --from=builder /app/target/release/nazo-oauth-migrate /usr/local/bin/nazo-oauth-migrate
COPY --from=builder /app/target/release/nazo-oauth-keyctl /usr/local/bin/nazo-oauth-keyctl

EXPOSE 8000

CMD ["nazo-oauth-server"]
