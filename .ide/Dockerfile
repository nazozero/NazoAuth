FROM docker.io/grafana/k6:2.3@sha256:9c2dee7f8ed74d317e4027c06a10f169b625638189de8d4555d0b3486a5aeb34 AS k6
FROM docker.io/docker:29.8.2-cli@sha256:b1805116a6a86cc591b5d5f60a910a0715cdcc9d18d866ad68b1457ead25c35c AS docker-cli

FROM docker.io/library/python:3.14.8-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151 AS python

FROM docker.io/library/rust:1.99.0-trixie@sha256:cb1b90b0ce00f9eb950c4de62cc1bb89c7bf8a3577de6600d10e31fb15f876de

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=always
ENV RUST_BACKTRACE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        gnupg \
        jq \
        less \
        libpq-dev \
        lld \
        llvm \
        make \
        openssh-client \
        openssh-server \
        pkg-config \
        postgresql-client \
        protobuf-compiler \
        python3 \
        python3-pip \
        python3-venv \
        redis-tools \
        shellcheck \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd \
    && sshd -t

# Project Python lives in /usr/local; Debian tools retain /usr/bin/python3.
COPY --from=python /usr/local /usr/local

RUN python3 -m pip install --no-cache-dir \
        "argon2-cffi==25.1.0" \
        "cryptography==50.0.2" \
        "psycopg[binary]==3.3.6" \
        "redis==8.1.0"

RUN mkdir -p /usr/local/cargo /usr/local/libexec/docker/cli-plugins

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

RUN printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && docker --version \
    && docker compose version \
    && k6 version \
    && sshd -t \
    && rustc --version \
    && cargo --version \
    && python3 --version \
    && python3 -c "import ssl, sqlite3, ctypes, bz2, lzma, cryptography, psycopg, redis"

WORKDIR /workspace
