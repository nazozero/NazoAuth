FROM docker.io/grafana/k6:2.4.0@sha256:d41bb79cd8de5a7ad619b53570e3712633e8bff0937010a5c6c57a4747e7a276 AS k6
FROM docker.io/docker:29.10.0-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS docker-cli

FROM docker.io/library/node:26.13.1-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS node

FROM docker.io/library/python:3.15.2-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS python

FROM docker.io/library/rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8

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

RUN ldconfig \
    && python3 -m pip install --no-cache-dir \
        "argon2-cffi==25.1.0" \
        "cryptography==50.0.2" \
        "psycopg[binary]==3.3.9" \
        "redis==8.1.0"

RUN mkdir -p /usr/local/cargo /usr/local/libexec/docker/cli-plugins

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

RUN printf '[registries.crates-io]\nprotocol = "sparse"\n' > /usr/local/cargo/config.toml \
    && docker --version \
    && docker compose version \
    && k6 version \
    && node --version \
    && sshd -t \
    && rustc --version \
    && cargo --version \
    && python3 --version \
    && python3 -c "import ssl, sqlite3, ctypes, bz2, lzma, cryptography, psycopg, redis"

WORKDIR /workspace
