#!/usr/bin/env bash
set -euo pipefail

image="nazo-oauth-supply-chain:$GITHUB_SHA"
docker run --rm --entrypoint dpkg-query "$image" -W apt libpcre2-8-0 libsqlite3-0 perl-base zlib1g
mkdir -p target/ci-service-image
docker save "$image" -o target/ci-service-image/nazo-oauth-service.tar
docker run --rm \
  -v "$PWD/target/ci-service-image/nazo-oauth-service.tar:/image.tar:ro" \
  "$TRIVY_IMAGE" image \
    --format table \
    --exit-code 1 \
    --severity CRITICAL,HIGH \
    --ignore-unfixed \
    --input /image.tar
