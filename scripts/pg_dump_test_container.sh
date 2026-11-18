#!/bin/sh
# Match the PostgreSQL 18 test service's dump version on CI runners.
exec docker run --rm --network host --entrypoint pg_dump \
  docker.io/library/postgres:18.7-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015 "$@"
