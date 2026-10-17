#!/bin/sh
# Match the PostgreSQL 18 test service's dump version on CI runners.
exec docker run --rm --network host --entrypoint pg_dump \
  docker.io/library/postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873 "$@"
