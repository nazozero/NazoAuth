#!/usr/bin/env bash
set -euo pipefail

mkdir -p runtime/ci/avatars
docker run --detach --name avatar-store --publish 127.0.0.1:9000:9000 \
  --env MINIO_ROOT_USER="$NAZO_TEST_S3_ACCESS_KEY" \
  --env MINIO_ROOT_PASSWORD="$NAZO_TEST_S3_SECRET_KEY" \
  nazoauth-test-minio:ci \
  server /data
ready=false
for _ in $(seq 1 30); do
  if curl --fail --silent "$NAZO_TEST_S3_ENDPOINT/minio/health/live"; then
    ready=true
    break
  fi
  sleep 1
done
test "$ready" = true
docker exec avatar-store mc alias set test http://127.0.0.1:9000 \
  "$NAZO_TEST_S3_ACCESS_KEY" "$NAZO_TEST_S3_SECRET_KEY"
docker exec avatar-store mc mb "test/$NAZO_TEST_S3_BUCKET"
