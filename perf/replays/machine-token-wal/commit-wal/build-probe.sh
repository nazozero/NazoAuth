#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -shared -fPIC -O2 -Wall -Wextra -o app-probe.so commit_probe.c -ldl
image=$(docker inspect -f '{{.Image}}' oauthbench-pg)
builder=nazo-wal-musl-build
docker run -d --name "$builder" --entrypoint /bin/sh "$image" -c 'sleep infinity' >/dev/null
trap 'docker rm -fv "$builder" >/dev/null' EXIT
docker exec "$builder" apk add --no-cache gcc musl-dev binutils
docker cp commit_probe.c "$builder:/tmp/probe.c"
docker exec "$builder" gcc -shared -fPIC -O2 -Wall -Wextra -DPG_PROBE -o /tmp/probe.so /tmp/probe.c -ldl
docker cp "$builder:/tmp/probe.so" pg-probe.so
