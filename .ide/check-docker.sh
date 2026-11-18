#!/bin/sh
set -eu

for attempt in $(seq 1 30); do
  if docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker version
docker compose version
